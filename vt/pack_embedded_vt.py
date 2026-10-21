import ctypes
import struct
import os
import argparse

ntdll = ctypes.windll.ntdll

COMPRESSION_FORMAT_XPRESS = 0x0003
COMPRESSION_ENGINE_STANDARD = 0x0000

def xpress_compress(data: bytes) -> bytes:
    fmt = COMPRESSION_FORMAT_XPRESS | COMPRESSION_ENGINE_STANDARD
    ws_buf_size = ctypes.c_ulong(0)
    frag_buf_size = ctypes.c_ulong(0)
    status = ntdll.RtlGetCompressionWorkSpaceSize(
        ctypes.c_ushort(fmt),
        ctypes.byref(ws_buf_size),
        ctypes.byref(frag_buf_size),
    )
    if status != 0:
        raise RuntimeError(f"RtlGetCompressionWorkSpaceSize failed: 0x{status:08X}")

    workspace = ctypes.create_string_buffer(ws_buf_size.value)
    out_cap = len(data) + 65536
    out_buf = ctypes.create_string_buffer(out_cap)
    final_size = ctypes.c_ulong(0)

    status = ntdll.RtlCompressBuffer(
        ctypes.c_ushort(fmt),
        data,
        ctypes.c_ulong(len(data)),
        out_buf,
        ctypes.c_ulong(out_cap),
        ctypes.c_ulong(4096),
        ctypes.byref(final_size),
        workspace,
    )
    if status != 0:
        raise RuntimeError(f"RtlCompressBuffer failed: 0x{status:08X}")

    return out_buf.raw[:final_size.value]

def stream_byte(seed: int, i: int) -> int:
    mask = 0xFFFFFFFFFFFFFFFF
    x = (seed + (((i + 0x9E3779B97F4A7C15) & mask) * 0xBF58476D1CE4E5B9)) & mask
    x ^= (x >> 30)
    x = (x * 0xBF58476D1CE4E5B9) & mask
    x ^= (x >> 27)
    x = (x * 0x94D049BB133111EB) & mask
    x ^= (x >> 31)
    return (x >> 56) & 0xFF

def crypt_buffer(data: bytes, seed: int) -> bytes:
    return bytes(b ^ stream_byte(seed, idx) for idx, b in enumerate(data))

def pe_to_rawpack(pe_bytes: bytes) -> bytes:
    e_magic, = struct.unpack_from("<H", pe_bytes, 0)
    if e_magic != 0x5A4D:
        raise ValueError("Invalid DOS signature")
    e_lfanew, = struct.unpack_from("<I", pe_bytes, 0x3C)
    pe_sig, = struct.unpack_from("<I", pe_bytes, e_lfanew)
    if pe_sig != 0x00004550:
        raise ValueError("Invalid PE signature")

    file_hdr_off = e_lfanew + 4
    num_sections, = struct.unpack_from("<H", pe_bytes, file_hdr_off + 2)
    size_opt_hdr, = struct.unpack_from("<H", pe_bytes, file_hdr_off + 16)
    opt_hdr_off = file_hdr_off + 20

    entry_rva, = struct.unpack_from("<I", pe_bytes, opt_hdr_off + 16)
    image_base, = struct.unpack_from("<Q", pe_bytes, opt_hdr_off + 24)
    size_of_image, = struct.unpack_from("<I", pe_bytes, opt_hdr_off + 56)

    # DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC = 5] at opt_hdr_off + 112 + 5*8
    reloc_dir_off = opt_hdr_off + 112 + 5 * 8
    reloc_rva, reloc_size = struct.unpack_from("<II", pe_bytes, reloc_dir_off)

    sec_table_off = opt_hdr_off + size_opt_hdr
    sections = []
    for i in range(num_sections):
        sh_off = sec_table_off + i * 40
        name = pe_bytes[sh_off:sh_off+8]
        vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, sh_off + 8)
        chars, = struct.unpack_from("<I", pe_bytes, sh_off + 36)
        raw_data = pe_bytes[raw_ptr:raw_ptr + raw_size] if (raw_size and raw_ptr) else b""
        sections.append((rva, vsize, len(raw_data), chars, raw_data))

    def rva_to_file_offset(target_rva: int) -> int:
        for rva, vsize, raw_size, chars, _ in sections:
            span = max(vsize, raw_size)
            if rva <= target_rva < rva + span:
                # find raw_ptr again
                break
        for i in range(num_sections):
            sh_off = sec_table_off + i * 40
            vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, sh_off + 8)
            span = max(vsize, raw_size)
            if rva <= target_rva < rva + span:
                return raw_ptr + (target_rva - rva)
        raise ValueError(f"Cannot map RVA 0x{target_rva:X}")

    relocs = []
    if reloc_rva and reloc_size:
        reloc_file_off = rva_to_file_offset(reloc_rva)
        cur = 0
        while cur + 8 <= reloc_size:
            page_rva, block_size = struct.unpack_from("<II", pe_bytes, reloc_file_off + cur)
            if page_rva == 0 or block_size < 8:
                break
            entry_count = (block_size - 8) // 2
            for j in range(entry_count):
                val, = struct.unpack_from("<H", pe_bytes, reloc_file_off + cur + 8 + j * 2)
                rtype = (val >> 12) & 0xF
                roff = val & 0xFFF
                if rtype == 10:  # IMAGE_REL_BASED_DIR64
                    relocs.append(page_rva + roff)
                elif rtype != 0:
                    raise ValueError(f"Unsupported relocation type: {rtype}")
            cur += block_size

    header_size = 56
    section_table_offset = header_size
    section_table_bytes = len(sections) * 20
    reloc_table_offset = section_table_offset + section_table_bytes
    reloc_table_bytes = len(relocs) * 4
    data_offset = reloc_table_offset + reloc_table_bytes

    sec_entries = bytearray()
    sec_blob = bytearray()
    for rva, vsize, raw_size, chars, raw_data in sections:
        cur_data_off = (data_offset + len(sec_blob)) if raw_size else 0
        sec_entries += struct.pack("<IIIII", rva, vsize, raw_size, cur_data_off, chars)
        sec_blob += raw_data

    reloc_blob = b"".join(struct.pack("<I", r) for r in relocs)
    raw_header = struct.pack(
        "<QIIQIIIIIIII",
        0x504C445241573031,  # PLDRAW01
        1,                   # version
        header_size,
        image_base,
        size_of_image,
        entry_rva,
        len(sections),
        len(relocs),
        section_table_offset,
        reloc_table_offset,
        data_offset,
        len(sec_blob),
    )
    return raw_header + bytes(sec_entries) + reloc_blob + bytes(sec_blob)

def format_c_array(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 32):
        chunk = data[i:i+32]
        line = "    " + ",".join(f"0x{b:02X}" for b in chunk)
        if i + 32 < len(data):
            line += ","
        lines.append(line)
    return "\n".join(lines)

def generate_test_driver_h(pe_path: str, out_h: str):
    raw = open(pe_path, "rb").read()
    comp = xpress_compress(raw)
    enc = crypt_buffer(comp, 0xA7C3D19B5E6F4021)
    content = f"""#pragma once

#define TEST_SYS_COMPRESSED 1
#define TEST_SYS_COMPRESSION_FORMAT 0x0003
#define TEST_SYS_UNPACKED_SIZE {len(raw)}ul
#define TEST_SYS_PACKED_SIZE {len(enc)}ul

static unsigned char test_sys[] = {{
{format_c_array(enc)}
}};

static __forceinline unsigned char test_sys_stream_byte(unsigned long long i)
{{
    unsigned long long x = 0xA7C3D19B5E6F4021ull + ((i + 0x9E3779B97F4A7C15ull) * 0xBF58476D1CE4E5B9ull);
    x ^= (x >> 30);
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= (x >> 27);
    x *= 0x94D049BB133111EBull;
    x ^= (x >> 31);
    return (unsigned char)(x >> 56);
}}

static __forceinline void test_sys_crypt(void)
{{
    for (unsigned long long i = 0; i < sizeof(test_sys); i++)
        test_sys[i] ^= test_sys_stream_byte(i);
}}
"""
    with open(out_h, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Updated {out_h}: unpacked={len(raw)} B -> packed={len(enc)} B")

def generate_resident_payload_h(pe_path: str, out_h: str):
    pe = open(pe_path, "rb").read()
    rawpack = pe_to_rawpack(pe)
    comp = xpress_compress(rawpack)
    enc = crypt_buffer(comp, 0x6D2B79F5A341C8E7)
    content = f"""#pragma once

// payloadRuntime.bin is compiled as a PE source, then converted by pack_embedded_vt.py
// into this custom raw section+reloc packet before being embedded.
#define PAYLOAD_IMAGE_FORMAT_PE 1
#define PAYLOAD_IMAGE_FORMAT_RAWPACK 2
#define PAYLOAD_IMAGE_FORMAT 2
#define PAYLOAD_IMAGE_COMPRESSED 1
#define PAYLOAD_IMAGE_COMPRESSION_FORMAT 0x0003
#define PAYLOAD_IMAGE_SOURCE_PE_SIZE {len(pe)}ul
#define PAYLOAD_IMAGE_UNPACKED_SIZE {len(rawpack)}ul
#define PAYLOAD_IMAGE_PACKED_SIZE {len(enc)}ul

static unsigned char payload_image_blob[] = {{
{format_c_array(enc)}
}};

static __forceinline unsigned char payload_image_stream_byte(unsigned long long i)
{{
    unsigned long long x = 0x6D2B79F5A341C8E7ull + ((i + 0x9E3779B97F4A7C15ull) * 0xBF58476D1CE4E5B9ull);
    x ^= (x >> 30);
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= (x >> 27);
    x *= 0x94D049BB133111EBull;
    x ^= (x >> 31);
    return (unsigned char)(x >> 56);
}}

static __forceinline void payload_image_crypt(void)
{{
    for (unsigned long long i = 0; i < sizeof(payload_image_blob); i++)
        payload_image_blob[i] ^= payload_image_stream_byte(i);
}}
"""
    with open(out_h, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Updated {out_h}: source_pe={len(pe)} B -> rawpack={len(rawpack)} B -> packed={len(enc)} B")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser = argparse.ArgumentParser(description="Pack TestDriver and resident payload into mapDriver headers")
    parser.add_argument("--test", default=os.path.join(base_dir, "bin", "vt", "TestDriver.sys"))
    parser.add_argument("--payload", default=os.path.join(base_dir, "bin", "vt", "payloadRuntime.sys"))
    parser.add_argument("--test-header", default=os.path.join(
        base_dir, "vt", "vt-call-mapdriver-main", "common", "testDriver.h"))
    parser.add_argument("--payload-header", default=os.path.join(
        base_dir, "vt", "vt-call-mapdriver-main", "common", "resident_payload.h"))
    args = parser.parse_args()
    generate_test_driver_h(os.path.abspath(args.test), os.path.abspath(args.test_header))
    generate_resident_payload_h(os.path.abspath(args.payload), os.path.abspath(args.payload_header))
