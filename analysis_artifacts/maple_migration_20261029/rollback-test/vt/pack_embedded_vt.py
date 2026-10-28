import ctypes
import hashlib
import struct
import os

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
    if len(pe_bytes) < 0x100:
        raise ValueError("PE image is too small")

    e_magic, = struct.unpack_from("<H", pe_bytes, 0)
    if e_magic != 0x5A4D:
        raise ValueError("Invalid DOS signature")
    e_lfanew, = struct.unpack_from("<I", pe_bytes, 0x3C)
    pe_sig, = struct.unpack_from("<I", pe_bytes, e_lfanew)
    if pe_sig != 0x00004550:
        raise ValueError("Invalid PE signature")

    file_hdr_off = e_lfanew + 4
    if file_hdr_off + 20 > len(pe_bytes):
        raise ValueError("Truncated PE file header")
    num_sections, = struct.unpack_from("<H", pe_bytes, file_hdr_off + 2)
    size_opt_hdr, = struct.unpack_from("<H", pe_bytes, file_hdr_off + 16)
    opt_hdr_off = file_hdr_off + 20
    if opt_hdr_off + size_opt_hdr > len(pe_bytes):
        raise ValueError("Truncated PE optional header")

    opt_magic, = struct.unpack_from("<H", pe_bytes, opt_hdr_off)
    if opt_magic != 0x20B:
        raise ValueError(f"Unsupported PE optional header: 0x{opt_magic:X}")

    entry_rva, = struct.unpack_from("<I", pe_bytes, opt_hdr_off + 16)
    image_base, = struct.unpack_from("<Q", pe_bytes, opt_hdr_off + 24)
    size_of_image, = struct.unpack_from("<I", pe_bytes, opt_hdr_off + 56)
    size_of_headers, = struct.unpack_from("<I", pe_bytes, opt_hdr_off + 60)
    if not size_of_image or not size_of_headers or size_of_headers > len(pe_bytes):
        raise ValueError("Invalid PE image/header size")

    reloc_dir_off = opt_hdr_off + 112 + 5 * 8
    reloc_rva, reloc_size = struct.unpack_from("<II", pe_bytes, reloc_dir_off)
    import_dir_off = opt_hdr_off + 112 + 1 * 8
    import_rva, import_size = struct.unpack_from("<II", pe_bytes, import_dir_off)

    sec_table_off = opt_hdr_off + size_opt_hdr
    if sec_table_off + num_sections * 40 > len(pe_bytes):
        raise ValueError("Truncated PE section table")

    # RawPack v2 显式携带 PE 头。Bootstrap 需要其中的 DataDirectory 来解析 IAT；
    # v1 只复制节，导致 IAT 槽保留 IMAGE_IMPORT_BY_NAME RVA 并被当作函数地址执行。
    sections = [(0, size_of_headers, size_of_headers, 0x40000040, pe_bytes[:size_of_headers])]
    for i in range(num_sections):
        sh_off = sec_table_off + i * 40
        vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, sh_off + 8)
        chars, = struct.unpack_from("<I", pe_bytes, sh_off + 36)
        if rva > size_of_image or max(vsize, raw_size) > size_of_image - rva:
            raise ValueError(f"Section {i} exceeds SizeOfImage")
        if raw_size and (not raw_ptr or raw_ptr > len(pe_bytes) or raw_size > len(pe_bytes) - raw_ptr):
            raise ValueError(f"Section {i} raw data is truncated")
        raw_data = pe_bytes[raw_ptr:raw_ptr + raw_size] if (raw_size and raw_ptr) else b""
        sections.append((rva, vsize, len(raw_data), chars, raw_data))

    def rva_to_file_offset(target_rva: int) -> int:
        for i in range(num_sections):
            sh_off = sec_table_off + i * 40
            vsize, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", pe_bytes, sh_off + 8)
            span = max(vsize, raw_size)
            if rva <= target_rva < rva + span:
                return raw_ptr + (target_rva - rva)
        raise ValueError(f"Cannot map RVA 0x{target_rva:X}")

    def read_ascii_z(target_rva: int, max_length: int) -> str:
        file_off = rva_to_file_offset(target_rva)
        end = min(len(pe_bytes), file_off + max_length)
        terminator = pe_bytes.find(b"\0", file_off, end)
        if terminator < 0:
            raise ValueError(f"Unterminated ASCII string at RVA 0x{target_rva:X}")
        try:
            return pe_bytes[file_off:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Non-ASCII import string at RVA 0x{target_rva:X}") from exc

    # 只允许当前 ResidentPayload 所需的受信任内核模块。未知模块、序号导入和
    # 越界 thunk 在打包时直接失败，避免把不可解析映像带入内核。
    allowed_import_modules = {
        "ntoskrnl.exe",
        "ntkrnlmp.exe",
        "ntkrnlpa.exe",
        "ntkrpamp.exe",
        "netio.sys",
    }
    import_count = 0
    if import_rva or import_size:
        if not import_rva or import_size < 20:
            raise ValueError("Malformed import directory")
        import_file_off = rva_to_file_offset(import_rva)
        descriptor_limit = import_size // 20
        descriptor_terminated = False
        for descriptor_index in range(descriptor_limit):
            desc_off = import_file_off + descriptor_index * 20
            if desc_off + 20 > len(pe_bytes):
                raise ValueError("Truncated import descriptor")
            original_first_thunk, timestamp, forwarder_chain, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", pe_bytes, desc_off
            )
            if not any((original_first_thunk, timestamp, forwarder_chain, name_rva, first_thunk)):
                descriptor_terminated = True
                break
            module_name = read_ascii_z(name_rva, 128).lower()
            if module_name not in allowed_import_modules:
                raise ValueError(f"RawPack import module is not allowed: {module_name}")
            thunk_rva = original_first_thunk or first_thunk
            if not thunk_rva or not first_thunk:
                raise ValueError(f"Malformed thunk table for {module_name}")
            thunk_file_off = rva_to_file_offset(thunk_rva)
            thunk_terminated = False
            max_thunks = min(0x10000, (len(pe_bytes) - thunk_file_off) // 8)
            for thunk_index in range(max_thunks):
                thunk, = struct.unpack_from("<Q", pe_bytes, thunk_file_off + thunk_index * 8)
                if thunk == 0:
                    thunk_terminated = True
                    break
                if thunk & (1 << 63):
                    raise ValueError(f"Ordinal import is unsupported: {module_name}!{thunk & 0xFFFF}")
                if thunk > 0xFFFFFFFF:
                    raise ValueError(f"Import name RVA is out of range: 0x{thunk:X}")
                read_ascii_z(int(thunk) + 2, 256)
                import_count += 1
            if not thunk_terminated:
                raise ValueError(f"Unterminated thunk table for {module_name}")
        if not descriptor_terminated:
            raise ValueError("Import descriptor table is not terminated")

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
        2,                   # version：携带 PE 头并由 Bootstrap 解析 IAT
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
    rawpack = raw_header + bytes(sec_entries) + reloc_blob + bytes(sec_blob)
    if import_count and sections[0][0] != 0:
        raise AssertionError("RawPack v2 must preserve PE headers for imports")
    return rawpack

def format_c_array(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 32):
        chunk = data[i:i+32]
        line = "    " + ",".join(f"0x{b:02X}" for b in chunk)
        if i + 32 < len(data):
            line += ","
        lines.append(line)
    return "\r\n".join(lines)

def write_if_changed(out_h: str, content: str, source_mtime: float = None) -> bool:
    normalized = content.replace("\r\n", "\n").replace("\n", "\r\n")
    raw_bytes = b"\xef\xbb\xbf" + normalized.encode("utf-8")
    if os.path.exists(out_h):
        try:
            if open(out_h, "rb").read() == raw_bytes:
                if source_mtime is not None and os.path.getmtime(out_h) < source_mtime:
                    os.utime(out_h, None)
                return False
        except OSError:
            pass
    with open(out_h, "wb") as f:
        f.write(raw_bytes)
    if source_mtime is not None:
        try:
            os.utime(out_h, (source_mtime, source_mtime))
        except OSError:
            pass
    return True

def generate_hypervisor_payload_h(pe_path: str, out_h: str):
    raw = open(pe_path, "rb").read()
    raw_sha256 = hashlib.sha256(raw).hexdigest().upper()
    comp = xpress_compress(raw)
    enc = crypt_buffer(comp, 0xA7C3D19B5E6F4021)
    content = f"""#pragma once

#define HYPERVISOR_PAYLOAD_COMPRESSED 1
#define HYPERVISOR_PAYLOAD_COMPRESSION_FORMAT 0x0003
#define HYPERVISOR_PAYLOAD_UNPACKED_SIZE {len(raw)}ul
#define HYPERVISOR_PAYLOAD_PACKED_SIZE {len(enc)}ul
#define HYPERVISOR_PAYLOAD_SHA256 "{raw_sha256}"

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
    source_mtime = os.path.getmtime(pe_path)
    changed = write_if_changed(out_h, content, source_mtime)
    state = "Updated" if changed else "Up-to-date"
    print(f"[+] [{state}] {out_h}: unpacked={len(raw)} B -> packed={len(enc)} B sha256={raw_sha256}")

generate_test_driver_h = generate_hypervisor_payload_h

def generate_resident_payload_h(pe_path: str, out_h: str):
    pe = open(pe_path, "rb").read()
    pe_sha256 = hashlib.sha256(pe).hexdigest().upper()
    rawpack = pe_to_rawpack(pe)
    rawpack_sha256 = hashlib.sha256(rawpack).hexdigest().upper()
    comp = xpress_compress(rawpack)
    enc = crypt_buffer(comp, 0x6D2B79F5A341C8E7)
    content = f"""#pragma once

// payloadRuntime.bin is compiled as a PE source, then converted by pack_embedded_vt.py
// into a RawPack v2 header+section+reloc packet; Bootstrap validates and resolves IAT.
#define PAYLOAD_IMAGE_FORMAT_PE 1
#define PAYLOAD_IMAGE_FORMAT_RAWPACK 2
#define PAYLOAD_IMAGE_FORMAT 2
#define PAYLOAD_IMAGE_COMPRESSED 1
#define PAYLOAD_IMAGE_COMPRESSION_FORMAT 0x0003
#define PAYLOAD_IMAGE_SOURCE_PE_SIZE {len(pe)}ul
#define PAYLOAD_IMAGE_SOURCE_PE_SHA256 "{pe_sha256}"
#define PAYLOAD_IMAGE_UNPACKED_SIZE {len(rawpack)}ul
#define PAYLOAD_IMAGE_PACKED_SIZE {len(enc)}ul
#define PAYLOAD_IMAGE_RAWPACK_SHA256 "{rawpack_sha256}"

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
    source_mtime = os.path.getmtime(pe_path)
    changed = write_if_changed(out_h, content, source_mtime)
    state = "Updated" if changed else "Up-to-date"
    print(f"[+] [{state}] {out_h}: source_pe={len(pe)} B -> rawpack={len(rawpack)} B -> packed={len(enc)} B sha256={pe_sha256}")

def generate_machenike_payload_h(pe_path: str, out_h: str):
    raw = open(pe_path, "rb").read()
    raw_sha256 = hashlib.sha256(raw).hexdigest().upper()
    comp = xpress_compress(raw)
    enc = crypt_buffer(comp, 0x9C4E81A27B35D60F)
    content = f"""#pragma once

#define MACHENIKE_SYS_COMPRESSED 1
#define MACHENIKE_SYS_COMPRESSION_FORMAT 0x0003
#define MACHENIKE_SYS_UNPACKED_SIZE {len(raw)}ul
#define MACHENIKE_SYS_PACKED_SIZE {len(enc)}ul
#define MACHENIKE_SYS_SHA256 "{raw_sha256}"

static unsigned char machenike_sys[] = {{
{format_c_array(enc)}
}};

static __forceinline unsigned char machenike_sys_stream_byte(unsigned long long i)
{{
    unsigned long long x = 0x9C4E81A27B35D60Full + ((i + 0x9E3779B97F4A7C15ull) * 0xBF58476D1CE4E5B9ull);
    x ^= (x >> 30);
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= (x >> 27);
    x *= 0x94D049BB133111EBull;
    x ^= (x >> 31);
    return (unsigned char)(x >> 56);
}}

static __forceinline void machenike_sys_crypt(void)
{{
    for (unsigned long long i = 0; i < sizeof(machenike_sys); i++)
        machenike_sys[i] ^= machenike_sys_stream_byte(i);
}}
"""
    source_mtime = os.path.getmtime(pe_path)
    changed = write_if_changed(out_h, content, source_mtime)
    state = "Updated" if changed else "Up-to-date"
    print(f"[+] [{state}] {out_h}: unpacked={len(raw)} B -> packed={len(enc)} B sha256={raw_sha256}")

def validate_input_image(path: str, label: str):
    if not path or not os.path.exists(path):
        print(f"[FATAL ERROR] Required embedded payload image '{label}' NOT found: {path}")
        print(f"[FATAL ERROR] All fallbacks rejected. Please ensure {label} is built successfully.")
        import sys
        sys.exit(1)
    size = os.path.getsize(path)
    if size < 0x200:
        print(f"[FATAL ERROR] Payload image '{label}' ({path}) is too small ({size} bytes). Corrupt build output.")
        import sys
        sys.exit(1)
    with open(path, "rb") as f:
        magic = f.read(2)
        if magic != b"MZ":
            print(f"[FATAL ERROR] Payload image '{label}' ({path}) is not a valid PE binary (missing MZ header).")
            import sys
            sys.exit(1)

if __name__ == "__main__":
    import argparse
    import sys

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_test = os.path.join(base_dir, "bin", "vt", "VtHypervisor.sys")
    default_payload = os.path.join(base_dir, "bin", "vt", "VtResidentPayload.sys")
    default_machenike = os.path.join(base_dir, "bin", "mswsk.sys")

    parser = argparse.ArgumentParser()
    parser.add_argument("--test", default=default_test)
    parser.add_argument("--payload", default=default_payload)
    parser.add_argument("--machenike", default=default_machenike)
    args = parser.parse_args()

    # 严禁任何回退降级，必须严格存在且为有效 PE 映像
    validate_input_image(args.test, "VtHypervisor")
    validate_input_image(args.payload, "VtResidentPayload")
    validate_input_image(args.machenike, "Machenike/mswsk")

    out_hypervisor_h = os.path.join(base_dir, "vt", "VtBootstrapDriver", "common", "hypervisor_payload.h")
    out_payload_h = os.path.join(base_dir, "vt", "VtBootstrapDriver", "common", "resident_payload.h")
    out_machenike_h = os.path.join(base_dir, "vt", "VtBootstrapDriver", "common", "machenike_payload.h")

    generate_hypervisor_payload_h(args.test, out_hypervisor_h)
    generate_resident_payload_h(args.payload, out_payload_h)
    generate_machenike_payload_h(args.machenike, out_machenike_h)

    # 彻底清理历史残留 testDriver.h，防止老旧引用被误编译
    old_test_h = os.path.join(base_dir, "vt", "VtBootstrapDriver", "common", "testDriver.h")
    if os.path.exists(old_test_h):
        try:
            os.remove(old_test_h)
            print(f"[*] Removed legacy header: {old_test_h}")
        except OSError:
            pass
