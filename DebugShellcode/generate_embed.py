#!/usr/bin/env python3
"""将 DebugShellcode shellcode.exe 解析并生成 Machenike 内嵌镜像头文件。"""
from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


class PeImage:
    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < 0x100 or data[:2] != b"MZ":
            raise ValueError("输入不是有效 PE：缺少 MZ")
        self.pe_offset = self.u32(0x3C)
        if self.pe_offset < 0x40 or self.pe_offset + 24 > len(data):
            raise ValueError("PE 头偏移越界")
        if self.data[self.pe_offset:self.pe_offset + 4] != b"PE\0\0":
            raise ValueError("输入不是有效 PE：缺少 PE 签名")
        file_header = self.pe_offset + 4
        self.section_count = self.u16(file_header + 2)
        optional_size = self.u16(file_header + 16)
        self.optional = file_header + 20
        if self.optional + optional_size > len(data) or optional_size < 0x70:
            raise ValueError("PE OptionalHeader 越界")
        if self.u16(self.optional) != 0x20B:
            raise ValueError("Shellcode 必须是 x64 PE")
        self.optional_size = optional_size
        self.entry_rva = self.u32(self.optional + 16)
        self.image_base = self.u64(self.optional + 24)
        self.image_size = self.u32(self.optional + 56)
        self.header_size = self.u32(self.optional + 60)
        self.section_table = self.optional + optional_size
        if not self.image_size or not self.header_size or self.header_size > len(data):
            raise ValueError("PE SizeOfImage/SizeOfHeaders 无效")
        if self.section_table + self.section_count * 40 > len(data):
            raise ValueError("PE 节表越界")
        self.sections = []
        for index in range(self.section_count):
            off = self.section_table + index * 40
            name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, off + 8)
            if rva > self.image_size or max(virtual_size, raw_size) > self.image_size - rva:
                raise ValueError(f"节 {name} 超出 SizeOfImage")
            if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
                raise ValueError(f"节 {name} 原始数据越界")
            self.sections.append((name, rva, virtual_size, raw_size, raw_offset))

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.data, offset)[0]

    def file_offset(self, rva: int) -> int:
        for _, section_rva, virtual_size, raw_size, raw_offset in self.sections:
            span = max(virtual_size, raw_size)
            if section_rva <= rva < section_rva + span:
                delta = rva - section_rva
                if delta >= raw_size:
                    raise ValueError(f"RVA 0x{rva:X} 位于未初始化尾部")
                return raw_offset + delta
        if 0 <= rva < self.header_size:
            return rva
        raise ValueError(f"RVA 0x{rva:X} 无法映射到文件")

    def export_rva(self, name: str) -> int:
        directory = self.optional + 112 + 8 * 0
        export_rva, export_size = struct.unpack_from("<II", self.data, directory)
        if not export_rva or not export_size:
            raise ValueError("PE 没有导出目录")
        export_offset = self.file_offset(export_rva)
        fields = struct.unpack_from("<IIHHIIIIIII", self.data, export_offset)
        name_count, address_count = fields[6], fields[7]
        address_of_functions, address_of_names, address_of_ordinals = fields[8], fields[9], fields[10]
        for index in range(name_count):
            name_rva = self.u32(self.file_offset(address_of_names) + index * 4)
            name_offset = self.file_offset(name_rva)
            end = self.data.find(b"\0", name_offset)
            if end < 0:
                raise ValueError("导出名称未终止")
            if self.data[name_offset:end].decode("ascii", "replace") != name:
                continue
            ordinal = self.u16(self.file_offset(address_of_ordinals) + index * 2)
            if ordinal >= address_count:
                raise ValueError(f"导出 {name} ordinal 越界")
            return self.u32(self.file_offset(address_of_functions) + ordinal * 4)
        raise ValueError(f"找不到导出 {name}")

    def resolve_thunk(self, rva: int) -> int:
        offset = self.file_offset(rva)
        if self.data[offset] != 0xE9:
            raise ValueError(f"导出 thunk 0x{rva:X} 不是 E9 跳转")
        displacement = struct.unpack_from("<i", self.data, offset + 1)[0]
        return rva + 5 + displacement


def c_array(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        suffix = "," if offset + 16 < len(data) else ""
        lines.append("    " + ", ".join(f"0x{byte:02X}" for byte in chunk) + suffix)
    return "\n".join(lines)


def generate(source: Path, output: Path) -> None:
    image = source.read_bytes()
    pe = PeImage(image)
    x1 = pe.resolve_thunk(0x100A)
    size_function = pe.resolve_thunk(pe.export_rva("X1ImageSize"))
    size_offset = pe.file_offset(size_function)
    if image[size_offset:size_offset + 3] != b"\x48\x8D\x05":
        raise ValueError("X1ImageSize 没有预期 LEA 元数据")
    size_disp = struct.unpack_from("<i", image, size_offset + 3)[0]
    end_rva = size_function + 7 + size_disp
    runtime_dispatch = pe.resolve_thunk(pe.export_rva("RuntimeDispatch"))
    text_sections = [section for section in pe.sections if section[0] == ".text"]
    if len(text_sections) != 1:
        raise ValueError("Shellcode 必须且只能包含一个 .text 节")
    _, text_rva, text_virtual_size, text_raw_size, text_raw_offset = text_sections[0]
    if text_rva % 0x1000 != 0:
        raise ValueError(f".text RVA 未按页对齐: 0x{text_rva:X}")
    text_span = max(text_virtual_size, text_raw_size)
    if not text_span or not text_raw_size:
        raise ValueError(".text 大小关系无效")
    text_end = text_rva + text_span
    if text_end < text_rva:
        raise ValueError(".text RVA 溢出")
    for label, rva in (("X1", x1), ("RuntimeDispatch", runtime_dispatch)):
        if not text_rva <= rva < text_end:
            raise ValueError(f"{label} RVA 0x{rva:X} 不在 .text")
    if end_rva <= x1 or end_rva > text_end:
        raise ValueError("X1 镜像大小超出 .text")
    digest = hashlib.sha256(image).hexdigest().upper()
    content = f"""#pragma once

// Generated from DebugShellcode shellcode.exe; do not edit by hand.
static const char g_DebugShellcodeImageSha256[] = \"{digest}\";
static const unsigned long g_DebugShellcodeImageSize = {len(image)}u;
static const unsigned long g_DebugShellcodeTextRva = 0x{text_rva:X}u;
static const unsigned long g_DebugShellcodeTextVirtualSize = 0x{text_virtual_size:X}u;
static const unsigned long g_DebugShellcodeTextRawOffset = 0x{text_raw_offset:X}u;
static const unsigned long g_DebugShellcodeTextRawSize = 0x{text_raw_size:X}u;
static const unsigned long g_DebugShellcodeTextSpan = 0x{text_span:X}u;
static const unsigned long g_DebugShellcodeImageEntryRva = 0x{x1:X}u;
static const unsigned long g_DebugShellcodeImageEntryOffset = 0x{x1 - text_rva:X}u;
static const unsigned long g_DebugShellcodeImageEntrySize = 0x{end_rva - x1:X}u;
static const unsigned long g_DebugShellcodeRuntimeDispatchRva = 0x{runtime_dispatch:X}u;
static const unsigned long g_DebugShellcodeRuntimeDispatchOffset = 0x{runtime_dispatch - text_rva:X}u;
static const unsigned long g_DebugShellcodeImageSpan = 0x{pe.image_size:X}u;
static const unsigned char g_DebugShellcodeImage[] = {{
{c_array(image)}
}};
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = b"\xEF\xBB\xBF" + content.replace("\n", "\r\n").encode("utf-8")
    temporary = output.with_suffix(output.suffix + ".tmp")
    if output.exists() and output.read_bytes() == encoded:
        print(f"[+] [Up-to-date] {output}: source_sha256={digest}")
        return
    temporary.write_bytes(encoded)
    temporary.replace(output)
    print(f"[+] [Updated] {output}: source={source} size={len(image)} entry=0x{x1:X} dispatch=0x{runtime_dispatch:X} source_sha256={digest}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.input.is_file():
        raise SystemExit(f"[FATAL] shellcode image missing: {args.input}")
    generate(args.input, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


