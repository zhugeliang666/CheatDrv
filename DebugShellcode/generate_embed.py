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
        # LTCG 可能把导出直接放在实现处，也可能保留 E9 跳板；两者都合法。
        if self.data[offset] != 0xE9:
            return rva
        displacement = struct.unpack_from("<i", self.data, offset + 1)[0]
        return rva + 5 + displacement


def c_array(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        suffix = "," if offset + 16 < len(data) else ""
        lines.append("    " + ", ".join(f"0x{byte:02X}" for byte in chunk) + suffix)
    return "\n".join(lines)


EXCLUDED_R0_EXPORTS = ("PatchRuntimeDispatch", "PatchRuntimeSlot", "X1ImageSize", "X2ImageOffset")


def scan_text_reads(pe: "PeImage", image: bytes, text_rva: int, text_end: int) -> dict:
    """按 .pdata 函数区间反汇编 .text，审计 RIP 相对数据读。

    判定：含 [rip+disp32] 内存操作数、非 LEA、目标按段分类。
    排除仅供驱动注入前扫描特征偏移的 R0 辅助导出函数区间。
    缺 capstone 或 .pdata 未覆盖任何函数时直接失败（门禁不允许静默失效）。
    """
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        from capstone.x86 import X86_OP_MEM, X86_REG_RIP
    except ImportError as exc:
        raise SystemExit("[FATAL] 需要 capstone 审计 .text 自读：pip install capstone") from exc

    exception_rva, exception_size = struct.unpack_from("<II", image, pe.optional + 112 + 8 * 3)
    if not exception_rva or exception_size < 12:
        raise SystemExit("[FATAL] shellcode 缺少 .pdata 异常目录，无法做 .text 自读门禁")

    ranges = []
    for index in range(exception_size // 12):
        begin, end, _ = struct.unpack_from("<III", image, pe.file_offset(exception_rva + index * 12))
        if begin and end > begin and text_rva <= begin < text_end:
            ranges.append((begin, end))
    if not ranges:
        raise SystemExit("[FATAL] .pdata 未覆盖任何 .text 函数，无法做 .text 自读门禁")

    excluded = {}
    not_in_pdata = []
    for name in EXCLUDED_R0_EXPORTS:
        try:
            rva = pe.resolve_thunk(pe.export_rva(name))
        except ValueError:
            continue
        for begin, end in ranges:
            if begin <= rva < end:
                excluded[(begin, end)] = name
                break
        else:
            not_in_pdata.append(name)

    xconst = next((section for section in pe.sections if section[0] == ".xconst"), None)
    xconst_begin = xconst[1] if xconst else 0
    xconst_end = xconst_begin + max(xconst[2], xconst[3]) if xconst else 0

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    self_reads, xconst_reads, other_reads = [], [], []
    functions = 0
    for begin, end in ranges:
        if (begin, end) in excluded:
            continue
        functions += 1
        code = image[pe.file_offset(begin):pe.file_offset(begin) + (end - begin)]
        pc = begin
        while pc < end:
            decoded = False
            for insn in md.disasm(code[pc - begin:], pc):
                decoded = True
                if insn.mnemonic != "lea":
                    for operand in insn.operands:
                        if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                            target = insn.address + insn.size + operand.mem.disp
                            record = (insn.address, insn.mnemonic, insn.op_str, target)
                            if text_rva <= target < text_end:
                                self_reads.append(record)
                            elif xconst_begin <= target < xconst_end:
                                xconst_reads.append(record)
                            else:
                                other_reads.append(record)
                pc = insn.address + insn.size
                break
            if not decoded:
                pc += 1

    return {
        "self": self_reads,
        "xconst": xconst_reads,
        "other": other_reads,
        "functions": functions,
        "excluded": sorted(excluded.values()),
        "not_in_pdata": sorted(not_in_pdata),
    }


def first_rva(records: list) -> int:
    return min((record[0] for record in records), default=0)


def audit_comment(audit: dict) -> str:
    lines = [
        "// Auto-audited by generate_embed.py (scan over .pdata function ranges):",
        f"//   scanned .text functions      : {audit['functions']}",
        f"//   excluded R0 helper exports   : {', '.join(audit['excluded']) if audit['excluded'] else '-'}",
        f"//   R0 helpers without .pdata    : {', '.join(audit['not_in_pdata']) if audit['not_in_pdata'] else '-'}",
        f"//   .text self-read instructions : {len(audit['self'])} (first RVA: 0x{first_rva(audit['self']):X})",
        f"//   .text -> .xconst read insns  : {len(audit['xconst'])} (first RVA: 0x{first_rva(audit['xconst']):X})",
        f"//   .text -> other-section reads : {len(audit['other'])}",
    ]
    for record in audit["self"][:8]:
        lines.append(f"// [VIOLATION] .text self-read RVA=0x{record[0]:X}: {record[1]} {record[2]} -> target=0x{record[3]:X} (.text)")
    for record in audit["xconst"][:8]:
        lines.append(f"// [VIOLATION] .xconst read RVA=0x{record[0]:X}: {record[1]} {record[2]} -> target=0x{record[3]:X} (.xconst)")
    return "\n".join(lines)


def generate(source: Path, output: Path) -> None:
    image = source.read_bytes()
    pe = PeImage(image)
    # 入口点由链接器直接绑定到 X1；不要依赖 LTCG/节区排序产生的固定 thunk RVA。
    x1 = pe.entry_rva
    size_function = pe.resolve_thunk(pe.export_rva("X1ImageSize"))
    size_offset = pe.file_offset(size_function)
    if image[size_offset:size_offset + 3] != b"\x48\x8D\x05":
        raise ValueError("X1ImageSize 没有预期 LEA 元数据")
    size_disp = struct.unpack_from("<i", image, size_offset + 3)[0]
    end_rva = size_function + 7 + size_disp
    x2_offset_rva = pe.resolve_thunk(pe.export_rva("X2ImageOffset"))
    x2_offset_file = pe.file_offset(x2_offset_rva)
    x2_offset = None
    if image[x2_offset_file:x2_offset_file + 1] == b"\xB8":
        x2_offset = struct.unpack_from("<I", image, x2_offset_file + 1)[0]
    elif image[x2_offset_file:x2_offset_file + 3] == b"\x48\xC7\xC0":
        x2_offset = struct.unpack_from("<I", image, x2_offset_file + 3)[0]
    elif image[x2_offset_file:x2_offset_file + 3] == b"\x48\x8D\x05":
        x2 = x2_offset_rva + 7 + struct.unpack_from("<i", image, x2_offset_file + 3)[0]
    else:
        x2 = None
    if 'x2' not in locals() or x2 is None:
        x2 = x1 + x2_offset if x2_offset is not None else None
    if x2 is None:
        raise ValueError("X2ImageOffset 没有预期常量元数据")
    custom_hook_dispatch2 = pe.resolve_thunk(pe.export_rva("CustomHookDispatch2"))
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
    for label, rva in (("X1", x1), ("X2", x2),
                       ("CustomHookDispatch2", custom_hook_dispatch2),
                       ("RuntimeDispatch", runtime_dispatch)):
        if not text_rva <= rva < text_end:
            raise ValueError(f"{label} RVA 0x{rva:X} 不在 .text")
    if end_rva <= x1 or end_rva > text_end:
        raise ValueError("X1 镜像大小超出 .text")
    audit = scan_text_reads(pe, image, text_rva, text_end)
    audit_block = audit_comment(audit)
    digest = hashlib.sha256(image).hexdigest().upper()
    content = f"""#pragma once

// Generated from DebugShellcode shellcode.exe; do not edit by hand.
{audit_block}
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
static const unsigned long g_DebugShellcodeX2Rva = 0x{x2:X}u;
static const unsigned long g_DebugShellcodeX2Offset = 0x{x2 - text_rva:X}u;
static const unsigned long g_DebugShellcodeCustomHookDispatch2Rva = 0x{custom_hook_dispatch2:X}u;
static const unsigned long g_DebugShellcodeCustomHookDispatch2Offset = 0x{custom_hook_dispatch2 - text_rva:X}u;
static const unsigned long g_DebugShellcodeRuntimeDispatchRva = 0x{runtime_dispatch:X}u;
static const unsigned long g_DebugShellcodeRuntimeDispatchOffset = 0x{runtime_dispatch - text_rva:X}u;
static const unsigned long g_DebugShellcodeImageSpan = 0x{pe.image_size:X}u;
static constexpr unsigned long g_DebugShellcodeTextSelfReadCount = {len(audit['self'])}u;
static constexpr unsigned long g_DebugShellcodeTextSelfReadFirstRva = 0x{first_rva(audit['self']):X}u;
static constexpr unsigned long g_DebugShellcodeTextXconstReadCount = {len(audit['xconst'])}u;
static constexpr unsigned long g_DebugShellcodeTextXconstReadFirstRva = 0x{first_rva(audit['xconst']):X}u;
static constexpr unsigned long g_DebugShellcodeTextDataReadCount = {len(audit['other'])}u;
static constexpr unsigned long g_DebugShellcodeTextScannedFunctions = {audit['functions']}u;
static const unsigned char g_DebugShellcodeImage[] = {{
{c_array(image)}
}};
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = b"\xEF\xBB\xBF" + content.replace("\n", "\r\n").encode("utf-8")
    temporary = output.with_suffix(output.suffix + ".tmp")
    summary = (f"self_read={len(audit['self'])} xconst_read={len(audit['xconst'])} "
               f"other_read={len(audit['other'])} funcs={audit['functions']} "
               f"excluded={','.join(audit['excluded']) if audit['excluded'] else '-'}")
    if output.exists() and output.read_bytes() == encoded:
        print(f"[+] [Up-to-date] {output}: source_sha256={digest} {summary}")
        return
    temporary.write_bytes(encoded)
    temporary.replace(output)
    print(f"[+] [Updated] {output}: source={source} size={len(image)} entry=0x{x1:X} dispatch=0x{runtime_dispatch:X} source_sha256={digest} {summary}")


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


