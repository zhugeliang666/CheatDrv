#!/usr/bin/env python3
"""扫描 x64 PE 中的 RIP-relative 自读指令：用于判定 EPT exec/read 双视图乒乓风险。

判定口径：
  1. 只统计落在 .pdata RUNTIME_FUNCTION 区间内的指令（排除 .text 内嵌的跳转表/常量表被误当代码）。
  2. RIP-relative 且非 LEA  -> 真实内存访问（读）；若目标与指令同 4KB 页 => EPT 乒乓必死。
  3. RIP-relative LEA       -> 仅取地址；若目标落在可执行节内，则后续索引访问同样会打到已装视图页。
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_REG_RIP, X86_INS_LEA


class Pe:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        assert data[self.e_lfanew:self.e_lfanew + 4] == b"PE\0\0"
        fh = self.e_lfanew + 4
        self.section_count = struct.unpack_from("<H", data, fh + 2)[0]
        opt_size = struct.unpack_from("<H", data, fh + 16)[0]
        self.opt = fh + 20
        self.image_base = struct.unpack_from("<Q", data, self.opt + 24)[0]
        self.image_size = struct.unpack_from("<I", data, self.opt + 56)[0]
        self.entry_rva = struct.unpack_from("<I", data, self.opt + 16)[0]
        self.dir_base = self.opt + 112
        self.sections = []
        st = self.opt + opt_size
        for i in range(self.section_count):
            off = st + i * 40
            name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            vsize, rva, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append(
                dict(name=name, rva=rva, vsize=vsize, raw_size=raw_size,
                     raw_off=raw_off, chars=chars,
                     span=max(vsize, raw_size))
            )

    def directory(self, index: int) -> tuple[int, int]:
        return struct.unpack_from("<II", self.data, self.dir_base + index * 8)

    def rva_to_off(self, rva: int) -> int:
        for s in self.sections:
            if s["rva"] <= rva < s["rva"] + s["span"]:
                delta = rva - s["rva"]
                return s["raw_off"] + delta if delta < s["raw_size"] else -1
        return -1

    def section_of(self, rva: int) -> str:
        for s in self.sections:
            if s["rva"] <= rva < s["rva"] + s["span"]:
                return s["name"]
        return "<none>"

    def section_by_name(self, name: str) -> dict:
        for s in self.sections:
            if s["name"] == name:
                return s
        raise KeyError(name)


def parse_pdata(pe: Pe) -> list[tuple[int, int]]:
    rva, size = pe.directory(3)  # IMAGE_DIRECTORY_ENTRY_EXCEPTION
    if not rva or not size:
        return []
    off = pe.rva_to_off(rva)
    if off < 0:
        return []
    out = []
    for i in range(size // 12):
        begin, end, _unwind = struct.unpack_from("<III", pe.data, off + i * 12)
        if end > begin:
            out.append((begin, end))
    out.sort()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--limit", type=int, default=40)
    args = ap.parse_args()

    data = args.input.read_bytes()
    pe = Pe(data)
    text = pe.section_by_name(".text")
    funcs = parse_pdata(pe)
    print(f"[*] {args.input.name} size={len(data)} image_base=0x{pe.image_base:X} "
          f"entry_rva=0x{pe.entry_rva:X}")
    print(f"[*] sections: " + ", ".join(
        f"{s['name']}(rva=0x{s['rva']:X} span=0x{s['span']:X}"
        f"{' X' if s['chars'] & 0x20000000 else ''})" for s in pe.sections))
    print(f"[*] .pdata functions={len(funcs)}  .text rva=0x{text['rva']:X} span=0x{text['span']:X}")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True

    text_lo = pe.image_base + text["rva"]
    text_hi = text_lo + text["span"]

    stats = {"insn": 0, "rip_lea": 0, "rip_mem": 0}
    same_page: list[tuple] = []
    text_cross: list[tuple] = []
    other: list[tuple] = []
    lea_into_text: list[tuple] = []

    for begin, end in funcs:
        size = end - begin
        if size <= 0 or size > 0x4000:
            continue
        off = pe.rva_to_off(begin)
        if off < 0:
            continue
        code = data[off:off + size]
        va = pe.image_base + begin
        for ins in md.disasm(code, va):
            stats["insn"] += 1
            is_lea = ins.id == X86_INS_LEA
            for op in ins.operands:
                if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                    continue
                target = ins.address + ins.size + op.mem.disp
                rec = (ins.address - pe.image_base, ins.address, ins.mnemonic, ins.op_str,
                       target, target - pe.image_base, pe.section_of(target - pe.image_base))
                if is_lea:
                    stats["rip_lea"] += 1
                    if p := rec:
                        if text_lo <= target < text_hi:
                            lea_into_text.append(p)
                    break
                stats["rip_mem"] += 1
                if (target >> 12) == (ins.address >> 12):
                    same_page.append(rec)
                elif text_lo <= target < text_hi:
                    text_cross.append(rec)
                else:
                    other.append(rec)
                break

    print(f"\n[=] 指令总数(仅在 .pdata 函数区间内) = {stats['insn']}")
    print(f"[=] RIP-relative LEA        = {stats['rip_lea']}")
    print(f"[=] RIP-relative 内存访问   = {stats['rip_mem']}")
    print(f"    ├─ 目标同 4KB 页 (EPT 乒乓必死)   = {len(same_page)}")
    print(f"    ├─ 目标跨页但在 .text (读视图=0)  = {len(text_cross)}")
    print(f"    └─ 目标在其他节/外部 (安全)       = {len(other)}")

    def dump(title: str, rows: list[tuple], n: int) -> None:
        print(f"\n--- {title} ({len(rows)}) ---")
        for r in rows[:n]:
            print(f"  rva=0x{r[0]:06X} {r[2]:<8} {r[3]:<40} -> rva=0x{r[5]:06X} [{r[6]}]")
        if len(rows) > n:
            print(f"  ... 其余 {len(rows) - n} 条省略")

    # --- 第二遍：全 .text 线性扫描（含 .pdata 未覆盖区间），用于交叉验证覆盖率 ---
    full = {"insn": 0, "rip_lea": 0, "rip_mem": 0, "same": 0, "cross": 0, "out": 0}
    full_same: list[tuple] = []
    off = pe.rva_to_off(text["rva"])
    code = data[off:off + text["span"]]
    for ins in md.disasm(code, text_lo):
        if ins.id == 0:  # skipdata 伪指令（.byte）
            continue
        full["insn"] += 1
        is_lea = ins.id == X86_INS_LEA
        try:
            ops = ins.operands
        except Exception:
            continue
        for op in ops:
            if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                continue
            target = ins.address + ins.size + op.mem.disp
            if is_lea:
                full["rip_lea"] += 1
            else:
                full["rip_mem"] += 1
                if (target >> 12) == (ins.address >> 12):
                    full["same"] += 1
                    full_same.append((ins.address - pe.image_base, ins.address, ins.mnemonic,
                                      ins.op_str, target, target - pe.image_base,
                                      pe.section_of(target - pe.image_base)))
                elif text_lo <= target < text_hi:
                    full["cross"] += 1
                else:
                    full["out"] += 1
            break

    print(f"\n[=] 全 .text 线性扫描：指令={full['insn']} lea={full['rip_lea']} mem={full['rip_mem']} "
          f"| 同页={full['same']} 跨页.text={full['cross']} 其他={full['out']}")
    dump("全 .text 中同页 RIP 自读", full_same, args.limit)

    dump("其他节/外部 RIP 读（不落在已装视图页内）", other, args.limit)
    dump("同页 RIP 自读（exec/read 互斥 -> 无限 VM-exit）", same_page, args.limit)
    dump("跨页但落在 .text 的 RIP 读（数据访问命中已装视图页 -> 读到 dummy 页 0）", text_cross, args.limit)
    dump("LEA 指向 .text 内部（后续索引读同样打到视图页）", lea_into_text, args.limit)

    if same_page or text_cross:
        print("\n[!] 结论：存在自读指令，exec_shadow_read_zero 会在这些点乒乓或读到零。")
    else:
        print("\n[+] 结论：未发现自读指令。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
