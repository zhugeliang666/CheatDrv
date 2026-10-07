#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_shellcode.py — 从编译后的 shellcode.obj 提取机器码字节数组

用法：
    1. 编译 shellcode.asm: ml64 /c /Fo shellcode.obj shellcode.asm
    2. 提取字节码: python extract_shellcode.py shellcode.obj
    3. 输出 C++ 数组格式，可直接粘贴到 shellcode_builder.h
"""

import sys
import struct
from pathlib import Path

def parse_coff_obj(obj_path):
    """解析 COFF .obj 文件，提取 .text 段的机器码"""
    with open(obj_path, 'rb') as f:
        data = f.read()

    # COFF 文件头：20 字节
    # 偏移 0x02: NumberOfSections (2 bytes)
    # 偏移 0x14: SizeOfOptionalHeader (2 bytes, 应为 0)
    if len(data) < 20:
        raise ValueError("文件过小，不是有效的 COFF .obj 文件")

    num_sections = struct.unpack('<H', data[0x02:0x04])[0]
    opt_hdr_size = struct.unpack('<H', data[0x10:0x12])[0]

    # 节表起始位置 = 20 (文件头) + opt_hdr_size
    section_table_offset = 20 + opt_hdr_size

    # 遍历节表找 .text 段
    # 每个节表项：40 字节
    #   +0x00: Name (8 bytes)
    #   +0x10: PointerToRawData (4 bytes)
    #   +0x14: SizeOfRawData (4 bytes)
    for i in range(num_sections):
        sect_offset = section_table_offset + i * 40
        if sect_offset + 40 > len(data):
            continue

        sect_name = data[sect_offset:sect_offset+8].rstrip(b'\x00')
        raw_data_ptr = struct.unpack('<I', data[sect_offset+0x14:sect_offset+0x18])[0]
        raw_data_size = struct.unpack('<I', data[sect_offset+0x10:sect_offset+0x14])[0]

        if sect_name == b'.text' or sect_name.startswith(b'.text$'):
            # 找到代码段
            if raw_data_ptr == 0 or raw_data_size == 0:
                raise ValueError(f".text 段为空 (Ptr={raw_data_ptr:08X}, Size={raw_data_size})")

            code_bytes = data[raw_data_ptr:raw_data_ptr+raw_data_size]
            return code_bytes

    raise ValueError("未找到 .text 段")

def format_cpp_array(bytecode, name="scBytes", indent=4):
    """将字节码格式化为 C++ 数组"""
    lines = [f"static const uint8_t {name}[] = {{"]

    # 每行 16 字节
    for i in range(0, len(bytecode), 16):
        chunk = bytecode[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        lines.append(' ' * indent + hex_str + ',')

    lines[-1] = lines[-1].rstrip(',')  # 去掉最后一个逗号
    lines.append("};")
    lines.append(f"static const size_t {name}_size = sizeof({name});")

    return '\n'.join(lines)

def main():
    if len(sys.argv) < 2:
        print(f"用法: {sys.argv[0]} shellcode.obj")
        print("输出: C++ 格式的字节数组，可粘贴到 shellcode_builder.h")
        sys.exit(1)

    obj_path = Path(sys.argv[1])
    if not obj_path.exists():
        print(f"错误: 文件不存在 — {obj_path}")
        sys.exit(1)

    try:
        bytecode = parse_coff_obj(obj_path)
        print(f"// 提取自 {obj_path.name}, 大小: {len(bytecode)} 字节")
        print(format_cpp_array(bytecode))
        print(f"\n// 使用方法：")
        print(f"//   1. 复制上述数组到 shellcode_builder.h 的 InjectShellcode 函数内")
        print(f"//   2. 替换 lines 256-258 的 TODO 注释")
        print(f"//   3. 修改写入代码为：WhqlWritePhys(..., scBytes, scBytes_size)")
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
