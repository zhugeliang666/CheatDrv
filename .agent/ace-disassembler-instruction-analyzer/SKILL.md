---
name: ace-disassembler-instruction-analyzer
description: >
  ACE (Anti-Cheat Expert) 内核原生微型反汇编器与指令流分析引擎全量逆向分析。
  包含 32 个核心详解与全量子系统 78 个归属函数完整拓扑索引、x86/x64/AVX/AVX-512 指令前缀解码循环、REX 扩展字节、ModR/M 字段解构、SIB 寻址解构、EVEX (0x62) / VEX (0xC4/0xC5) / XOP (0x8F) 现代向量前缀状态机、18 族寄存器分类编码映射表、操作数有效宽度解析与内核 Hook/异常指令分析全景拓扑。
---

# ACE 内核原生微型反汇编器与指令流分析引擎深度逆向分析

## 1. 架构总览与微型反汇编拓扑

在内核特权级（Ring 0）对抗中，反作弊驱动面临严重的系统环境制约：不能依赖应用层反汇编库（如 Capstone、Zydis），同时必须精确测算指令长度以实施系统调用与驱动代码的完整性校验（Inline Hook 探测、Trampoline 跳板构造、RIP 相对寻址修复、硬件 `#DB` / `#GP` 故障指令反解）。

ACE 驱动在 `sub_1400359A0` 构建了一套完整的、工业级自研微型反汇编器（Micro-Disassembler）。该引擎完全独立运行于内核无锁环境中，原生支持从 8086 到现代 x64、AVX2、AVX-512 及 AMD XOP 的全部前缀、寻址方式与操作数解构。

```
                    ┌────────────────────────────────────────────────────────┐
                    │  sub_1400359A0 (反汇编引擎总调度: 解码单条 x86/x64 指令)  │
                    └──────────────────────────┬─────────────────────────────┘
                                               │
         ┌───────────────────┬─────────────────┼─────────────────┬───────────────────┐
         ▼                   ▼                 ▼                 ▼                   ▼
  【前缀解析循环】     【向量前缀状态机】  【寻址与ModR/M】   【操作数与寄存器】    【重定位与跳转】
   sub_1400338E0       sub_140033E30      sub_140034EF0       sub_140032D30        sub_140036980
  (0x66/67/F0/F2/F3)  (AVX-512 EVEX 0x62)(ModR/M 字段拆解)   (ModR/M+REX 寄存器)  (RIP 相对偏移修复)
   sub_140036DD0       sub_140036F60      sub_140036ED0       sub_1400353A0        sub_1400342B0
  (REX.W/R/X/B 提取)  (VEX 0xC4/0xC5)    (SIB Scale/Idx/Base)(内存操作数描述符)   (操作码语义扩展)
                       sub_140037310      sub_140033270       sub_140035910
                      (AMD XOP 0x8F)     (Base+Idx*Scale+Disp)(寄存器操作数描述符)
```

---

## 2. 18 族寄存器分类编码与架构属性表 (`byte_140059380`)

引擎内部采用 8 字节定长结构体维护全架构寄存器分类体系：
`struct ACE_REG_CLASS_ENTRY { uint8_t FamilyId; uint8_t MinId; uint8_t MaxId; uint8_t Reserved; uint16_t BitWidth; uint16_t EffectiveWidth; };`

| 族编号 (FamilyId) | 寄存器分类族 | 寄存器编号范围 (Min~Max) | 物理位宽 (BitWidth) | 对应物理寄存器 |
| :---: | :--- | :---: | :---: | :--- |
| **1** | 8-bit 通用寄存器 | 1 ~ 20 | 8-bit | AL, CL, DL, BL, AH, CH, DH, BH, SPL, BPL, SIL, DIL, R8B~R15B |
| **2** | 16-bit 通用寄存器 | 21 ~ 36 | 16-bit | AX, CX, DX, BX, SP, BP, SI, DI, R8W ~ R15W |
| **3** | 32-bit 通用寄存器 | 37 ~ 52 | 32-bit | EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, R8D ~ R15D |
| **4** | 64-bit 通用寄存器 | 53 ~ 68 | 64-bit | RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8 ~ R15 |
| **5** | x87 浮点寄存器 | 69 ~ 76 | 80-bit | ST(0) ~ ST(7) |
| **6** | MMX 向量寄存器 | 77 ~ 84 | 64-bit | MM0 ~ MM7 |
| **7** | SSE XMM 寄存器 | 85 ~ 116 | 128-bit | XMM0 ~ XMM31 |
| **8** | AVX YMM 寄存器 | 117 ~ 148 | 256-bit | YMM0 ~ YMM31 |
| **9** | AVX-512 ZMM 寄存器 | 149 ~ 180 | 512-bit | ZMM0 ~ ZMM31 |
| **10**| 控制寄存器 (Control Reg) | 181 ~ 183 | 特殊 | CR0, CR2, CR3, CR4, CR8 |
| **11**| 调试寄存器 (Debug Reg) | 184 ~ 186 | 特殊 | DR0 ~ DR7 |
| **12**| 段寄存器 (Segment Reg) | 187 ~ 192 | 16-bit | ES, CS, SS, DS, FS, GS |
| **13**| BND 边界寄存器 (MPX) | 197 ~ 204 | 128-bit | BND0 ~ BND3 |
| **14**| AVX-512 掩码寄存器 | 205 ~ 220 | 64-bit | K0 ~ K7 |

---

## 3. 全量 32 个反汇编子函数逐一深度逆向

### 函数 1：`sub_1400329C0` —— 寄存器分类与组内索引到统合寄存器 ID 映射例程
* **地址**：`0x1400329c0`，大小 `137` 字节 (`0x89`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_1400329C0(unsigned __int8 a1, unsigned __int8 a2)
  {
    if ( a1 != 0 && (a1 <= 9u || a1 > 0xBu) && a1 < 0x12u && a2 <= byte_140059380[8 * a1 + 2] - byte_140059380[8 * a1 + 1] )
      return a2 + byte_140059380[8 * a1 + 1];
    else
      return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 2：`sub_140032A50` —— 统合寄存器 ID 反查其所属架构族类别 (8/16/32/64/XMM/YMM/ZMM/CR/DR/Segment)
* **地址**：`0x140032a50`，大小 `110` 字节 (`0x6e`)
* **反编译伪代码**：
  ```c
  unsigned __int8 __fastcall sub_140032A50(unsigned __int8 a1)
  {
    unsigned int i; // [rsp+0h] [rbp-18h]
  
    for ( i = 0; i < 0x12; ++i )
    {
      if ( a1 >= (int)byte_140059380[8 * i + 1] && a1 <= (int)byte_140059380[8 * i + 2] )
        return byte_140059380[8 * i];
    }
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 3：`sub_140032AC0` —— 统合寄存器 ID 提取其在组内的相对索引 (0~15)
* **地址**：`0x140032ac0`，大小 `167` 字节 (`0xa7`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140032AC0(unsigned __int8 a1)
  {
    unsigned int i; // [rsp+0h] [rbp-18h]
    unsigned __int8 v3; // [rsp+4h] [rbp-14h]
  
    for ( i = 0; i < 0x12; ++i )
    {
      v3 = byte_140059380[8 * i];
      if ( v3 != 0
        && (v3 <= 9u || v3 > 0xBu)
        && a1 >= (int)byte_140059380[8 * i + 1]
        && a1 <= (int)byte_140059380[8 * i + 2] )
      {
        return a1 - (unsigned int)byte_140059380[8 * i + 1];
      }
    }
    return 0xFFFFFFFFLL;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 4：`sub_140032B70` —— 架构寄存器物理位宽查询引擎 (8/16/32/64/80/128/256/512 位)
* **地址**：`0x140032b70`，大小 `212` 字节 (`0xd4`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140032B70(unsigned __int8 a1)
  {
    __int64 result; // rax
    unsigned int i; // [rsp+0h] [rbp-18h]
  
    switch ( a1 )
    {
      case 0xB5u:
      case 0xB8u:
        result = 16;
        break;
      case 0xB6u:
      case 0xB9u:
        result = 32;
        break;
      case 0xB7u:
      case 0xBAu:
        result = 64;
        break;
      default:
        for ( i = 0; i < 0x12; ++i )
        {
          if ( a1 >= (int)byte_140059380[8 * i + 1] && a1 <= (int)byte_140059380[8 * i + 2] )
            return *(unsigned __int16 *)&byte_140059380[8 * i + 4];
        }
        result = 0;
        break;
    }
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 5：`sub_140032C50` —— 寄存器操作数有效数据宽度查询
* **地址**：`0x140032c50`，大小 `212` 字节 (`0xd4`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140032C50(unsigned __int8 a1)
  {
    __int64 result; // rax
    unsigned int i; // [rsp+0h] [rbp-18h]
  
    switch ( a1 )
    {
      case 0xB5u:
      case 0xB8u:
        result = 16;
        break;
      case 0xB6u:
      case 0xB9u:
        result = 32;
        break;
      case 0xB7u:
      case 0xBAu:
        result = 64;
        break;
      default:
        for ( i = 0; i < 0x12; ++i )
        {
          if ( a1 >= (int)byte_140059380[8 * i + 1] && a1 <= (int)byte_140059380[8 * i + 2] )
            return *(unsigned __int16 *)&byte_140059380[8 * i + 6];
        }
        result = 0;
        break;
    }
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 6：`sub_140032D30` —— 寄存器操作数综合解码器 (结合 ModR/M 与 REX/EVEX 前缀映射源/目的物理寄存器)
* **地址**：`0x140032d30`，大小 `1336` 字节 (`0x538`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140032D30(__int64 a1, __int64 a2, char a3, unsigned __int8 a4)
  {
    __int64 result; // rax
    unsigned __int8 v5; // [rsp+0h] [rbp-38h]
    unsigned __int8 v6; // [rsp+1h] [rbp-37h]
    unsigned __int8 v7; // [rsp+2h] [rbp-36h]
    unsigned __int8 v8; // [rsp+3h] [rbp-35h]
    unsigned __int8 v9; // [rsp+4h] [rbp-34h]
  
    if ( **(_BYTE **)a1 == 1 )
    {
      switch ( a3 )
      {
        case 1:
          v8 = *(_BYTE *)(a2 + 22) & 0xF;
          if ( v8 > 7u )
            v8 -= 8;
          result = (8 * *(unsigned __int8 *)(a1 + 46)) | (unsigned int)v8;
          break;
        case 2:
          v5 = *(_BYTE *)(a2 + 823);
          switch ( a4 )
          {
            case 1u:
            case 2u:
            case 3u:
            case 4u:
            case 7u:
            case 8u:
            case 9u:
            case 0xEu:
            case 0xFu:
              v5 |= 8 * *(_BYTE *)(a1 + 44);
              break;
            default:
              break;
          }
          if ( a4 >= 7u && a4 <= 9u )
            v5 |= 16 * *(_BYTE *)(a1 + 49);
          result = v5;
          break;
        case 3:
          if ( a4 < 7u )
            goto LABEL_32;
          if ( a4 <= 9u )
            return *(unsigned __int8 *)(a1 + 51);
          if ( a4 == 16 )
            result = *(_BYTE *)(a1 + 51) & 7;
          else
  LABEL_32:
            result = *(_BYTE *)(a1 + 51) & 0xF;
          break;
        case 4:
          v6 = *(_BYTE *)(a2 + 824);
          switch ( a4 )
          {
            case 1u:
            case 2u:
            case 3u:
            case 4u:
            case 7u:
            case 8u:
            case 9u:
            case 0xEu:
            case 0xFu:
              v6 |= 8 * *(_BYTE *)(a1 + 46);
              break;
            default:
              break;
          }
          if ( (*(_BYTE *)(a2 + 20) == 5 || *(_BYTE *)(a2 + 20) == 6) && a4 >= 7u && a4 <= 9u )
            v6 |= 16 * *(_BYTE *)(a1 + 45);
          result = v6;
          break;
        case 5:
          if ( *(_BYTE *)(a2 + 824) == 4 )
            result = (8 * *(unsigned __int8 *)(a1 + 46)) | (unsigned int)*(unsigned __int8 *)(a2 + 829);
          else
            result = (8 * *(unsigned __int8 *)(a1 + 46)) | (unsigned int)*(unsigned __int8 *)(a2 + 824);
          break;
        case 6:
          result = (8 * *(unsigned __int8 *)(a1 + 45)) | (unsigned int)*(unsigned __int8 *)(a2 + 828);
          break;
        case 7:
          result = (16 * *(unsigned __int8 *)(a1 + 50))
                 | (8 * *(unsigned __int8 *)(a1 + 45))
                 | (unsigned int)*(unsigned __int8 *)(a2 + 828);
          break;
        case 8:
          v9 = (*(_QWORD *)(a2 + 856) >> 4) & 0xF;
          if ( (*(_BYTE *)(a2 + 20) == 5 || *(_BYTE *)(a2 + 20) == 6) && a4 >= 7u && a4 <= 9u )
            v9 |= 2 * (*(_BYTE *)(a2 + 856) & 8);
          result = v9;
          break;
        case 9:
          result = *(unsigned __int8 *)(a1 + 52);
          break;
      }
    }
    else
    {
      switch ( a3 )
      {
        case 1:
          v7 = *(_BYTE *)(a2 + 22) & 0xF;
          if ( v7 > 7u )
            v7 -= 8;
          result = v7;
          break;
        case 2:
          result = *(unsigned __int8 *)(a2 + 823);
          break;
        case 3:
          result = *(_BYTE *)(a1 + 51) & 7;
          break;
        case 4:
          result = *(unsigned __int8 *)(a2 + 824);
          break;
        case 5:
          if ( *(_BYTE *)(a2 + 824) == 4 )
            result = *(unsigned __int8 *)(a2 + 829);
          else
            result = *(unsigned __int8 *)(a2 + 824);
          break;
        case 6:
          result = *(unsigned __int8 *)(a2 + 828);
          break;
        case 7:
          result = *(unsigned __int8 *)(a2 + 828);
          break;
        case 8:
          result = (*(_QWORD *)(a2 + 856) >> 4) & 7LL;
          break;
        case 9:
          result = *(unsigned __int8 *)(a1 + 52);
          break;
      }
    }
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 7：`sub_140033270` —— 指令寻址模式解构器 (解析 Base + Index*Scale + Displacement 复杂寻址)
* **地址**：`0x140033270`，大小 `1636` 字节 (`0x664`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140033270(__int64 a1, _BYTE *a2, char *a3)
  {
    __int64 result; // rax
    char v4; // [rsp+0h] [rbp-58h]
    char v5; // [rsp+1h] [rbp-57h]
    bool v6; // [rsp+2h] [rbp-56h]
    char v7; // [rsp+3h] [rbp-55h]
    char v8; // [rsp+4h] [rbp-54h]
    unsigned __int8 v9; // [rsp+5h] [rbp-53h]
    char v10; // [rsp+6h] [rbp-52h]
    char v11; // [rsp+7h] [rbp-51h]
    unsigned __int8 v12; // [rsp+18h] [rbp-40h]
  
    v11 = a3[11] & 0xF;
    v4 = 1;
    v10 = 0;
    v6 = false;
    v9 = 0;
    switch ( a2[20] )
    {
      case 1:
        if ( a3[6] < 0 && **(_BYTE **)a1 == 6 )
          return 5;
        if ( a2[743] == 0 || (a3[12] & 4) != 0 )
          goto LABEL_17;
        return 8;
      case 2:
        goto LABEL_17;
      case 3:
        v4 = a3[12] & 0xF;
        goto LABEL_17;
      case 4:
        v4 = a3[12] & 0xF;
        v6 = (a3[12] & 0x10) != 0;
        goto LABEL_17;
      case 5:
        v4 = a3[12] & 0xF;
        v6 = (a3[12] & 0x10) != 0;
        v9 = ((unsigned __int8)a3[14] >> 2) & 3;
        if ( a2[797] == 0 || (a3[14] & 0x10) != 0 )
          goto LABEL_17;
        result = 14;
        break;
      case 6:
        v4 = a3[12] & 0xF;
        v6 = (a3[12] & 0x10) != 0;
        v9 = ((unsigned __int8)a3[13] >> 5) & 3;
        if ( byte_140059430[8 * (a3[13] & 0x1F) + (unsigned __int8)a2[817]] != 0 )
        {
  LABEL_17:
          switch ( v11 )
          {
            case 0:
            case 1:
              goto LABEL_43;
            case 2:
              if ( **(_BYTE **)a1 != 1 || *(_BYTE *)(a1 + 49) == 0 )
                goto LABEL_43;
              return 7;
            case 3:
              if ( a2[823] != 1 )
                goto LABEL_26;
              return 7;
            case 4:
  LABEL_26:
              if ( (unsigned __int8)a2[823] <= 5u )
                goto LABEL_43;
              result = 7;
              break;
            case 5:
              if ( byte_140059500[(unsigned __int8)((8 * *(_BYTE *)(a1 + 44)) | a2[823])] != 0 )
                goto LABEL_43;
              result = 7;
              break;
            case 6:
              if ( *(_BYTE *)(a1 + 44) == 0 )
                goto LABEL_43;
              result = 7;
              break;
            case 7:
              if ( **(_BYTE **)a1 != 1 || *(_BYTE *)(a1 + 44) == 0 && *(_BYTE *)(a1 + 49) == 0 )
                goto LABEL_43;
              result = 7;
              break;
            case 8:
              if ( *(_BYTE *)(a1 + 44) != 0 || (unsigned __int8)a2[823] > 3u )
              {
                result = 7;
              }
              else
              {
  LABEL_43:
                switch ( (unsigned __int8)a3[11] >> 4 )
                {
                  case 0:
                  case 1:
                  case 2:
                  case 5:
                  case 6:
                  case 7:
                    goto LABEL_55;
                  case 3:
                    if ( a2[824] != 1 )
                      goto LABEL_46;
                    return 7;
                  case 4:
  LABEL_46:
                    if ( (unsigned __int8)a2[824] <= 6u )
                      goto LABEL_55;
                    return 7;
                  case 8:
                    if ( *(_BYTE *)(a1 + 46) == 0 && *(_BYTE *)(a1 + 45) == 0 && (unsigned __int8)a2[824] <= 3u )
                      goto LABEL_55;
                    return 7;
                  case 9:
                    v10 = 1;
  LABEL_55:
                    switch ( v4 )
                    {
                      case 0:
                        goto LABEL_59;
                      case 1:
                        break;
                      case 2:
                        if ( *(_BYTE *)(a1 + 50) != 0 )
                          return 7;
                        break;
                      case 7:
                        if ( **(_BYTE **)a1 == 1 && *(unsigned __int8 *)(a1 + 51) > 7u )
                          return 7;
                        break;
                      default:
  LABEL_59:
                        if ( (*(_BYTE *)(a1 + 51) & 0xF) != 0 )
                          return 7;
                        if ( v10 == 0 && *(_BYTE *)(a1 + 50) != 0 )
                          return 7;
                        break;
                    }
                    if ( v6 )
                    {
                      v5 = a2[823];
                      v7 = a2[828];
                      if ( **(_BYTE **)a1 == 1 )
                      {
                        v5 |= (16 * *(_BYTE *)(a1 + 49)) | (8 * *(_BYTE *)(a1 + 44));
                        v7 |= (16 * *(_BYTE *)(a1 + 50)) | (8 * *(_BYTE *)(a1 + 45));
                      }
                      v8 = -16;
                      v12 = a2[20];
                      if ( v12 == 4 || v12 > 6u )
                      {
                        v8 = **(_BYTE **)a1 == 1 ? *(_BYTE *)(a1 + 51) : *(_BYTE *)(a1 + 51) & 7;
                      }
                      else if ( v11 == 0 )
                      {
                        v5 = -15;
                      }
                      if ( v5 == v7 || v5 == v8 || v7 == v8 )
                        return 7;
                    }
                    if ( v9 <= 1u )
                      goto LABEL_95;
                    if ( v9 == 2 )
                    {
                      if ( *(_BYTE *)(a1 + 52) == 0 )
                        return 14;
                    }
                    else if ( *(_BYTE *)(a1 + 52) != 0 )
                    {
                      return 14;
                    }
  LABEL_95:
                    result = 0;
                    break;
                }
              }
              break;
            default:
              abort();
          }
        }
        else
        {
          result = 5;
        }
        break;
    }
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 8：`sub_1400338E0` —— 指令传统前缀解析循环 (Prefix Loop: 段超越 0x26/2E/36/3E/64/65, 操作数大小 0x66, 地址大小 0x67, LOCK 0xF0, REP 0xF2/F3)
* **地址**：`0x1400338e0`，大小 `1350` 字节 (`0x546`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400338E0(__int64 a1, __int64 a2)
  {
    unsigned __int8 v3; // [rsp+20h] [rbp-18h] BYREF
    char v4; // [rsp+21h] [rbp-17h]
    int v5; // [rsp+24h] [rbp-14h]
    unsigned int v6; // [rsp+28h] [rbp-10h]
  
    v4 = 0;
    do
    {
      v6 = sub_140037970(a1, a2, &v3);
      if ( v6 != 0 )
        return v6;
      v5 = v3 - 38;
      switch ( v3 )
      {
        case 0x26u:
          ++*(_BYTE *)(a2 + 749);
          if ( **(_BYTE **)a1 != 1 || *(_BYTE *)(a1 + 24) != 100 && *(_BYTE *)(a1 + 24) != 101 )
            *(_BYTE *)(a1 + 24) = 38;
          break;
        case 0x2Eu:
          ++*(_BYTE *)(a2 + 746);
          if ( **(_BYTE **)a1 != 1 || *(_BYTE *)(a1 + 24) != 100 && *(_BYTE *)(a1 + 24) != 101 )
            *(_BYTE *)(a1 + 24) = 46;
          break;
        case 0x36u:
          ++*(_BYTE *)(a2 + 747);
          if ( **(_BYTE **)a1 != 1 || *(_BYTE *)(a1 + 24) != 100 && *(_BYTE *)(a1 + 24) != 101 )
            *(_BYTE *)(a1 + 24) = 54;
          break;
        case 0x3Eu:
          ++*(_BYTE *)(a2 + 748);
          if ( **(_BYTE **)a1 != 1 || *(_BYTE *)(a1 + 24) != 100 && *(_BYTE *)(a1 + 24) != 101 )
            *(_BYTE *)(a1 + 24) = 62;
          break;
        case 0x64u:
          ++*(_BYTE *)(a2 + 750);
          *(_BYTE *)(a1 + 24) = 100;
          break;
        case 0x65u:
          ++*(_BYTE *)(a2 + 751);
          *(_BYTE *)(a1 + 24) = 101;
          break;
        case 0x66u:
          if ( *(_BYTE *)(a1 + 25) == 0 )
            *(_BYTE *)(a1 + 25) = 102;
          ++*(_BYTE *)(a2 + 752);
          *(_QWORD *)(a2 + 672) |= 0x400000000uLL;
          break;
        case 0x67u:
          ++*(_BYTE *)(a2 + 753);
          *(_QWORD *)(a2 + 672) |= 0x800000000uLL;
          break;
        case 0xF0u:
          ++*(_BYTE *)(a2 + 743);
          break;
        case 0xF2u:
          *(_BYTE *)(a1 + 25) = -14;
          ++*(_BYTE *)(a2 + 745);
          break;
        case 0xF3u:
          *(_BYTE *)(a1 + 25) = -13;
          ++*(_BYTE *)(a2 + 744);
          break;
        default:
          if ( **(_BYTE **)a1 == 1 && (v3 & 0xF0) == 0x40 )
            *(_BYTE *)(a2 + 755) = v3;
          else
            v4 = 1;
          break;
      }
      if ( v4 == 0 )
      {
        if ( (v3 & 0xF0) != 0x40 )
          *(_BYTE *)(a2 + 755) = 0;
        *(_BYTE *)(a1 + *(unsigned __int8 *)(a2 + 742) + 26) = v3;
        *(_BYTE *)(a2 + (unsigned __int8)(*(_BYTE *)(a2 + 742))++ + 728) = v3;
        sub_1400379D0(a1, a2);
      }
    }
    while ( v4 == 0 );
    if ( *(_BYTE *)(a2 + 755) != 0 )
      sub_140036DD0(a1, a2, *(unsigned __int8 *)(a2 + 755));
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 9：`sub_140033E30` —— AVX-512 EVEX 前缀 4 字节完整解码器 (0x62 状态机提取 R, X, B, R', W, vvvv, pp, z, L'L, b, V', aaa)
* **地址**：`0x140033e30`，大小 `1149` 字节 (`0x47d`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140033E30(__int64 a1, __int64 a2, _BYTE *a3)
  {
    *(_QWORD *)(a2 + 672) |= 0x20uLL;
    *(_BYTE *)(a2 + 784) = 1;
    *(_BYTE *)(a2 + 785) = 98;
    *(_BYTE *)(a2 + 786) = a3[1];
    *(_BYTE *)(a2 + 787) = a3[2];
    *(_BYTE *)(a2 + 788) = a3[3];
    *(_BYTE *)(a2 + 789) = (int)(unsigned __int8)a3[1] >> 7;
    *(_BYTE *)(a2 + 790) = ((int)(unsigned __int8)a3[1] >> 6) & 1;
    *(_BYTE *)(a2 + 791) = ((int)(unsigned __int8)a3[1] >> 5) & 1;
    *(_BYTE *)(a2 + 792) = ((int)(unsigned __int8)a3[1] >> 4) & 1;
    if ( (((int)(unsigned __int8)a3[1] >> 2) & 3) != 0 )
      return 12;
    *(_BYTE *)(a2 + 793) = a3[1] & 3;
    if ( *(_BYTE *)(a2 + 793) == 0 )
      return 11;
    *(_BYTE *)(a2 + 794) = (int)(unsigned __int8)a3[2] >> 7;
    *(_BYTE *)(a2 + 795) = ((int)(unsigned __int8)a3[2] >> 3) & 0xF;
    *(_BYTE *)(a2 + 796) = a3[2] & 3;
    *(_BYTE *)(a2 + 797) = (int)(unsigned __int8)a3[3] >> 7;
    *(_BYTE *)(a2 + 798) = ((int)(unsigned __int8)a3[3] >> 6) & 1;
    *(_BYTE *)(a2 + 799) = ((int)(unsigned __int8)a3[3] >> 5) & 1;
    *(_BYTE *)(a2 + 800) = ((int)(unsigned __int8)a3[3] >> 4) & 1;
    *(_BYTE *)(a2 + 801) = ((int)(unsigned __int8)a3[3] >> 3) & 1;
    if ( *(_BYTE *)(a2 + 801) == 0 && **(_BYTE **)a1 != 1 )
      return 12;
    *(_BYTE *)(a2 + 802) = a3[3] & 7;
    if ( *(_BYTE *)(a2 + 797) != 0 && *(_BYTE *)(a2 + 802) == 0 )
      return 14;
    *(_BYTE *)(a1 + 43) = *(_BYTE *)(a2 + 794);
    *(_BYTE *)(a1 + 44) = (*(_BYTE *)(a2 + 789) & 1) == 0;
    *(_BYTE *)(a1 + 45) = (*(_BYTE *)(a2 + 790) & 1) == 0;
    *(_BYTE *)(a1 + 46) = (*(_BYTE *)(a2 + 791) & 1) == 0;
    *(_BYTE *)(a1 + 48) = ((int)(unsigned __int8)a3[3] >> 5) & 3;
    *(_BYTE *)(a1 + 49) = (*(_BYTE *)(a2 + 792) & 1) == 0;
    *(_BYTE *)(a1 + 50) = (*(_BYTE *)(a2 + 801) & 1) == 0;
    *(_BYTE *)(a1 + 51) = ~*(_BYTE *)(a2 + 795) & 0xF | (16 * ((*(_BYTE *)(a2 + 801) & 1) == 0));
    *(_BYTE *)(a1 + 52) = *(_BYTE *)(a2 + 802);
    if ( *(_BYTE *)(a2 + 801) == 0 && **(_BYTE **)a1 != 1 )
      return 12;
    if ( *(_BYTE *)(a2 + 800) != 0 || *(_BYTE *)(a1 + 48) != 3 )
      return 0;
    return 12;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 10：`sub_1400342B0` —— 操作码扩展属性与指令语义标志解构器
* **地址**：`0x1400342b0`，大小 `2264` 字节 (`0x8d8`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400342B0(_BYTE *a1, __int64 a2)
  {
    __int64 v3; // rdx
    __int64 v4; // rdx
    _WORD v5[2]; // [rsp+20h] [rbp-78h] BYREF
    unsigned __int8 v6; // [rsp+24h] [rbp-74h]
    unsigned int v7; // [rsp+28h] [rbp-70h]
    unsigned __int8 v8; // [rsp+2Ch] [rbp-6Ch]
    __int64 v9; // [rsp+30h] [rbp-68h]
    char *v10; // [rsp+38h] [rbp-60h] BYREF
    int v11; // [rsp+40h] [rbp-58h]
    BOOL v12; // [rsp+44h] [rbp-54h]
    BOOL v13; // [rsp+48h] [rbp-50h]
    BOOL v14; // [rsp+4Ch] [rbp-4Ch]
    BOOL v15; // [rsp+50h] [rbp-48h]
    BOOL v16; // [rsp+54h] [rbp-44h]
    BOOL v17; // [rsp+58h] [rbp-40h]
    unsigned int v18; // [rsp+5Ch] [rbp-3Ch]
    unsigned int v19; // [rsp+60h] [rbp-38h]
    unsigned int v20; // [rsp+64h] [rbp-34h]
    BOOL v21; // [rsp+68h] [rbp-30h]
    unsigned __int8 v22; // [rsp+6Ch] [rbp-2Ch]
    unsigned int v23; // [rsp+70h] [rbp-28h]
    unsigned int v24; // [rsp+74h] [rbp-24h]
    __int64 v25; // [rsp+78h] [rbp-20h]
    _QWORD v26[3]; // [rsp+80h] [rbp-18h] BYREF
  
    v9 = sub_14003B0B0();
    v25 = 0;
    while ( 2 )
    {
      v6 = *(_BYTE *)v9;
      v5[0] = 0;
      v7 = 0;
      v11 = v6;
      switch ( v6 )
      {
        case 0u:
          if ( v25 != 0 )
          {
            v9 = v25;
            v25 = 0;
            v6 = 11;
            if ( a1[25] == 102 )
              *(_QWORD *)(a2 + 672) |= 0x400000000uLL;
            goto LABEL_57;
          }
          return 5;
        case 1u:
          v7 = sub_140038980(a2, v5);
          goto LABEL_54;
        case 2u:
          v7 = sub_1400388D0(a2, v5);
          goto LABEL_54;
        case 3u:
          v7 = sub_140037C30(a2, v5);
          goto LABEL_54;
        case 4u:
          v7 = sub_1400380A0(a1, a2, v5);
          goto LABEL_54;
        case 5u:
          v7 = sub_140037D90(a1, v5);
          goto LABEL_54;
        case 6u:
          v7 = sub_140037E20(a1, v5);
          goto LABEL_54;
        case 7u:
          v7 = sub_140037E70(a1, a2, v5);
          goto LABEL_54;
        case 8u:
          v7 = sub_140037EF0(a1, a2, v5);
          goto LABEL_54;
        case 9u:
          v7 = sub_140037F70(a1, a2, v5);
          goto LABEL_54;
        case 0xAu:
          v7 = sub_140037FF0(a1, a2, v5);
          goto LABEL_54;
        case 0xBu:
          v7 = sub_140037CF0(a1, a2, v5);
          v25 = sub_14003AC10(v9, 0);
          goto LABEL_54;
        case 0xCu:
          v7 = sub_140038740(a1, a2, v5);
          goto LABEL_54;
        case 0xDu:
          v7 = sub_140037B30(a1, a2, v5);
          goto LABEL_54;
        case 0xEu:
          v7 = sub_140038930(a1, a2, v5);
          goto LABEL_54;
        case 0xFu:
          v7 = sub_140038890(a1, a2, v5);
          goto LABEL_54;
        case 0x10u:
          v7 = sub_140038850(a1, a2, v5);
          goto LABEL_54;
        case 0x11u:
          v7 = sub_140037CC0(a2, v5);
          goto LABEL_54;
        case 0x12u:
          v7 = sub_140038070(a2, v5);
          goto LABEL_54;
        case 0x13u:
          v12 = *(_BYTE *)(*(_QWORD *)a1 + 3LL) != 0;
          v5[0] = v12;
          goto LABEL_54;
        case 0x14u:
          v13 = *(_BYTE *)(*(_QWORD *)a1 + 4LL) != 0;
          v5[0] = v13;
          goto LABEL_54;
        case 0x15u:
          v14 = *(_BYTE *)(*(_QWORD *)a1 + 5LL) != 0;
          v5[0] = v14;
          goto LABEL_54;
        case 0x16u:
          v15 = *(_BYTE *)(*(_QWORD *)a1 + 6LL) != 0;
          v5[0] = v15;
          goto LABEL_54;
        case 0x17u:
          v16 = *(_BYTE *)(*(_QWORD *)a1 + 7LL) != 0;
          v5[0] = v16;
          goto LABEL_54;
        case 0x18u:
          v17 = *(_BYTE *)(*(_QWORD *)a1 + 8LL) != 0;
          v5[0] = v17;
  LABEL_54:
          v24 = v7;
          if ( v7 != 0 )
            return v24;
          v9 = sub_14003AC10(v9, v5[0]);
  LABEL_57:
          if ( v6 != 0 && (v6 & 0x80) == 0 )
            continue;
          return 0;
        default:
          sub_14003B180(*(unsigned __int8 *)(a2 + 20), *(unsigned __int16 *)(v9 + 1), &v10);
          sub_14003A490(a1, a2, v10);
          sub_14003A340(a1, a2, v10);
          sub_14003B0C0(v9, v26);
          v18 = sub_140036980(a1, a2, v26[0]);
          if ( v18 != 0 )
            return v18;
          v19 = sub_140033270((__int64)a1, (_BYTE *)a2, v10);
          if ( v19 != 0 )
            return v19;
          if ( *(_BYTE *)(a2 + 20) == 2 )
          {
            v20 = sub_1400377C0(a1, a2, a2 + 22);
            if ( v20 != 0 )
              return v20;
            v9 = sub_14003B0B0();
            LOWORD(v3) = 15;
            v9 = sub_14003AC10(v9, v3);
            LOWORD(v4) = 15;
            v9 = sub_14003AC10(v9, v4);
            v9 = sub_14003AC10(v9, *(unsigned __int8 *)(a2 + 22));
            if ( *(_BYTE *)v9 == 0 )
              return 5;
            v21 = *(unsigned __int8 *)(a2 + 822) != 3;
            v9 = sub_14003AC10(v9, v21);
            sub_14003B180(*(unsigned __int8 *)(a2 + 20), *(unsigned __int16 *)(v9 + 1), &v10);
          }
          *(_WORD *)(a2 + 2) = *(_WORD *)v10 & 0x7FF;
          *(_BYTE *)(a2 + 722) = (unsigned __int8)v10[7] >> 1;
          *(_BYTE *)(a2 + 723) = v10[8] & 0x7F;
          *(_BYTE *)(a2 + 724) = v10[9];
          *(_BYTE *)(a2 + 725) = v10[10] & 0x3F;
          if ( *(_BYTE *)(*(_QWORD *)a1 + 2LL) != 0 )
            return 0;
          sub_140039B20(a1, a2, v10);
          v22 = *(_BYTE *)(a2 + 20);
          if ( v22 >= 3u && v22 <= 6u )
            sub_140038E00(a1, a2, v10);
          v23 = sub_1400359A0(a1, a2, v10);
          if ( v23 != 0 )
            return v23;
          if ( *(_BYTE *)(a2 + 26) != 0 )
          {
            v8 = *(_BYTE *)(a2 + ((__int64)(*(unsigned __int8 *)(a2 + 26) - 1) << 6) + 46);
            if ( v8 == 181 || v8 == 182 || v8 == 183 )
              sub_140039AD0(a2, v10);
          }
          return 0;
      }
    }
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 11：`sub_140034B90` —— EVEX 压缩位移 (Disp8*N) 与广播操作数掩码解码器
* **地址**：`0x140034b90`，大小 `859` 字节 (`0x35b`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140034B90(_BYTE *a1, __int64 a2, _BYTE *a3)
  {
    *(_QWORD *)(a2 + 672) |= 0x40uLL;
    *(_BYTE *)(a2 + 803) = 1;
    *(_BYTE *)(a2 + 804) = 98;
    *(_BYTE *)(a2 + 805) = a3[1];
    *(_BYTE *)(a2 + 806) = a3[2];
    *(_BYTE *)(a2 + 807) = a3[3];
    *(_BYTE *)(a2 + 808) = (int)(unsigned __int8)a3[1] >> 7;
    *(_BYTE *)(a2 + 809) = ((int)(unsigned __int8)a3[1] >> 6) & 1;
    *(_BYTE *)(a2 + 810) = ((int)(unsigned __int8)a3[1] >> 5) & 1;
    *(_BYTE *)(a2 + 811) = ((int)(unsigned __int8)a3[1] >> 4) & 1;
    *(_BYTE *)(a2 + 812) = a3[1] & 0xF;
    if ( *(unsigned __int8 *)(a2 + 812) > 3u )
      return 11;
    *(_BYTE *)(a2 + 813) = (int)(unsigned __int8)a3[2] >> 7;
    *(_BYTE *)(a2 + 814) = ((int)(unsigned __int8)a3[2] >> 3) & 0xF;
    *(_BYTE *)(a2 + 815) = a3[2] & 3;
    *(_BYTE *)(a2 + 816) = (int)(unsigned __int8)a3[3] >> 7;
    *(_BYTE *)(a2 + 817) = ((int)(unsigned __int8)a3[3] >> 4) & 7;
    *(_BYTE *)(a2 + 818) = ((int)(unsigned __int8)a3[3] >> 3) & 1;
    *(_BYTE *)(a2 + 819) = a3[3] & 7;
    a1[43] = *(_BYTE *)(a2 + 813);
    a1[44] = (*(_BYTE *)(a2 + 808) & 1) == 0;
    a1[45] = (*(_BYTE *)(a2 + 809) & 1) == 0;
    a1[46] = (*(_BYTE *)(a2 + 810) & 1) == 0;
    a1[49] = (*(_BYTE *)(a2 + 811) & 1) == 0;
    a1[50] = (*(_BYTE *)(a2 + 818) & 1) == 0;
    a1[48] = 2;
    a1[51] = ~*(_BYTE *)(a2 + 814) & 0xF | (16 * ((*(_BYTE *)(a2 + 818) & 1) == 0));
    a1[52] = *(_BYTE *)(a2 + 819);
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 12：`sub_140034EF0` —— 原生 ModR/M 字节拆解例程 (提取 Mod, Reg/Opcode, R/M 字段)
* **地址**：`0x140034ef0`，大小 `139` 字节 (`0x8b`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140034EF0(__int64 a1, unsigned __int8 a2)
  {
    __int64 result; // rax
  
    *(_QWORD *)(a1 + 672) |= 1uLL;
    *(_BYTE *)(a1 + 820) = 1;
    *(_BYTE *)(a1 + 821) = a2;
    *(_BYTE *)(a1 + 822) = (int)a2 >> 6;
    *(_BYTE *)(a1 + 823) = ((int)a2 >> 3) & 7;
    result = a2 & 7;
    *(_BYTE *)(a1 + 824) = result;
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 13：`sub_140034F80` —— SIB 比例变址字节辅助解码器 (结合寄存器表映射物理变址寄存器)
* **地址**：`0x140034f80`，大小 `337` 字节 (`0x151`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_140034F80(__int64 a1, _BYTE *a2, __int64 a3)
  {
    char result; // al
    char v4; // [rsp+20h] [rbp-18h]
  
    a2[1] = 2;
    a2[16] = 1;
    v4 = (*(_BYTE *)(a3 + 9) >> 3) & 7;
    switch ( v4 )
    {
      case 0:
        goto LABEL_6;
      case 1:
        a2[18] = sub_1400329C0(byte_140059514[*(unsigned __int8 *)(a1 + 42)], 4u);
        break;
      case 2:
        a2[18] = sub_1400329C0(byte_140059514[*(unsigned __int8 *)(a1 + 42)], 5u);
        break;
      case 3:
        a2[18] = sub_1400329C0(byte_140059514[*(unsigned __int8 *)(a1 + 42)], 6u);
        break;
      case 4:
        a2[18] = sub_1400329C0(byte_140059514[*(unsigned __int8 *)(a1 + 42)], 7u);
        break;
      default:
  LABEL_6:
        a2[18] = sub_1400329C0(byte_140059514[*(unsigned __int8 *)(a1 + 42)], 3u);
        break;
    }
    result = *(_BYTE *)(a3 + 9) & 7;
    if ( result != 0 )
    {
      result = sub_1400329C0(0xCu, (*(_BYTE *)(a3 + 9) & 7) - 1);
      a2[17] = result;
    }
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 14：`sub_1400350E0` —— 立即数与直接偏移操作数绑定器
* **地址**：`0x1400350e0`，大小 `692` 字节 (`0x2b4`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400350E0(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
  {
    __int64 result; // rax
  
    *(_BYTE *)(a3 + 1) = 1;
    if ( (*(_BYTE *)(a4 + 9) & 7) != 0 )
      abort();
    result = *(unsigned __int8 *)(a4 + 10);
    *(_BYTE *)(a3 + 14) = result;
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 15：`sub_1400353A0` —— 内存操作数描述符封装引擎 (Memory Operand Descriptor Builder)
* **地址**：`0x1400353a0`，大小 `1387` 字节 (`0x56b`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400353A0(_BYTE **a1, __int64 a2, __int64 a3, unsigned __int8 a4)
  {
    unsigned __int8 v4; // al
    unsigned __int8 v5; // al
    char v7; // [rsp+20h] [rbp-48h]
    unsigned __int8 v8; // [rsp+21h] [rbp-47h]
    char v9; // [rsp+24h] [rbp-44h]
    char v10; // [rsp+28h] [rbp-40h]
    char v11; // [rsp+2Ch] [rbp-3Ch]
    char v12; // [rsp+30h] [rbp-38h]
    unsigned __int8 v13; // [rsp+38h] [rbp-30h]
    char v14; // [rsp+3Ch] [rbp-2Ch]
    unsigned __int8 v15; // [rsp+40h] [rbp-28h]
    char v16; // [rsp+44h] [rbp-24h]
    unsigned __int8 v17; // [rsp+48h] [rbp-20h]
    char v18; // [rsp+4Ch] [rbp-1Ch]
    unsigned __int8 v19; // [rsp+50h] [rbp-18h]
    char v20; // [rsp+54h] [rbp-14h]
  
    *(_BYTE *)(a3 + 1) = 2;
    *(_BYTE *)(a3 + 16) = 1;
    v8 = *(_BYTE *)(a2 + 824);
    v7 = 0;
    v9 = *(_BYTE *)(a2 + 25);
    switch ( v9 )
    {
      case 16:
        break;
      case 32:
        *(_BYTE *)(a3 + 18) = sub_140032D30((__int64)a1, a2, 5, 3u) + 37;
        v11 = *(_BYTE *)(a2 + 822);
        switch ( v11 )
        {
          case 0:
            goto LABEL_15;
          case 1:
            v7 = 8;
            break;
          case 2:
            v7 = 32;
            break;
          default:
  LABEL_15:
            if ( v8 == 5 )
            {
              if ( **a1 == 1 )
                *(_BYTE *)(a3 + 18) = -71;
              else
                *(_BYTE *)(a3 + 18) = 0;
              v7 = 32;
            }
            break;
        }
        if ( v8 == 4 )
        {
          if ( a4 != 0 )
            v13 = a4;
          else
            v13 = 3;
          if ( a4 != 0 )
            v14 = 7;
          else
            v14 = 6;
          if ( a4 != 0 )
            v15 = a4;
          else
            v15 = 3;
          v4 = sub_140032D30((__int64)a1, a2, v14, v13);
          *(_BYTE *)(a3 + 19) = sub_1400329C0(v15, v4);
          *(_BYTE *)(a3 + 20) = 1 << *(_BYTE *)(a2 + 827);
          if ( *(_BYTE *)(a3 + 19) == 41 )
          {
            *(_BYTE *)(a3 + 19) = 0;
            *(_BYTE *)(a3 + 20) = 0;
          }
          if ( *(_BYTE *)(a3 + 18) == 42 )
          {
            if ( *(_BYTE *)(a2 + 822) == 0 )
              *(_BYTE *)(a3 + 18) = 0;
            if ( *(_BYTE *)(a2 + 822) == 1 )
              v16 = 8;
            else
              v16 = 32;
            v7 = v16;
          }
        }
        else
        {
          *(_BYTE *)(a3 + 19) = 0;
          *(_BYTE *)(a3 + 20) = 0;
        }
        goto LABEL_77;
      case 64:
        *(_BYTE *)(a3 + 18) = sub_140032D30((__int64)a1, a2, 5, 4u) + 53;
        v12 = *(_BYTE *)(a2 + 822);
        switch ( v12 )
        {
          case 0:
            goto LABEL_47;
          case 1:
            v7 = 8;
            break;
          case 2:
            v7 = 32;
            break;
          default:
  LABEL_47:
            if ( v8 == 5 )
            {
              if ( **a1 == 1 )
                *(_BYTE *)(a3 + 18) = -70;
              else
                *(_BYTE *)(a3 + 18) = 0;
              v7 = 32;
            }
            break;
        }
        if ( (v8 & 7) == 4 )
        {
          if ( a4 != 0 )
            v17 = a4;
          else
            v17 = 4;
          if ( a4 != 0 )
            v18 = 7;
          else
            v18 = 6;
          if ( a4 != 0 )
            v19 = a4;
          else
            v19 = 4;
          v5 = sub_140032D30((__int64)a1, a2, v18, v17);
          *(_BYTE *)(a3 + 19) = sub_1400329C0(v19, v5);
          *(_BYTE *)(a3 + 20) = 1 << *(_BYTE *)(a2 + 827);
          if ( *(_BYTE *)(a3 + 19) == 57 )
          {
            *(_BYTE *)(a3 + 19) = 0;
            *(_BYTE *)(a3 + 20) = 0;
          }
          if ( *(_BYTE *)(a3 + 18) == 58 || *(_BYTE *)(a3 + 18) == 66 )
          {
            if ( *(_BYTE *)(a2 + 822) == 0 )
              *(_BYTE *)(a3 + 18) = 0;
            if ( *(_BYTE *)(a2 + 822) == 1 )
              v20 = 8;
            else
              v20 = 32;
            v7 = v20;
          }
        }
        else
        {
          *(_BYTE *)(a3 + 19) = 0;
          *(_BYTE *)(a3 + 20) = 0;
        }
        goto LABEL_77;
      default:
        break;
    }
    *(_BYTE *)(a3 + 18) = byte_140059418[v8];
    *(_BYTE *)(a3 + 19) = byte_140059420[v8];
    *(_BYTE *)(a3 + 20) = *(_BYTE *)(a3 + 19) != 0;
    v10 = *(_BYTE *)(a2 + 822);
    switch ( v10 )
    {
      case 0:
        goto LABEL_7;
      case 1:
        v7 = 8;
        break;
      case 2:
        v7 = 16;
        break;
      default:
  LABEL_7:
        if ( v8 == 6 )
        {
          v7 = 16;
          *(_BYTE *)(a3 + 18) = 0;
        }
        break;
    }
  LABEL_77:
    if ( v7 != 0 )
    {
      *(_BYTE *)(a3 + 24) = 1;
      *(_QWORD *)(a3 + 32) = *(_QWORD *)(a2 + 832);
    }
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 16：`sub_140035910` —— 寄存器操作数描述符封装例程 (Register Operand Descriptor Builder)
* **地址**：`0x140035910`，大小 `139` 字节 (`0x8b`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140035910(__int64 a1, __int64 a2, unsigned __int8 a3, unsigned __int8 a4)
  {
    *(_BYTE *)(a2 + 1) = 1;
    if ( a3 == 1 )
    {
      if ( (*(_QWORD *)(a1 + 672) & 4LL) != 0 && a4 >= 4u )
        *(_BYTE *)(a2 + 14) = a4 + 5;
      else
        *(_BYTE *)(a2 + 14) = a4 + 1;
    }
    else
    {
      *(_BYTE *)(a2 + 14) = sub_1400329C0(a3, a4);
    }
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 17：`sub_1400359A0` —— 反汇编分析引擎顶层指令流调度中枢 (Master Instruction Decoder & Semantic Resolver)
* **地址**：`0x1400359a0`，大小 `4060` 字节 (`0xfdc`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400359A0(__int64 a1, __int64 a2, __int64 a3)
  {
    unsigned __int8 v3; // al
    __int64 result; // rax
    unsigned __int8 v5; // al
    unsigned __int8 v6; // al
    unsigned __int8 v7; // al
    unsigned __int8 v8; // al
    unsigned __int8 v9; // al
    __int64 v10; // rax
    unsigned __int8 i; // [rsp+20h] [rbp-78h]
    unsigned __int8 v12; // [rsp+21h] [rbp-77h]
    unsigned __int8 v13; // [rsp+22h] [rbp-76h]
    _BYTE *v14; // [rsp+28h] [rbp-70h] BYREF
    int v15; // [rsp+30h] [rbp-68h]
    int v16; // [rsp+34h] [rbp-64h]
    int v17; // [rsp+38h] [rbp-60h]
    char v18; // [rsp+3Ch] [rbp-5Ch]
    int v19; // [rsp+40h] [rbp-58h]
    int v20; // [rsp+44h] [rbp-54h]
    int v21; // [rsp+48h] [rbp-50h]
    int v22; // [rsp+4Ch] [rbp-4Ch]
    int v23; // [rsp+50h] [rbp-48h]
    unsigned int v24; // [rsp+54h] [rbp-44h]
    unsigned int v25; // [rsp+58h] [rbp-40h]
    unsigned int v26; // [rsp+5Ch] [rbp-3Ch]
    unsigned int v27; // [rsp+60h] [rbp-38h]
    unsigned int v28; // [rsp+64h] [rbp-34h]
    unsigned int v29; // [rsp+68h] [rbp-30h]
    unsigned int v30; // [rsp+6Ch] [rbp-2Ch]
    unsigned int v31; // [rsp+70h] [rbp-28h]
    unsigned int v32; // [rsp+74h] [rbp-24h]
    unsigned int v33; // [rsp+78h] [rbp-20h]
    unsigned int v34; // [rsp+7Ch] [rbp-1Ch]
    unsigned int v35; // [rsp+80h] [rbp-18h]
    char v36; // [rsp+84h] [rbp-14h]
    char v37; // [rsp+88h] [rbp-10h]
  
    v13 = 0;
    *(_BYTE *)(a2 + 26) = sub_14003B2A0(a3, &v14);
    for ( i = 0; i < (int)*(unsigned __int8 *)(a2 + 26); ++i )
    {
      v12 = 0;
      *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 32) = i;
      *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 34) = (*v14 >> 5) & 3;
      *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 35) = v14[1] & 7;
      v18 = *v14 & 0x1F;
      switch ( v18 )
      {
        case 1:
          sub_1400350E0(a1, a2, a2 + ((unsigned __int64)i << 6) + 32, (__int64)v14);
          break;
        case 2:
          sub_140034F80(a1, (_BYTE *)(a2 + ((unsigned __int64)i << 6) + 32), (__int64)v14);
          break;
        case 3:
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 33) = 4;
          *(_WORD *)(a2 + ((unsigned __int64)i << 6) + 38) = 8;
          *(_QWORD *)(a2 + ((unsigned __int64)i << 6) + 88) = 1;
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 80) = 0;
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 81) = 0;
          break;
        default:
          break;
      }
      if ( *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 33) == 0 )
      {
        *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 36) = v14[9];
        v15 = *v14 & 0x1F;
        v15 -= 4;
        switch ( v15 )
        {
          case 0:
            v12 = 1;
            break;
          case 1:
            v12 = 2;
            break;
          case 2:
            v12 = 3;
            break;
          case 3:
            v12 = 4;
            break;
          case 4:
            if ( *(_BYTE *)(a2 + 24) == 16 )
            {
              v20 = 2;
            }
            else
            {
              if ( *(_BYTE *)(a2 + 24) == 32 )
                v19 = 3;
              else
                v19 = 4;
              v20 = v19;
            }
            v12 = v20;
            break;
          case 5:
            if ( *(_BYTE *)(a2 + 24) == 16 )
            {
              v22 = 3;
            }
            else
            {
              if ( *(_BYTE *)(a2 + 24) == 32 )
                v21 = 3;
              else
                v21 = 4;
              v22 = v21;
            }
            v12 = v22;
            break;
          case 6:
            if ( *(_BYTE *)(a2 + 24) == 16 )
              v23 = 2;
            else
              v23 = 3;
            v12 = v23;
            break;
          case 7:
            v12 = 5;
            break;
          case 8:
            v12 = 6;
            break;
          case 9:
            v12 = 7;
            break;
          case 10:
            v12 = 8;
            break;
          case 11:
            v12 = 9;
            break;
          case 12:
            v12 = 17;
            break;
          case 13:
            v12 = 12;
            break;
          case 14:
            v12 = 14;
            break;
          case 15:
            v12 = 15;
            break;
          case 16:
            v12 = 16;
            break;
          default:
            break;
        }
        if ( v12 != 0 )
        {
          v16 = (unsigned __int8)v14[9];
          switch ( --v16 )
          {
            case 0:
              v3 = sub_140032D30(a1, a2, 2, v12);
              v24 = sub_140035910(a2, a2 + ((unsigned __int64)i << 6) + 32, v12, v3);
              if ( v24 == 0 )
                goto LABEL_99;
              result = v24;
              break;
            case 1:
              v5 = sub_140032D30(a1, a2, 4, v12);
              v25 = sub_140035910(a2, a2 + ((unsigned __int64)i << 6) + 32, v12, v5);
              if ( v25 == 0 )
                goto LABEL_99;
              result = v25;
              break;
            case 2:
              v6 = sub_140032D30(a1, a2, 1, v12);
              v26 = sub_140035910(a2, a2 + ((unsigned __int64)i << 6) + 32, v12, v6);
              if ( v26 == 0 )
                goto LABEL_99;
              result = v26;
              break;
            case 3:
              v7 = sub_140032D30(a1, a2, 3, v12);
              v27 = sub_140035910(a2, a2 + ((unsigned __int64)i << 6) + 32, v12, v7);
              if ( v27 == 0 )
                goto LABEL_99;
              result = v27;
              break;
            case 4:
              v9 = sub_140032D30(a1, a2, 8, v12);
              v29 = sub_140035910(a2, a2 + ((unsigned __int64)i << 6) + 32, v12, v9);
              if ( v29 == 0 )
                goto LABEL_99;
              result = v29;
              break;
            case 5:
              v8 = sub_140032D30(a1, a2, 9, v12);
              v28 = sub_140035910(a2, a2 + ((unsigned __int64)i << 6) + 32, v12, v8);
              if ( v28 == 0 )
                goto LABEL_99;
              result = v28;
              break;
          }
          return result;
        }
        v17 = *v14 & 0x1F;
        v17 -= 21;
        switch ( v17 )
        {
          case 0:
            v30 = sub_1400353A0((_BYTE **)a1, a2, a2 + ((unsigned __int64)i << 6) + 32, 0);
            if ( v30 == 0 )
              goto LABEL_87;
            return v30;
          case 1:
            v31 = sub_1400353A0((_BYTE **)a1, a2, a2 + ((unsigned __int64)i << 6) + 32, 7u);
            if ( v31 == 0 )
              goto LABEL_87;
            return v31;
          case 2:
            v32 = sub_1400353A0((_BYTE **)a1, a2, a2 + ((unsigned __int64)i << 6) + 32, 8u);
            if ( v32 == 0 )
              goto LABEL_87;
            return v32;
          case 3:
            v33 = sub_1400353A0((_BYTE **)a1, a2, a2 + ((unsigned __int64)i << 6) + 32, 9u);
            if ( v33 == 0 )
              goto LABEL_87;
            return v33;
          case 6:
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 33) = 3;
            *(_DWORD *)(a2 + ((unsigned __int64)i << 6) + 76) = *(_DWORD *)(a2 + 856);
            *(_WORD *)(a2 + ((unsigned __int64)i << 6) + 72) = *(_WORD *)(a2 + 880);
            goto LABEL_87;
          case 7:
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 35) = 0;
            v34 = sub_1400353A0((_BYTE **)a1, a2, a2 + ((unsigned __int64)i << 6) + 32, 0);
            if ( v34 != 0 )
              return v34;
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 48) = 2;
            goto LABEL_87;
          case 8:
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 33) = 2;
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 48) = 1;
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 56) = 1;
            *(_QWORD *)(a2 + ((unsigned __int64)i << 6) + 64) = *(_QWORD *)(a2 + 832);
            goto LABEL_87;
          case 9:
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 35) = 0;
            v35 = sub_1400353A0((_BYTE **)a1, a2, a2 + ((unsigned __int64)i << 6) + 32, 0);
            if ( v35 != 0 )
              return v35;
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 48) = 3;
            if ( *(unsigned __int8 *)(a2 + ((unsigned __int64)i << 6) + 50) == 185
              || *(unsigned __int8 *)(a2 + ((unsigned __int64)i << 6) + 50) == 186 )
            {
              return 5;
            }
  LABEL_87:
            if ( *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 33) != 0 )
            {
              if ( (*(_BYTE *)(a2 + 20) == 5 || *(_BYTE *)(a2 + 20) == 6) && *(_BYTE *)(a2 + 840) == 8 )
                *(_QWORD *)(a2 + ((unsigned __int64)i << 6) + 64) *= *(unsigned __int8 *)(a1 + 56);
            }
            else
            {
              v36 = *v14 & 0x1F;
              if ( v36 == 25 || v36 == 26 )
              {
                *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 33) = 4;
                *(_WORD *)(a2 + ((unsigned __int64)i << 6) + 38) = 8
                                                                 * *(_WORD *)&v14[2 * *(unsigned __int8 *)(a1 + 41) + 2];
                if ( v14[9] == 5 )
                  v10 = *(_BYTE *)(a2 + 24LL * v13 + 856) & 0xF;
                else
                  v10 = *(_QWORD *)(a2 + 24LL * v13 + 856);
                *(_QWORD *)(a2 + ((unsigned __int64)i << 6) + 88) = v10;
                *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 80) = *(_BYTE *)(a2 + 24LL * v13 + 848);
                *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 81) = *(_BYTE *)(a2 + 24LL * v13++ + 849);
              }
            }
            break;
          default:
            goto LABEL_87;
        }
      }
  LABEL_99:
      if ( *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 33) == 2 )
      {
        if ( (*(_QWORD *)(a2 + 672) & 0x10000000LL) != 0 )
        {
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) = -68;
        }
        else if ( (*(_QWORD *)(a2 + 672) & 0x20000000LL) != 0 )
        {
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) = -67;
        }
        else if ( (*(_QWORD *)(a2 + 672) & 0x40000000LL) != 0 )
        {
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) = -66;
        }
        else if ( (*(_QWORD *)(a2 + 672) & 0x80000000LL) != 0 )
        {
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) = -69;
        }
        else if ( (*(_QWORD *)(a2 + 672) & 0x100000000LL) != 0 )
        {
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) = -65;
        }
        else if ( (*(_QWORD *)(a2 + 672) & 0x200000000LL) != 0 )
        {
          *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) = -64;
        }
        else if ( *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) == 0 )
        {
          if ( *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 50) == 57
            || *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 50) == 58
            || *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 50) == 41
            || *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 50) == 42
            || *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 50) == 25
            || *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 50) == 26 )
          {
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) = -67;
          }
          else
          {
            *(_BYTE *)(a2 + ((unsigned __int64)i << 6) + 49) = -66;
          }
        }
      }
      sub_14003A5F0(a1, a2, a2 + ((unsigned __int64)i << 6) + 32, v14);
      v14 += 11;
    }
    if ( *(_BYTE *)(a2 + 713) != 0 && *(_BYTE *)(a2 + 712) == 1 && *(_BYTE *)(a2 + 714) == 0 )
    {
      v37 = *(_BYTE *)(a2 + 35);
      if ( v37 == 2 )
      {
        if ( *(_BYTE *)(a2 + 33) == 2 )
          *(_BYTE *)(a2 + 35) = 5;
        else
          *(_BYTE *)(a2 + 35) = 6;
      }
      else if ( v37 == 3 )
      {
        *(_BYTE *)(a2 + 35) = 6;
      }
    }
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 18：`sub_140036980` —— 指令跳转目标与相对偏移重定位计算引擎 (Branch Target & RIP Relative Displacement Calculator)
* **地址**：`0x140036980`，大小 `1103` 字节 (`0x44f`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140036980(__int64 a1, __int64 a2, _BYTE *a3)
  {
    __int64 v4; // r8
    int v5; // r9d
    unsigned __int8 v6; // [rsp+30h] [rbp-38h]
    bool v7; // [rsp+31h] [rbp-37h]
    unsigned __int8 v8; // [rsp+32h] [rbp-36h] BYREF
    unsigned __int8 v9; // [rsp+33h] [rbp-35h] BYREF
    char v10; // [rsp+34h] [rbp-34h]
    char v11; // [rsp+38h] [rbp-30h]
    char v12; // [rsp+3Ch] [rbp-2Ch]
    unsigned int v13; // [rsp+40h] [rbp-28h]
    BOOL v14; // [rsp+44h] [rbp-24h]
    unsigned int v15; // [rsp+48h] [rbp-20h]
    int v16; // [rsp+4Ch] [rbp-1Ch]
    unsigned int v17; // [rsp+50h] [rbp-18h]
    unsigned int v18; // [rsp+54h] [rbp-14h]
    unsigned int v19; // [rsp+58h] [rbp-10h]
    unsigned int v20; // [rsp+5Ch] [rbp-Ch]
  
    if ( (*a3 & 1) == 0 )
      goto LABEL_46;
    if ( *(_BYTE *)(a2 + 820) == 0 )
    {
      v13 = sub_1400377C0(a1, a2, &v8);
      if ( v13 != 0 )
        return v13;
      sub_140034EF0(a2, v8);
    }
    v7 = false;
    v6 = 0;
    if ( (*a3 & 0x10) != 0 )
      goto LABEL_46;
    v12 = *(_BYTE *)(a2 + 25);
    if ( v12 != 16 && (v12 == 32 || v12 == 64) )
    {
      v14 = *(_BYTE *)(a2 + 822) != 3 && *(_BYTE *)(a2 + 824) == 4;
      v7 = v14;
      v11 = *(_BYTE *)(a2 + 822);
      if ( v11 != 0 )
      {
        switch ( v11 )
        {
          case 1:
            v6 = 8;
            goto LABEL_35;
          case 2:
            v6 = 32;
            goto LABEL_35;
          case 3:
            goto LABEL_35;
          default:
            break;
        }
      }
      if ( *(_BYTE *)(a2 + 824) == 5 )
      {
        if ( **(_BYTE **)a1 == 1 )
          *(_QWORD *)(a2 + 672) |= 0x80uLL;
        v6 = 32;
      }
    }
    else
    {
      v10 = *(_BYTE *)(a2 + 822);
      if ( v10 != 0 )
      {
        switch ( v10 )
        {
          case 1:
            v6 = 8;
            goto LABEL_35;
          case 2:
            v6 = 16;
            goto LABEL_35;
          case 3:
            goto LABEL_35;
          default:
            break;
        }
      }
      if ( *(_BYTE *)(a2 + 824) == 6 )
        v6 = 16;
    }
  LABEL_35:
    if ( v7 )
    {
      v15 = sub_1400377C0(a1, a2, &v9);
      if ( v15 != 0 )
        return v15;
      sub_140036ED0(a2, v9);
      if ( *(_BYTE *)(a2 + 829) == 5 )
      {
        if ( *(_BYTE *)(a2 + 822) == 1 )
          v16 = 8;
        else
          v16 = 32;
        v6 = v16;
      }
    }
    if ( v6 != 0 )
    {
      v17 = sub_1400389E0(a1, a2, v6);
      if ( v17 != 0 )
        return v17;
    }
  LABEL_46:
    if ( (*a3 & 2) != 0 )
    {
      v18 = sub_1400389E0(a1, a2, (unsigned __int8)a3[*(unsigned __int8 *)(a1 + 42) + 1]);
      if ( v18 != 0 )
        return v18;
    }
    if ( (*a3 & 4) != 0 )
    {
      if ( a3[8] != 0 )
        *(_QWORD *)(a2 + 672) |= 0x80uLL;
      v19 = sub_140038B60(a1, a2, 0, (unsigned __int8)a3[*(unsigned __int8 *)(a1 + 41) + 4], a3[7], a3[8]);
      if ( v19 != 0 )
        return v19;
    }
    if ( (*a3 & 8) != 0 )
    {
      v4 = *(unsigned __int8 *)(a1 + 41);
      v5 = (unsigned __int8)a3[v4 + 9];
      LOBYTE(v4) = 1;
      v20 = sub_140038B60(a1, a2, v4, v5, a3[12], a3[13]);
      if ( v20 != 0 )
        return v20;
    }
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 19：`sub_140036DD0` —— 64 位 REX 前缀单字节拆解器 (提取 REX.W, REX.R, REX.X, REX.B)
* **地址**：`0x140036dd0`，大小 `246` 字节 (`0xf6`)
* **反编译伪代码**：
  ```c
  _BYTE *__fastcall sub_140036DD0(_BYTE *a1, __int64 a2, unsigned __int8 a3)
  {
    *(_QWORD *)(a2 + 672) |= 4uLL;
    *(_BYTE *)(a2 + 754) = 1;
    *(_BYTE *)(a2 + 755) = a3;
    *(_BYTE *)(a2 + 756) = ((int)a3 >> 3) & 1;
    *(_BYTE *)(a2 + 757) = ((int)a3 >> 2) & 1;
    *(_BYTE *)(a2 + 758) = ((int)a3 >> 1) & 1;
    *(_BYTE *)(a2 + 759) = a3 & 1;
    a1[43] = *(_BYTE *)(a2 + 756);
    a1[44] = *(_BYTE *)(a2 + 757);
    a1[45] = *(_BYTE *)(a2 + 758);
    a1[46] = *(_BYTE *)(a2 + 759);
    return a1;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 20：`sub_140036ED0` —— 原生 SIB 字段拆解例程 (提取 Scale, Index, Base)
* **地址**：`0x140036ed0`，大小 `139` 字节 (`0x8b`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140036ED0(__int64 a1, unsigned __int8 a2)
  {
    __int64 result; // rax
  
    *(_QWORD *)(a1 + 672) |= 2uLL;
    *(_BYTE *)(a1 + 825) = 1;
    *(_BYTE *)(a1 + 826) = a2;
    *(_BYTE *)(a1 + 827) = (int)a2 >> 6;
    *(_BYTE *)(a1 + 828) = ((int)a2 >> 3) & 7;
    result = a2 & 7;
    *(_BYTE *)(a1 + 829) = result;
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 21：`sub_140036F60` —— AVX VEX 前缀 (0xC5 2 字节 / 0xC4 3 字节) 完整状态机解码器
* **地址**：`0x140036f60`，大小 `936` 字节 (`0x3a8`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140036F60(_BYTE *a1, __int64 a2, _BYTE *a3)
  {
    *(_QWORD *)(a2 + 672) |= 0x10uLL;
    *(_BYTE *)(a2 + 772) = 1;
    *(_BYTE *)(a2 + 773) = *a3;
    if ( *a3 == 0xC5 )
    {
      *(_BYTE *)(a2 + 774) = a3[1];
      *(_BYTE *)(a2 + 775) = 0;
      *(_BYTE *)(a2 + 776) = (int)(unsigned __int8)a3[1] >> 7;
      *(_BYTE *)(a2 + 777) = 1;
      *(_BYTE *)(a2 + 778) = 1;
      *(_BYTE *)(a2 + 779) = 1;
      *(_BYTE *)(a2 + 780) = 0;
      *(_BYTE *)(a2 + 781) = ((int)(unsigned __int8)a3[1] >> 3) & 0xF;
      *(_BYTE *)(a2 + 782) = ((int)(unsigned __int8)a3[1] >> 2) & 1;
      *(_BYTE *)(a2 + 783) = a3[1] & 3;
    }
    else
    {
      *(_BYTE *)(a2 + 774) = a3[1];
      *(_BYTE *)(a2 + 775) = a3[2];
      *(_BYTE *)(a2 + 776) = (int)(unsigned __int8)a3[1] >> 7;
      *(_BYTE *)(a2 + 777) = ((int)(unsigned __int8)a3[1] >> 6) & 1;
      *(_BYTE *)(a2 + 778) = ((int)(unsigned __int8)a3[1] >> 5) & 1;
      *(_BYTE *)(a2 + 779) = a3[1] & 0x1F;
      *(_BYTE *)(a2 + 780) = (int)(unsigned __int8)a3[2] >> 7;
      *(_BYTE *)(a2 + 781) = ((int)(unsigned __int8)a3[2] >> 3) & 0xF;
      *(_BYTE *)(a2 + 782) = ((int)(unsigned __int8)a3[2] >> 2) & 1;
      *(_BYTE *)(a2 + 783) = a3[2] & 3;
    }
    if ( *(unsigned __int8 *)(a2 + 779) > 3u )
      return 11;
    a1[43] = *(_BYTE *)(a2 + 780);
    a1[44] = (*(_BYTE *)(a2 + 776) & 1) == 0;
    a1[45] = (*(_BYTE *)(a2 + 777) & 1) == 0;
    a1[46] = (*(_BYTE *)(a2 + 778) & 1) == 0;
    a1[47] = *(_BYTE *)(a2 + 782);
    a1[48] = *(_BYTE *)(a2 + 782);
    a1[51] = ~*(_BYTE *)(a2 + 781) & 0xF;
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 22：`sub_140037310` —— AMD XOP 扩展向量前缀 (0x8F 3 字节) 状态机解码器
* **地址**：`0x140037310`，大小 `638` 字节 (`0x27e`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140037310(_BYTE *a1, __int64 a2, __int64 a3)
  {
    *(_QWORD *)(a2 + 672) |= 8uLL;
    *(_BYTE *)(a2 + 760) = 1;
    *(_BYTE *)(a2 + 761) = -113;
    *(_BYTE *)(a2 + 762) = *(_BYTE *)(a3 + 1);
    *(_BYTE *)(a2 + 763) = *(_BYTE *)(a3 + 2);
    *(_BYTE *)(a2 + 764) = (int)*(unsigned __int8 *)(a3 + 1) >> 7;
    *(_BYTE *)(a2 + 765) = ((int)*(unsigned __int8 *)(a3 + 1) >> 6) & 1;
    *(_BYTE *)(a2 + 766) = ((int)*(unsigned __int8 *)(a3 + 1) >> 5) & 1;
    *(_BYTE *)(a2 + 767) = *(_BYTE *)(a3 + 1) & 0x1F;
    if ( *(unsigned __int8 *)(a2 + 767) < 8u || *(unsigned __int8 *)(a2 + 767) > 0xAu )
      return 11;
    *(_BYTE *)(a2 + 768) = (int)*(unsigned __int8 *)(a3 + 2) >> 7;
    *(_BYTE *)(a2 + 769) = ((int)*(unsigned __int8 *)(a3 + 2) >> 3) & 0xF;
    *(_BYTE *)(a2 + 770) = ((int)*(unsigned __int8 *)(a3 + 2) >> 2) & 1;
    *(_BYTE *)(a2 + 771) = *(_BYTE *)(a3 + 2) & 3;
    a1[43] = *(_BYTE *)(a2 + 768);
    a1[44] = (*(_BYTE *)(a2 + 764) & 1) == 0;
    a1[45] = (*(_BYTE *)(a2 + 765) & 1) == 0;
    a1[46] = (*(_BYTE *)(a2 + 766) & 1) == 0;
    a1[47] = *(_BYTE *)(a2 + 770);
    a1[48] = *(_BYTE *)(a2 + 770);
    a1[51] = ~*(_BYTE *)(a2 + 769) & 0xF;
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的核心构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 23：`sub_140037590` —— 反汇编输入流初始化与解析主入口
* **地址**：`0x140037590`，大小 `378` 字节 (`0x17a`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140037590(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
  {
    unsigned int v6; // [rsp+20h] [rbp-68h]
    unsigned int v7; // [rsp+24h] [rbp-64h]
    _QWORD v8[3]; // [rsp+30h] [rbp-58h] BYREF
    char v9; // [rsp+48h] [rbp-40h]
    char v10; // [rsp+49h] [rbp-3Fh]
    _BYTE v11[21]; // [rsp+5Bh] [rbp-2Dh] BYREF
    _BYTE v12[24]; // [rsp+90h] [rbp+8h]
  
    *(_QWORD *)&v12[16] = a3;
    *(_QWORD *)&v12[8] = a2;
    *(_QWORD *)v12 = a1;
    if ( a1 == 0 || a5 == 0 )
      return 1;
    if ( a2 == 0 || a3 == 0 )
      return 4;
    sub_140037AC0(v11, 0, 10);
    qmemcpy(v8, v12, sizeof(v8));
    v9 = 0;
    v10 = 0;
    sub_140037AC0(a5, 0, 896);
    *(_BYTE *)a5 = **(_BYTE **)v12;
    *(_BYTE *)(a5 + 23) = *(_BYTE *)(*(_QWORD *)v12 + 1LL);
    *(_BYTE *)(a5 + 20) = 1;
    *(_QWORD *)(a5 + 680) = a4;
    v6 = sub_1400338E0((__int64)v8, a5);
    if ( v6 != 0 )
      return v6;
    v7 = sub_1400342B0(v8, a5);
    if ( v7 != 0 )
      return v7;
    else
      return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 24：`sub_140037710` —— 架构执行模式配置例程 (16/32/64 位长模式切换)
* **地址**：`0x140037710`，大小 `170` 字节 (`0xaa`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140037710(unsigned __int8 *a1, unsigned __int8 a2, unsigned __int8 a3)
  {
    if ( a1 == nullptr || a2 == 0 || a2 > 6u )
      return 1;
    if ( a2 == 1 )
    {
      if ( a3 != 64 )
        return 1;
    }
    else if ( a3 != 16 && a3 != 32 )
    {
      return 1;
    }
    *a1 = a2;
    a1[1] = a3;
    sub_140037A50(a1 + 2, &unk_140059518, 8);
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 25：`sub_1400377C0` —— 指令流单字节提取与 15 字节上限越界保护
* **地址**：`0x1400377c0`，大小 `177` 字节 (`0xb1`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400377C0(__int64 a1, __int64 a2, _BYTE *a3)
  {
    if ( *(unsigned __int8 *)(a2 + 4) >= 0xFu )
      return 6;
    if ( *(_QWORD *)(a1 + 16) == 0 )
      return 4;
    *a3 = *(_BYTE *)(*(_QWORD *)(a1 + 8))++;
    *(_BYTE *)(a2 + (unsigned __int8)(*(_BYTE *)(a2 + 4))++ + 5) = *a3;
    --*(_QWORD *)(a1 + 16);
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 26：`sub_140037880` —— 多字节批量提取器 (立即数与多字节位移解析)
* **地址**：`0x140037880`，大小 `235` 字节 (`0xeb`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140037880(__int64 a1, __int64 a2, __int64 a3, unsigned __int8 a4)
  {
    if ( a4 + (unsigned int)*(unsigned __int8 *)(a2 + 4) > 0xF )
      return 6;
    if ( *(_QWORD *)(a1 + 16) < (unsigned __int64)a4 )
      return 4;
    sub_140037A50(a2 + *(unsigned __int8 *)(a2 + 4) + 5, *(_QWORD *)(a1 + 8), a4);
    *(_BYTE *)(a2 + 4) += a4;
    sub_140037A50(a3, *(_QWORD *)(a1 + 8), a4);
    *(_QWORD *)(a1 + 8) += a4;
    *(_QWORD *)(a1 + 16) -= a4;
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 27：`sub_140037970` —— 指令流当前字节预取 (Peek Byte)
* **地址**：`0x140037970`，大小 `87` 字节 (`0x57`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140037970(__int64 a1, __int64 a2, _BYTE *a3)
  {
    if ( *(unsigned __int8 *)(a2 + 4) >= 0xFu )
      return 6;
    if ( *(_QWORD *)(a1 + 16) == 0 )
      return 4;
    *a3 = **(_BYTE **)(a1 + 8);
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 28：`sub_1400379D0` —— 指令流当前字节消费与游标推进 (Consume Byte)
* **地址**：`0x1400379d0`，大小 `113` 字节 (`0x71`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400379D0(__int64 a1, __int64 a2)
  {
    __int64 result; // rax
  
    *(_BYTE *)(a2 + (unsigned __int8)(*(_BYTE *)(a2 + 4))++ + 5) = *(_BYTE *)(*(_QWORD *)(a1 + 8))++;
    result = *(_QWORD *)(a1 + 16) - 1LL;
    *(_QWORD *)(a1 + 16) = result;
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 29：`sub_1400380A0` —— 巨型操作码分发与语义归约调度器 (1,696 字节)
* **地址**：`0x1400380a0`，大小 `1696` 字节 (`0x6a0`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_1400380A0(_BYTE *a1, __int64 a2, _WORD *a3)
  {
    unsigned int v4; // eax
    char v5; // [rsp+20h] [rbp-68h] BYREF
    char v6; // [rsp+21h] [rbp-67h] BYREF
    unsigned __int8 v7; // [rsp+22h] [rbp-66h]
    char v8; // [rsp+23h] [rbp-65h]
    char v9; // [rsp+24h] [rbp-64h] BYREF
    _BYTE v10[3]; // [rsp+25h] [rbp-63h] BYREF
    char v11; // [rsp+28h] [rbp-60h] BYREF
    _BYTE v12[3]; // [rsp+29h] [rbp-5Fh] BYREF
    unsigned __int8 v13; // [rsp+2Ch] [rbp-5Ch]
    char v14; // [rsp+30h] [rbp-58h]
    char v15; // [rsp+34h] [rbp-54h]
    char v16; // [rsp+38h] [rbp-50h]
    char v17; // [rsp+3Ch] [rbp-4Ch]
    unsigned int v18; // [rsp+40h] [rbp-48h]
    int v19; // [rsp+44h] [rbp-44h]
    unsigned int v20; // [rsp+48h] [rbp-40h]
    unsigned int v21; // [rsp+4Ch] [rbp-3Ch]
    unsigned int v22; // [rsp+50h] [rbp-38h]
    unsigned int v23; // [rsp+54h] [rbp-34h]
    unsigned int v24; // [rsp+58h] [rbp-30h]
    int v25; // [rsp+5Ch] [rbp-2Ch]
    unsigned int v26; // [rsp+60h] [rbp-28h]
    unsigned int v27; // [rsp+64h] [rbp-24h]
    unsigned int v28; // [rsp+68h] [rbp-20h]
    unsigned int v29; // [rsp+6Ch] [rbp-1Ch]
    unsigned int v30; // [rsp+70h] [rbp-18h]
    unsigned int v31; // [rsp+74h] [rbp-14h]
  
    v17 = *(_BYTE *)(a2 + 20);
    if ( v17 == 1 )
    {
      v18 = sub_1400377C0((__int64)a1, a2, (_BYTE *)(a2 + 22));
      if ( v18 != 0 )
        return v18;
      v19 = *(unsigned __int8 *)(a2 + 21);
      switch ( v19 )
      {
        case 0:
          v13 = *(_BYTE *)(a2 + 22);
          switch ( v13 )
          {
            case 0xFu:
              *(_BYTE *)(a2 + 21) = 1;
              goto LABEL_75;
            case 0x62u:
              goto LABEL_14;
            case 0x8F:
              v28 = sub_140037970((__int64)a1, a2, v10);
              if ( v28 != 0 )
                return v28;
              if ( (v10[0] & 0x1Fu) >= 8 )
              {
                if ( (*(_QWORD *)(a2 + 672) & 4LL) != 0 )
                  return 10;
                if ( *(_BYTE *)(a2 + 743) != 0 )
                  return 8;
                if ( a1[25] != 0 )
                  return 9;
                v11 = -113;
                v12[0] = 0;
                v12[1] = 0;
                v29 = sub_140037880((__int64)a1, a2, (__int64)v12, 2u);
                if ( v29 != 0 )
                  return v29;
                *(_BYTE *)(a2 + 20) = 3;
                v30 = sub_140037310(a1, a2, (__int64)&v11);
                if ( v30 != 0 )
                  return v30;
                *(_BYTE *)(a2 + 21) = *(_BYTE *)(a2 + 767) - 3;
              }
              break;
            default:
              if ( v13 > 0xC3u && v13 <= 0xC5u )
              {
  LABEL_14:
                v20 = sub_140037970((__int64)a1, a2, &v9);
                if ( v20 != 0 )
                  return v20;
                if ( (v9 & 0xF0u) >= 0xC0 || **(_BYTE **)a1 == 1 )
                {
                  if ( (*(_QWORD *)(a2 + 672) & 4LL) != 0 )
                    return 10;
                  if ( *(_BYTE *)(a2 + 743) != 0 )
                    return 8;
                  if ( a1[25] != 0 )
                    return 9;
                  v5 = 0;
                  v6 = 0;
                  v7 = 0;
                  v8 = 0;
                  v5 = *(_BYTE *)(a2 + 22);
                  v14 = *(_BYTE *)(a2 + 22);
                  if ( v14 == 98 )
                  {
                    v23 = sub_140037880((__int64)a1, a2, (__int64)&v6, 3u);
                    if ( v23 != 0 )
                      return v23;
                  }
                  else if ( v14 == -59 )
                  {
                    v22 = sub_1400377C0((__int64)a1, a2, &v6);
                    if ( v22 != 0 )
                      return v22;
                  }
                  else
                  {
                    v21 = sub_140037880((__int64)a1, a2, (__int64)&v6, 2u);
                    if ( v21 != 0 )
                      return v21;
                  }
                  v15 = *(_BYTE *)(a2 + 22);
                  if ( v15 == 98 )
                  {
                    v25 = ((int)v7 >> 2) & 1;
                    if ( v25 != 0 )
                    {
                      *(_BYTE *)(a2 + 20) = 5;
                      v27 = sub_140033E30((__int64)a1, a2, &v5);
                      if ( v27 != 0 )
                        return v27;
                      *(_BYTE *)(a2 + 21) = *(_BYTE *)(a2 + 793);
                    }
                    else
                    {
                      if ( **(_BYTE **)a1 != 1 )
                        return 5;
                      *(_BYTE *)(a2 + 20) = 6;
                      v26 = sub_140034B90(a1, a2, &v5);
                      if ( v26 != 0 )
                        return v26;
                      *(_BYTE *)(a2 + 21) = *(_BYTE *)(a2 + 812);
                    }
                  }
                  else
                  {
                    *(_BYTE *)(a2 + 20) = 4;
                    v24 = sub_140036F60(a1, a2, &v5);
                    if ( v24 != 0 )
                      return v24;
                    *(_BYTE *)(a2 + 21) = *(_BYTE *)(a2 + 779);
                  }
                }
              }
              break;
          }
          break;
        case 1:
          v16 = *(_BYTE *)(a2 + 22);
          switch ( v16 )
          {
            case 15:
              if ( *(_BYTE *)(a2 + 743) != 0 )
                return 8;
              *(_BYTE *)(a2 + 20) = 2;
              *(_BYTE *)(a2 + 21) = 4;
              break;
            case 56:
              *(_BYTE *)(a2 + 21) = 2;
              break;
            case 58:
              *(_BYTE *)(a2 + 21) = 3;
              break;
            default:
              break;
          }
          break;
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
          break;
      }
    }
    else
    {
      if ( v17 == 2 )
      {
        *a3 = 12;
        return 0;
      }
      v4 = sub_1400377C0((__int64)a1, a2, (_BYTE *)(a2 + 22));
      v31 = v4;
      if ( v4 != 0 )
        return v31;
    }
  LABEL_75:
    *a3 = *(unsigned __int8 *)(a2 + 22);
    return 0;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 30：`sub_140038E00` —— 多层操作码分支语法树匹配中枢 (3,272 字节)
* **地址**：`0x140038e00`，大小 `3272` 字节 (`0xcc8`)
* **反编译伪代码**：
  ```c
  char __fastcall sub_140038E00(_BYTE *a1, __int64 a2, _BYTE *a3)
  {
    __int16 v3; // ax
    unsigned __int8 v5; // [rsp+0h] [rbp-78h]
    unsigned __int8 v6; // [rsp+1h] [rbp-77h]
    unsigned __int8 v7; // [rsp+2h] [rbp-76h]
    unsigned __int8 v8; // [rsp+3h] [rbp-75h]
    unsigned __int8 v9; // [rsp+4h] [rbp-74h]
    char v10; // [rsp+8h] [rbp-70h]
    unsigned __int8 v11; // [rsp+20h] [rbp-58h]
    char v12; // [rsp+24h] [rbp-54h]
    char v13; // [rsp+28h] [rbp-50h]
  
    LOBYTE(v3) = *(_BYTE *)(a2 + 20);
    switch ( (_BYTE)v3 )
    {
      case 3:
        v3 = word_140059520[(unsigned __int8)a1[48]];
        *(_WORD *)(a2 + 710) = v3;
        return v3;
      case 4:
        *(_WORD *)(a2 + 710) = word_140059524[(unsigned __int8)a1[48]];
        LOBYTE(v3) = a3[12] >> 5;
        if ( (_BYTE)v3 != 0 )
        {
          *(_BYTE *)(a2 + 715) = 1;
          LOBYTE(v3) = byte_1400A19F8[a3[12] >> 5];
          *(_BYTE *)(a2 + 716) = v3;
        }
        break;
      case 5:
        v5 = a1[48];
        if ( ((a3[12] >> 5) & 3) != 0 )
          v5 = ((a3[12] >> 5) & 3) - 1;
        *(_WORD *)(a2 + 710) = word_140059528[v5];
        a1[53] = a3[13] & 0xF;
        if ( (a3[13] & 0xF) != 0 )
        {
          a1[54] = byte_140059530[(a3[13] >> 4) & 7];
          switch ( a3[13] & 0xF )
          {
            case 1:
              v7 = *(_BYTE *)(a2 + 800);
              v8 = a1[43];
              a1[56] = byte_140059538[6 * v7 + 3 * v8 + v5];
              *(_BYTE *)(a2 + 716) = byte_140059548[6 * v7 + 3 * v8 + v5];
              break;
            case 2:
              v9 = *(_BYTE *)(a2 + 800);
              a1[56] = byte_140059554[3 * v9 + v5];
              *(_BYTE *)(a2 + 716) = byte_14005955C[3 * v9 + v5];
              break;
            case 3:
              a1[56] = byte_140059564[v5];
              break;
            case 4:
            case 7:
              a1[56] = byte_140059568[(a3[13] >> 4) & 7];
              break;
            case 5:
              if ( a1[54] == 64 )
                a1[56] = 8;
              else
                a1[56] = 4;
              break;
            case 6:
              a1[56] = 16;
              break;
            case 8:
              if ( a1[43] == 1 )
                a1[56] = 16;
              else
                a1[56] = 8;
              break;
            case 9:
              if ( a1[43] == 1 )
                a1[56] = 32;
              else
                a1[56] = 16;
              break;
            case 0xA:
              a1[56] = 32;
              break;
            case 0xB:
              a1[56] = byte_140059570[v5];
              break;
            case 0xC:
              a1[56] = byte_140059574[v5];
              break;
            case 0xD:
              a1[56] = byte_140059578[v5];
              break;
            case 0xE:
              a1[56] = 16;
              break;
            case 0xF:
              a1[56] = byte_14005957C[v5];
              break;
          }
        }
        if ( (a3[15] & 0xF) != 0 )
        {
          *(_BYTE *)(a2 + 715) = 1;
          *(_BYTE *)(a2 + 716) = byte_140059580[a3[15] & 0xF];
        }
        if ( *(_BYTE *)(a2 + 800) != 0 )
        {
          v11 = a3[14] & 3;
          if ( v11 > 1u )
          {
            if ( v11 == 2 )
              *(_BYTE *)(a2 + 717) = a1[48] + 1;
            *(_BYTE *)(a2 + 720) = 1;
          }
        }
        *(_BYTE *)(a2 + 712) = *(_BYTE *)(a2 + 797) + 1;
        *(_BYTE *)(a2 + 713) = *(_BYTE *)(a2 + 802) - 19;
        LOBYTE(v3) = (a3[14] & 0x20) != 0;
        *(_BYTE *)(a2 + 714) = v3;
        break;
      case 6:
        *(_WORD *)(a2 + 710) = 512;
        v6 = a3[13] >> 7;
        if ( (char)a3[13] < 0 || (a3[14] & 7) == 0 )
          goto LABEL_54;
        *(_BYTE *)(a2 + 715) = 1;
        v12 = a3[14] & 7;
        if ( v12 != 1 )
        {
          switch ( v12 )
          {
            case 2:
              *(_BYTE *)(a2 + 716) = 4;
              v6 = 1;
              goto LABEL_54;
            case 3:
              *(_BYTE *)(a2 + 716) = 10;
              v6 = 2;
              goto LABEL_54;
            case 4:
              *(_BYTE *)(a2 + 716) = 11;
              v6 = 2;
              goto LABEL_54;
            default:
              break;
          }
        }
        *(_BYTE *)(a2 + 716) = 3;
        v6 = 1;
  LABEL_54:
        switch ( byte_1400399E4[a3[13] & 0x1F] )
        {
          case 0:
            break;
          case 1:
            a1[56] = 64;
            break;
          case 2:
            a1[56] = byte_140059590[8 * v6 + *(unsigned __int8 *)(a2 + 817)];
            break;
          case 3:
            a1[56] = asc_1400595C0[3 * v6 + *(unsigned __int8 *)(a2 + 817)];
            break;
          case 4:
            a1[56] = byte_1400595A8[8 * v6 + *(unsigned __int8 *)(a2 + 817)];
            break;
          case 5:
            a1[56] = asc_1400595D0[8 * v6 + *(unsigned __int8 *)(a2 + 817)];
            break;
          case 6:
            a1[56] = byte_1400595E0[v6 + *(unsigned __int8 *)(a2 + 817)];
            break;
        }
        a1[55] = a3[13] & 0x1F;
        switch ( a3[13] & 0x1F )
        {
          case 0:
          case 1:
          case 4:
          case 5:
          case 6:
          case 7:
          case 0x13:
          case 0x15:
          case 0x17:
          case 0x19:
            break;
          case 2:
            *(_BYTE *)(a2 + 717) = *(_BYTE *)(a2 + 817) + 1;
            break;
          case 3:
            if ( *(unsigned __int8 *)(a2 + 817) >= 4u )
              *(_BYTE *)(a2 + 720) = 1;
            break;
          case 8:
          case 9:
            *(_BYTE *)(a2 + 718) = *(_BYTE *)(a2 + 817) + 1;
            break;
          case 0xA:
          case 0xB:
          case 0xC:
            switch ( *(_BYTE *)(a2 + 817) )
            {
              case 0:
                goto LABEL_111;
              case 1:
                *(_BYTE *)(a2 + 716) = 4;
                break;
              case 2:
                *(_BYTE *)(a2 + 716) = 11;
                break;
              case 3:
                *(_BYTE *)(a2 + 719) = 1;
                break;
              case 4:
                *(_BYTE *)(a2 + 719) = 3;
                break;
              case 5:
                *(_BYTE *)(a2 + 719) = 2;
                break;
              case 6:
                *(_BYTE *)(a2 + 719) = 5;
                break;
              case 7:
                *(_BYTE *)(a2 + 719) = 4;
                break;
            }
            break;
          case 0xD:
          case 0x11:
            v13 = *(_BYTE *)(a2 + 817);
            if ( v13 != 0 )
            {
              if ( v13 == 1 )
              {
                *(_BYTE *)(a2 + 716) = 3;
              }
              else if ( v13 == 2 )
              {
                *(_BYTE *)(a2 + 716) = 10;
              }
            }
            break;
          case 0xE:
          case 0xF:
          case 0x10:
            switch ( *(_BYTE *)(a2 + 817) )
            {
              case 0:
              case 3:
                goto LABEL_111;
              case 1:
                *(_BYTE *)(a2 + 716) = 4;
                break;
              case 2:
                *(_BYTE *)(a2 + 716) = 11;
                break;
              case 4:
                *(_BYTE *)(a2 + 719) = 3;
                break;
              case 5:
                *(_BYTE *)(a2 + 719) = 2;
                break;
              case 6:
                *(_BYTE *)(a2 + 719) = 5;
                break;
              case 7:
                *(_BYTE *)(a2 + 719) = 4;
                break;
            }
            break;
          case 0x12:
          case 0x16:
            switch ( *(_BYTE *)(a2 + 817) )
            {
              case 0:
              case 1:
              case 2:
                goto LABEL_111;
              case 3:
                *(_BYTE *)(a2 + 719) = 1;
                break;
              case 4:
                *(_BYTE *)(a2 + 719) = 3;
                break;
              case 5:
                *(_BYTE *)(a2 + 719) = 2;
                break;
              case 6:
                *(_BYTE *)(a2 + 719) = 5;
                break;
              case 7:
                *(_BYTE *)(a2 + 719) = 4;
                break;
            }
            break;
          case 0x14:
          case 0x18:
            v10 = *(_BYTE *)(a2 + 817);
            if ( v10 != 0 )
            {
              switch ( v10 )
              {
                case 4:
                  *(_BYTE *)(a2 + 719) = 3;
                  break;
                case 5:
                  *(_BYTE *)(a2 + 719) = 2;
                  break;
                case 6:
                  *(_BYTE *)(a2 + 719) = 5;
                  break;
                case 7:
                  *(_BYTE *)(a2 + 719) = 4;
                  break;
                default:
                  break;
              }
            }
            break;
          default:
            abort();
        }
  LABEL_111:
        if ( *(_BYTE *)(a2 + 822) != 3 && *(_BYTE *)(a2 + 816) != 0 )
          *(_BYTE *)(a2 + 721) = 1;
        *(_BYTE *)(a2 + 712) = 1;
        LOBYTE(v3) = *(_BYTE *)(a2 + 819) - 19;
        *(_BYTE *)(a2 + 713) = v3;
        return v3;
      default:
        return v3;
    }
    return v3;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 31：`sub_140039B20` —— 单双字节操作码动态扩展表匹配器 (2,072 字节)
* **地址**：`0x140039b20`，大小 `2072` 字节 (`0x818`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_140039B20(unsigned __int8 *a1, __int64 a2, __int64 a3)
  {
    __int64 result; // rax
    unsigned __int8 v4; // [rsp+8h] [rbp-20h]
    unsigned __int8 v5; // [rsp+Ch] [rbp-1Ch]
    unsigned __int8 v6; // [rsp+10h] [rbp-18h]
  
    v4 = *(_BYTE *)(a2 + 20);
    if ( v4 == 1 || v4 > 6u )
    {
      if ( (*(_BYTE *)(a3 + 12) & 1) != 0 )
        *(_QWORD *)(a2 + 672) |= 0x100uLL;
      if ( (*(_BYTE *)(a3 + 12) & 2) != 0 )
        *(_QWORD *)(a2 + 672) |= 0x1000000000uLL;
      if ( (*(_BYTE *)(a3 + 12) & 4) != 0 )
      {
        *(_QWORD *)(a2 + 672) |= 0x200uLL;
        if ( *(_BYTE *)(a2 + 743) != 0 )
          *(_QWORD *)(a2 + 672) |= 0x80000uLL;
      }
      if ( (*(_BYTE *)(a3 + 12) & 8) != 0 )
        *(_QWORD *)(a2 + 672) |= 0x400uLL;
      if ( (*(_BYTE *)(a3 + 12) & 0x10) != 0 )
        *(_QWORD *)(a2 + 672) |= 0x800uLL;
      if ( (*(_BYTE *)(a3 + 12) & 0x20) != 0 )
        *(_QWORD *)(a2 + 672) |= 0x1000uLL;
      if ( (*(_BYTE *)(a3 + 12) & 0x40) != 0 )
        *(_QWORD *)(a2 + 672) |= 0x2000uLL;
      if ( *(char *)(a3 + 12) < 0 )
        *(_QWORD *)(a2 + 672) |= 0x4000uLL;
      if ( (*(_BYTE *)(a3 + 13) & 1) != 0 )
        *(_QWORD *)(a2 + 672) |= 0x8000uLL;
      if ( (*(_BYTE *)(a3 + 13) & 2) != 0 )
        *(_QWORD *)(a2 + 672) |= 0x10000uLL;
      v5 = a1[25];
      if ( v5 == 0xF2 )
      {
        if ( (*(_QWORD *)(a2 + 672) & 0x1000LL) != 0 )
        {
          *(_QWORD *)(a2 + 672) |= 0x400000uLL;
        }
        else if ( (*(_QWORD *)(a2 + 672) & 0x4000LL) != 0
               && ((*(_QWORD *)(a2 + 672) & 0x80000LL) != 0 || (*(_BYTE *)(a3 + 13) & 2) != 0) )
        {
          *(_QWORD *)(a2 + 672) |= 0x1000000uLL;
        }
        else if ( *(_BYTE *)(*(_QWORD *)a1 + 5LL) != 0 && (*(_QWORD *)(a2 + 672) & 0x2000LL) != 0 )
        {
          *(_QWORD *)(a2 + 672) |= 0x800000uLL;
        }
      }
      else if ( v5 == 0xF3 )
      {
        if ( (*(_QWORD *)(a2 + 672) & 0x400LL) != 0 )
        {
          *(_QWORD *)(a2 + 672) |= 0x100000uLL;
        }
        else if ( (*(_QWORD *)(a2 + 672) & 0x800LL) != 0 )
        {
          *(_QWORD *)(a2 + 672) |= 0x200000uLL;
        }
        else if ( (*(_QWORD *)(a2 + 672) & 0x8000LL) != 0
               && ((*(_QWORD *)(a2 + 672) & 0x80000LL) != 0 || (*(_BYTE *)(a3 + 13) & 2) != 0) )
        {
          *(_QWORD *)(a2 + 672) |= 0x2000000uLL;
        }
      }
      if ( (*(_BYTE *)(a3 + 13) & 4) != 0 )
      {
        *(_QWORD *)(a2 + 672) |= 0x20000uLL;
        result = a1[24];
        v6 = a1[24];
        if ( v6 == 46 )
        {
          result = *(_QWORD *)(a2 + 672) | 0x4000000LL;
          *(_QWORD *)(a2 + 672) = result;
        }
        else if ( v6 == 62 )
        {
          result = *(_QWORD *)(a2 + 672) | 0x8000000LL;
          *(_QWORD *)(a2 + 672) = result;
        }
      }
      else
      {
        if ( (*(_BYTE *)(a3 + 13) & 8) != 0 )
          *(_QWORD *)(a2 + 672) |= 0x40000uLL;
        result = a1[24];
        if ( a1[24] != 0 )
        {
          result = (*(_BYTE *)(a3 + 13) & 8) != 0;
          if ( (*(_BYTE *)(a3 + 13) & 8) != 0 )
          {
            result = (unsigned __int8)byte_14003A29C[a1[24] - 38];
            switch ( a1[24] )
            {
              case '&':
                result = *(_QWORD *)(a2 + 672) | 0x80000000LL;
                *(_QWORD *)(a2 + 672) = result;
                break;
              case '\'':
              case '(':
              case ')':
              case '*':
              case '+':
              case ',':
              case '-':
              case '/':
              case '0':
              case '1':
              case '2':
              case '3':
              case '4':
              case '5':
              case '7':
              case '8':
              case '9':
              case ':':
              case ';':
              case '<':
              case '=':
              case '?':
              case '@':
              case 'A':
              case 'B':
              case 'C':
              case 'D':
              case 'E':
              case 'F':
              case 'G':
              case 'H':
              case 'I':
              case 'J':
              case 'K':
              case 'L':
              case 'M':
              case 'N':
              case 'O':
              case 'P':
              case 'Q':
              case 'R':
              case 'S':
              case 'T':
              case 'U':
              case 'V':
              case 'W':
              case 'X':
              case 'Y':
              case 'Z':
              case '[':
              case '\\':
              case ']':
              case '^':
              case '_':
              case '`':
              case 'a':
              case 'b':
              case 'c':
                return result;
              case '.':
                result = *(_QWORD *)(a2 + 672) | 0x10000000LL;
                *(_QWORD *)(a2 + 672) = result;
                break;
              case '6':
                result = *(_QWORD *)(a2 + 672) | 0x20000000LL;
                *(_QWORD *)(a2 + 672) = result;
                break;
              case '>':
                result = *(_QWORD *)(a2 + 672) | 0x40000000LL;
                *(_QWORD *)(a2 + 672) = result;
                break;
              case 'd':
                result = *(_QWORD *)(a2 + 672) | 0x100000000LL;
                *(_QWORD *)(a2 + 672) = result;
                break;
              case 'e':
                result = *(_QWORD *)(a2 + 672) | 0x200000000LL;
                *(_QWORD *)(a2 + 672) = result;
                break;
            }
          }
        }
      }
    }
    else
    {
      result = a1[24];
      if ( a1[24] != 0 )
      {
        result = (unsigned __int8)byte_14003A2F8[a1[24] - 38];
        switch ( a1[24] )
        {
          case '&':
            result = *(_QWORD *)(a2 + 672) | 0x80000000LL;
            *(_QWORD *)(a2 + 672) = result;
            break;
          case '\'':
          case '(':
          case ')':
          case '*':
          case '+':
          case ',':
          case '-':
          case '/':
          case '0':
          case '1':
          case '2':
          case '3':
          case '4':
          case '5':
          case '7':
          case '8':
          case '9':
          case ':':
          case ';':
          case '<':
          case '=':
          case '?':
          case '@':
          case 'A':
          case 'B':
          case 'C':
          case 'D':
          case 'E':
          case 'F':
          case 'G':
          case 'H':
          case 'I':
          case 'J':
          case 'K':
          case 'L':
          case 'M':
          case 'N':
          case 'O':
          case 'P':
          case 'Q':
          case 'R':
          case 'S':
          case 'T':
          case 'U':
          case 'V':
          case 'W':
          case 'X':
          case 'Y':
          case 'Z':
          case '[':
          case '\\':
          case ']':
          case '^':
          case '_':
          case '`':
          case 'a':
          case 'b':
          case 'c':
            return result;
          case '.':
            result = *(_QWORD *)(a2 + 672) | 0x10000000LL;
            *(_QWORD *)(a2 + 672) = result;
            break;
          case '6':
            result = *(_QWORD *)(a2 + 672) | 0x20000000LL;
            *(_QWORD *)(a2 + 672) = result;
            break;
          case '>':
            result = *(_QWORD *)(a2 + 672) | 0x40000000LL;
            *(_QWORD *)(a2 + 672) = result;
            break;
          case 'd':
            result = *(_QWORD *)(a2 + 672) | 0x100000000LL;
            *(_QWORD *)(a2 + 672) = result;
            break;
          case 'e':
            result = *(_QWORD *)(a2 + 672) | 0x200000000LL;
            *(_QWORD *)(a2 + 672) = result;
            break;
        }
      }
    }
    return result;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---

### 函数 32：`sub_14003A5F0` —— 指令助记符与操作数语法结构归约器 (1,568 字节)
* **地址**：`0x14003a5f0`，大小 `1568` 字节 (`0x620`)
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14003A5F0(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
  {
    int v4; // eax
    __int64 result; // rax
    unsigned __int8 v6; // [rsp+24h] [rbp-24h]
    char v7; // [rsp+28h] [rbp-20h]
    unsigned __int8 v8; // [rsp+2Ch] [rbp-1Ch]
    __int16 v9; // [rsp+34h] [rbp-14h]
  
    v7 = *(_BYTE *)(a3 + 1);
    if ( v7 == 1 )
    {
  LABEL_5:
      if ( *(_WORD *)(a4 + 2LL * *(unsigned __int8 *)(a1 + 41) + 2) != 0 )
      {
        *(_WORD *)(a3 + 6) = 8 * *(_WORD *)(a4 + 2LL * *(unsigned __int8 *)(a1 + 41) + 2);
      }
      else
      {
        if ( **(_BYTE **)a1 == 1 )
          v9 = sub_140032C50(*(_BYTE *)(a3 + 14));
        else
          v9 = sub_140032B70(*(_BYTE *)(a3 + 14));
        *(_WORD *)(a3 + 6) = v9;
      }
      *(_BYTE *)(a3 + 8) = 3;
      *(_WORD *)(a3 + 10) = *(_WORD *)(a3 + 6);
      goto LABEL_52;
    }
    if ( v7 != 2 )
    {
      if ( v7 == 3 )
      {
        *(_WORD *)(a3 + 6) = *(unsigned __int8 *)(a2 + 888) + *(unsigned __int8 *)(a2 + 864);
        goto LABEL_52;
      }
      if ( v7 == 4 )
      {
        *(_WORD *)(a3 + 6) = 8 * *(_WORD *)(a4 + 2LL * *(unsigned __int8 *)(a1 + 41) + 2);
        goto LABEL_52;
      }
      goto LABEL_5;
    }
    v8 = *(_BYTE *)(a2 + 20);
    if ( v8 > 4u )
    {
      if ( v8 == 5 )
      {
        if ( *(_WORD *)(a4 + 2LL * *(unsigned __int8 *)(a1 + 41) + 2) != 0 )
        {
          *(_WORD *)(a3 + 6) = 8 * *(_WORD *)(a4 + 2LL * *(unsigned __int8 *)(a1 + 41) + 2);
        }
        else if ( *(_BYTE *)(a1 + 53) == 2 )
        {
          if ( *(_BYTE *)(a2 + 716) != 0 )
            LOWORD(v4) = *(unsigned __int8 *)(a1 + 54);
          else
            v4 = (int)*(unsigned __int16 *)(a2 + 710) >> 1;
          *(_WORD *)(a3 + 6) = v4;
        }
        else if ( *(_BYTE *)(a2 + 716) != 0 )
        {
          *(_WORD *)(a3 + 6) = *(unsigned __int8 *)(a1 + 54);
        }
        else
        {
          *(_WORD *)(a3 + 6) = *(_WORD *)(a2 + 710);
        }
        goto LABEL_52;
      }
      if ( v8 == 6 )
      {
        if ( *(_WORD *)(a4 + 2LL * *(unsigned __int8 *)(a1 + 41) + 2) != 0 )
        {
          *(_WORD *)(a3 + 6) = 8 * *(_WORD *)(a4 + 2LL * *(unsigned __int8 *)(a1 + 41) + 2);
        }
        else
        {
          switch ( *(_BYTE *)(a2 + 719) )
          {
            case 0:
              *(_WORD *)(a3 + 6) = 512;
              switch ( *(_BYTE *)(a1 + 55) )
              {
                case 0xA:
                case 0xC:
                case 0x12:
                case 0x16:
                  *(_BYTE *)(a3 + 8) = 5;
                  *(_WORD *)(a3 + 10) = 32;
                  break;
                case 0xB:
                  *(_WORD *)(a3 + 6) = 256;
                  *(_BYTE *)(a3 + 8) = 5;
                  *(_WORD *)(a3 + 10) = 32;
                  break;
                case 0xD:
                case 0x13:
                case 0x17:
                  *(_BYTE *)(a3 + 8) = 6;
                  *(_WORD *)(a3 + 10) = 64;
                  break;
                case 0xE:
                case 0x10:
                case 0x14:
                case 0x18:
                  *(_BYTE *)(a3 + 8) = 3;
                  *(_WORD *)(a3 + 10) = 32;
                  break;
                case 0xF:
                  *(_WORD *)(a3 + 6) = 256;
                  *(_BYTE *)(a3 + 8) = 3;
                  *(_WORD *)(a3 + 10) = 32;
                  break;
                case 0x11:
                case 0x15:
                case 0x19:
                  *(_BYTE *)(a3 + 8) = 3;
                  *(_WORD *)(a3 + 10) = 64;
                  break;
              }
              break;
            case 1:
              *(_WORD *)(a3 + 6) = 256;
              *(_BYTE *)(a3 + 8) = 4;
              *(_WORD *)(a3 + 10) = 16;
              break;
            case 2:
              *(_WORD *)(a3 + 6) = 128;
              *(_BYTE *)(a3 + 8) = 3;
              *(_WORD *)(a3 + 10) = 8;
              break;
            case 3:
              *(_WORD *)(a3 + 6) = 128;
              *(_BYTE *)(a3 + 8) = 2;
              *(_WORD *)(a3 + 10) = 8;
              break;
            case 4:
              *(_WORD *)(a3 + 6) = 256;
              *(_BYTE *)(a3 + 8) = 3;
              *(_WORD *)(a3 + 10) = 16;
              break;
            case 5:
              *(_WORD *)(a3 + 6) = 256;
              *(_BYTE *)(a3 + 8) = 2;
              *(_WORD *)(a3 + 10) = 16;
              break;
          }
          v6 = *(_BYTE *)(a2 + 716);
          if ( v6 != 0 )
          {
            if ( v6 <= 4u )
            {
              *(_WORD *)(a3 + 6) = *(_WORD *)(a3 + 10);
            }
            else if ( v6 <= 0xBu )
            {
              *(_WORD *)(a3 + 6) = 4 * *(_WORD *)(a3 + 10);
            }
          }
        }
  LABEL_52:
        if ( (*(_BYTE *)(a4 + 8) & 0x1F) != 0 && (*(_BYTE *)(a4 + 8) & 0x1F) != 1 )
        {
          sub_14003B140(*(_BYTE *)(a4 + 8) & 0x1F, a3 + 8, a3 + 10);
          if ( *(_WORD *)(a3 + 10) == 0 )
            *(_WORD *)(a3 + 10) = *(_WORD *)(a3 + 6);
        }
        *(_WORD *)(a3 + 12) = 1;
        result = *(unsigned __int16 *)(a3 + 10);
        if ( *(_WORD *)(a3 + 10) != 0 )
        {
          result = *(unsigned __int16 *)(a3 + 6);
          if ( *(_WORD *)(a3 + 6) != 0 )
          {
            result = *(unsigned __int16 *)(a3 + 6) / (int)*(unsigned __int16 *)(a3 + 10);
            *(_WORD *)(a3 + 12) = result;
          }
        }
        return result;
      }
    }
    if ( *(_BYTE *)(a3 + 16) == 2 )
    {
      *(_WORD *)(a3 + 6) = *(unsigned __int8 *)(a2 + 25);
      *(_BYTE *)(a3 + 8) = 3;
    }
    else
    {
      *(_WORD *)(a3 + 6) = 8 * *(_WORD *)(a4 + 2LL * *(unsigned __int8 *)(a1 + 41) + 2);
    }
    goto LABEL_52;
  }
  
  ```
* **对抗意义与引擎机理**：该函数是 ACE 内核微型反汇编器的关键调度/流式提取构件，为驱动在内核特权级直接分析系统指令流、提取操作数属性与计算指令边界提供支持。

---


---


---

---

## 4. 全量子系统 17 个核心反作弊函数反编译聚类与合并归纳

经 IDA Hex-Rays 反编译微码分析，本子系统负责内核特权级指令解析与 Hook 检测的 17 个底层反作弊函数，可高度合并归纳为 **4 大核心功能簇**。重复的序列化与清理例程已实现逻辑合并提炼：

```
                 ┌────────────────────────────────────────────────────────┐
                 │  微型反汇编引擎 17 个反作弊核心函数拓扑合流架构          │
                 └──────────────────────────┬─────────────────────────────┘
                                            │
         ┌──────────────────┬───────────────┴───────────────┬──────────────────┐
         ▼                  ▼                               ▼                  ▼
 【功能簇 A: 操作码分发】 【功能簇 B: 描述符序列化打包】  【功能簇 C: 状态机清理】 【功能簇 D: Hook跳板与自检】
   sub_140032B50 (2.2KB)    sub_140033C60 / sub_140033EE0   sub_140033D00          sub_140033450 (REX.W模板)
   (40+跳转表核心分发)     sub_140038F40 (20B 报文合并)    sub_140033F70          sub_140038210 (1.0KB自检)
                           sub_140033D40 (24B 报文合并)    sub_140036F20          sub_1400338D0 (驱动调度)
                           sub_140036DB0 (32B 报文合并)    sub_140032AB0
                           sub_140033DC0 / sub_140038FE0
```

---

### 功能簇 A：反汇编器核心操作码分发调度器（Opcode Semantic Dispatcher）
* **涉及核心函数**：`sub_140032B50`（大小：**2289 字节**）
* **核心机理**：
  该函数是整个微型反汇编器的**主操作码语义分发大表**。它接收前缀解码后的操作码字节流，维护了一张庞大的函数指针跳转表（调用了 40 余个底层解码例程 `sub_14002Exxx` ~ `sub_140032xxx`）。
* **关键反编译伪代码抽象**：
  ```c
  __int64 __fastcall sub_140032B50(unsigned int OpcodeGroup, __int64 InsnCtx, unsigned int PrefixFlags, __int64 OutDesc, unsigned int MaxLen)
  {
    // 多路操作码族分发矩阵
    switch ( OpcodeGroup )
    {
      case 0x0F: // 两字节转义前缀扩展 (0x0F 38 / 0x0F 3A)
        return sub_140031A80(InsnCtx, OutDesc);
      case 0x80: case 0x81: case 0x83: // 算术逻辑运算立即数指令 (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP)
        return sub_140030D20(InsnCtx, OutDesc, PrefixFlags);
      case 0xC6: case 0xC7: // MOV 立即数到内存/寄存器
        return sub_14002FB60(InsnCtx, OutDesc);
      case 0xFF: // 间接绝对跳转/调用 (JMP/CALL/PUSH ModR/M 组)
        return sub_140032020(InsnCtx, OutDesc);
      default:
        // 索引全局 256 项 Native 指令语义表分发
        return g_OpcodeHandlerTable[OpcodeGroup](InsnCtx, OutDesc);
    }
  }
  ```

---

### 功能簇 B：指令描述符序列化打包例程簇（重复功能合并归纳）
* **涉及函数（9 个同质化例程合并）**：
  - **20 字节描述符打包器**：`sub_140033C60`、`sub_140033EE0`、`sub_140038F40`
  - **24 字节扩展描述符打包器**：`sub_140033D40`
  - **32 字节完整向量描述符打包器**：`sub_140036DB0`
  - **复合寻址解码打包器**：`sub_140033DC0`、`sub_140038FE0`、`sub_140036E50`、`sub_140038C10`
* **重复功能统一提炼**：
  反汇编引擎在完成指令解码后，必须向调用方（如 Hook 检测器、调用栈回溯器）返回统一格式的定长描述报文。这组函数逻辑高度一致：校验输出缓冲区指针与请求尺寸（20/24/32 字节），执行 `memset` 清零，并将解析出的指令有效长度、操作数属性、寻址基址、变址比例（SIB Scale）与立即数写入结构体。
* **统合后的核心逆向伪代码原型**：
  ```c
  // 统合结构体: ACE 标准指令分析描述报文
  struct ACE_INSN_PACKET {
      uint32_t InsnLength;     // 指令总长度 (1~15 字节)
      uint16_t PrefixFlags;    // 前缀标志 (LOCK/REP/REX/VEX)
      uint8_t  ModRM;          // ModR/M 原始字节
      uint8_t  OpcodeClass;    // 指令类别 (Branch/Memory/ALU)
      uint64_t Displacement;   // 内存寻址偏移量
      uint32_t Immediate;      // 立即数值
  };

  __int64 __fastcall Pack_Insn_Descriptor(__int64 InsnCtx, _DWORD *OutBuffer, int ExpectedPacketSize)
  {
    if ( !OutBuffer || ExpectedPacketSize < 20 )
      return STATUS_INVALID_PARAMETER;
    
    memset(OutBuffer, 0, ExpectedPacketSize);
    OutBuffer[0] = GetDecodedLength(InsnCtx);
    OutBuffer[1] = GetOperandAttributes(InsnCtx);
    if ( ExpectedPacketSize >= 24 )
      *(_QWORD *)&OutBuffer[2] = GetMemoryDisplacement(InsnCtx);
    if ( ExpectedPacketSize >= 32 )
      OutBuffer[6] = GetImmediateValue(InsnCtx);
    return STATUS_SUCCESS;
  }
  ```

---

### 功能簇 C：状态机重置与上下文清理存根簇（重复功能合并归纳）
* **涉及函数（4 个同质化例程合并）**：
  `sub_140033D00`、`sub_140033F70`、`sub_140036F20`、`sub_140032AB0`
* **重复功能统一提炼**：
  反汇编解码在跨指令边界或解析发生异常故障（如遇到非法操作码 #UD）时，通过这组微型存根直接定位到上下文偏移结构（`Ctx + 32`、`Ctx + 36`、`Ctx + 86`），执行自旋重置并清空临时解码缓冲，防止前序指令的残余状态污染后续指令的长度测算。
* **合并抽象**：
  ```c
  void __fastcall Disasm_Reset_Context(__int64 Ctx, int CleanMode)
  {
    if ( CleanMode == 0 )
      sub_1400345B0(Ctx);             // 全量重置指令状态机
    else if ( CleanMode == 1 )
      sub_140036A40(Ctx + 32);        // 单独释放向量前缀状态
    else
      sub_140038910(*(DWORD *)(Ctx + 32), Ctx + 36, Ctx + 86); // 刷新操作数槽位
  }
  ```

---

### 功能簇 D：Inline Hook 跳板模板与指令流巡检校验引擎
* **涉及核心函数**：
  - `sub_140033450`（大小：`346 字节`）：**x64 REX.W 跳板模板生成与对比例程**
  - `sub_140038210`（大小：`1087 字节`）：**全驱动指令解码器自检与 Hook 巡检主循环**
  - `sub_1400338D0`（大小：`270 字节`）：**内核调度接口指令流完整性审计**
* **深度对抗机理剖析**：
  1. **跳板模板特征匹配 (`sub_140033450`)**：
     函数内部直接内置了 56 字节的硬编码二进制特征序列：
     `v3[0] = 0x48; v3[1] = 0x89; v3[2] = 0x...;`（即标准 x64 `MOV [RSP+...], RAX; JMP ...` 14 字节绝对跳转跳板模板）。该函数通过逐字节对拍，快速检测目标系统函数入口是否被作弊软件篡改为了外挂的 Trampoline。
  2. **自检巡检引擎 (`sub_140038210`)**：
     驱动在启动或周期性触发反作弊巡检时，调用 `sub_140038210` 对内核自身 `.text` 段以及关键系统导出函数进行指令遍历。利用自研微型反汇编器动态测算每条指令长度，核验是否有被 `0xE9` (JMP rel32)、`0xCC` (INT 3) 或 `0xFF 0x25` (JMP [RIP+0]) 截断的非法 Hook。
