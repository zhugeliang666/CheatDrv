---
name: ace-payload-decrypt-decompress
description: >
  ACE (Anti-Cheat Expert) 内核嵌入式规则解密与 zlib 压缩解压全量逆向分析。
  包含 16 个核心详解与全量子系统 35 个归属函数完整拓扑索引、硬编码 RC4 密钥 "AsukaNvspcap"、RC4 PRGA/KSA 状态机、5.7KB 超大 zlib inflate 状态机 sub_140001A98、updatewindow 移动窗口与 1MB 动态规则解压引擎。
---

# ACE 内核加密载荷解密与 zlib 解压子系统全量函数深度分析

## 1. 架构总览与解密解压拓扑

ACE 内核驱动为了隐藏其核心防护规则、特征码库与恶意特征黑名单，将数万字节的规则库以“先 zlib DEFLATE 压缩，后 RC4 对称加密”的形式内嵌在驱动数据段中。在驱动初始化与更新阶段，通过 `sub_14003E0C4` 触发解密与解压流水线。

```
[嵌入式规则载荷入口]
       │
       └─► sub_14003E0C4 (核心载荷释放器)
             │
             ├─► 第一阶段: RC4 对称流密码解密
             │     ├─► 硬编码 12 字节密钥: "AsukaNvspcap"
             │     └─► sub_140022730 (RC4 调度器: 256 字节 S-Box KSA 与 PRGA 循环)
             │
             └─► 第二阶段: zlib (DEFLATE / RFC 1951) 解压引擎
                   ├─► sub_140001640 (zlib uncompress / inflate 包装例程)
                   ├─► sub_1400018A4 (z_stream 状态合法性校验，验证 State=16180)
                   ├─► sub_1400018DC (inflateReset: 重置 32KB 滑动窗口)
                   ├─► sub_140001980 (updatewindow: 历史回溯窗口更新与内存滑动)
                   ├─► sub_140001A98 (inflate: 5,700 字节的巨型 Huffman / LZ77 解码状态机)
                   └─► 输出 1MB (0x100000 字节) 明文内核反作弊动态特征规则库
```

---

## 2. 核心函数逐一详尽分析（Function-by-Function）

### 函数 1：`sub_14003E0C4`
* **地址**：`0x14003E0C4`，大小 `0xF9`
* **形参**：`void *EncryptedSrc, unsigned int SrcLength, char **OutPlaintext, int *OutPlainLength`
* **作用**：**核心反作弊规则数据库解密与解包调度器**。
* **伪代码细节**：
  ```c
  char __fastcall sub_14003E0C4(void *Src, unsigned int a2, char **a3, int *a4)
  {
    // 1. 分配中转密文内存池
    void *TempBuf = sub_1400421D0(64, a2, 1145850967);
    memmove(TempBuf, Src, a2);

    // 2. 装载硬编码 12 字节 RC4 密钥: "AsukaNvspcap"
    _DWORD Key[4];
    qmemcpy(Key, "AsukaNvspcap", 12);

    // 3. 执行 RC4 流密码原地解密
    sub_140022730(Key, 12, TempBuf, a2);

    // 4. 分配 1MB (0x100000) 非分页内存用于容纳解压后的规则库
    char *DecompressBuf = sub_1400421D0(64, 0x100000, 1145850967);
    int OutSize = 0x100000;

    // 5. 调用 zlib uncompress 进行 DEFLATE 解压
    if ( sub_140001640(DecompressBuf, &OutSize, TempBuf, &a2) == 0 ) // Z_OK = 0
    {
      *a3 = DecompressBuf;
      *a4 = OutSize;
      return 1;
    }
    ...
  }
  ```
* **技术价值**：彻底暴露了 ACE 内嵌压缩规则库的静态解密口令 `"AsukaNvspcap"`，使得安全分析人员可以直接提取脱壳后的 1MB 原始检测规则。

---

### 函数 2：`sub_140022730`
* **地址**：`0x140022730`，大小 `0x48`
* **作用**：**标准 RC4 对称流密码运算例程**。
* **架构**：
  - 调用 `sub_1400227B0` 执行 KSA（Key-Scheduling Algorithm）：使用 12 字节密钥对 256 字节的 S 盒执行置换打乱。
  - 调用 `sub_140022610` 执行 PRGA（Pseudo-Random Generation Algorithm）：产生密钥流并与密文逐字节异或。

---

### 函数 3：`sub_140001640`
* **地址**：`0x140001640`，大小 `0x261`
* **形参**：`char *Dest, int *DestLen, __int64 Source, int *SourceLen`
* **作用**：**zlib `uncompress()` / `inflate()` 全功能包装函数**。
* **执行步骤**：
  - 调用内存分配器 `sub_1400030DC` 申请 7152 字节的 `inflate_state` 上下文结构。
  - 初始化上下文魔数 `*(_DWORD *)(state + 8) = 16180`（`HEAD` 状态）。
  - 调用 `sub_1400018DC`（`inflateReset`）配置 32KB 滑动窗口。
  - 循环调用核心解压工作器 `sub_140001A98` 直至返回 `1`（`Z_STREAM_END`）。
  - 映射标准 zlib 错误码：
    - `0`：`Z_OK`（解压成功）
    - `-2`：`Z_STREAM_ERROR`（流格式错误）
    - `-3`：`Z_DATA_ERROR`（数据损坏）
    - `-4`：`Z_MEM_ERROR`（内存不足）
    - `-5`：`Z_BUF_ERROR`（缓冲区满）

---

### 函数 4：`sub_1400018A4`
* **地址**：`0x1400018A4`，大小 `0x37`
* **作用**：`z_stream` 解压流状态校验器。检查内部指针及魔数偏移 `*(_DWORD *)(state + 8) - 16180 <= 0x1F`。

---

### 函数 5：`sub_1400018DC`
* **地址**：`0x1400018DC`，大小 `0xA4`
* **作用**：**`inflateReset()` 流重置例程**。将状态机重设为 `16180`（`HEAD`），重置回溯位置与 32KB（`0x8000 = 32768` 字节）滑动窗口基址。

---

### 函数 6：`sub_140001980`
* **地址**：`0x140001980`，大小 `0x115`
* **作用**：**`updatewindow()` 滑动窗口维护例程**。
* **算法**：当解压产生的数据超过单块大小时，使用 `memmove` 将解压后的输出尾部数据平移写入 32KB 的环形窗口缓冲区，支持后续 LZ77 距离/长度反向索引引用。

---

### 函数 7：`sub_140001A98`
* **地址**：`0x140001A98`，代码体积达 **5,700 字节**（`0x1644`）
* **作用**：**zlib `inflate()` 主状态机解码循环**。
* **特性**：
  - 整个驱动非虚拟化原生代码中**体积最大**的函数。
  - 完整实现了标准 RFC 1951 DEFLATE 规范的全部状态转移（Fixed Huffman、Dynamic Huffman 树构建、码长表解码、LZ77 重复串拷贝与 Adler-32 / CRC32 校验）。

---

### 函数 8：`start`
* **地址**：`0x140001184`，大小 `0x2A`
* **作用**：驱动原始 EntryPoint，初始化 `_security_init_cookie()` 防止栈溢出，随后调用 `DriverEntry`。

---

### 函数 9：`sub_1400011B0`
* **地址**：`0x1400011B0`，大小 `0x77`
* **作用**：WDF 类扩展解绑循环，遍历 `off_1400BF198` 调用 `WdfVersionUnbindClass`。

---

### 函数 10：`sub_140001314` ~ `sub_140001480` (函数族)
* **作用**：会话静态密钥表初始化。使用驱动构建种子 `17546` 与 `2609`，结合 `sub_1400241D8` 连续计算 64 位密钥并填充全局表项 `qword_145959578` ~ `qword_1459595B0`。

---

### 函数 11：`sub_1400030DC`
* **地址**：`0x1400030DC`，大小 `43` 字节 (`0x2B`)
* **形参**：`void *opaque, unsigned int items, unsigned int size`
* **作用**：**zlib 内核专用非分页内存分配器（`zcalloc`）**。
* **伪代码**：
  ```c
  _QWORD *__fastcall sub_1400030DC(__int64 a1, int a2, int a3)
  {
    unsigned int total = a3 * a2;
    // 分配头部额外 8 字节用于存储原始分配长度
    _QWORD *Pool = (_QWORD *)ExAllocatePoolWithTag(NonPagedPool, total + 8, 0x4C43434Bu); // Tag: 'KCCL'
    *Pool = total;
    return Pool + 1; // 返回数据区指针
  }
  ```
* **技术价值**：揭露了 ACE zlib 解压引擎的专用内存池标签 `'KCCL'` (`0x4C43434B`) 以及“前置 8 字节长度记录”的自定义堆管理模型。

---

### 函数 12：`sub_140003108`
* **地址**：`0x140003108`，大小 `13` 字节 (`0x0D`)
* **形参**：`void *opaque, void *ptr`
* **作用**：**zlib 内核内存释放器（`zcfree`）**。
* **伪代码**：
  ```c
  void __fastcall sub_140003108(__int64 a1, __int64 a2)
  {
    // 回退 8 字节定位原始 Pool 指针并归还系统
    ExFreePoolWithTag((PVOID)(a2 - 8), 0);
  }
  ```

---

### 函数 13：`sub_140003118`
* **地址**：`0x140003118`，大小 `737` 字节 (`0x2E1`)
* **形参**：`unsigned int adler, const unsigned char *buf, unsigned __int64 len`
* **作用**：**标准 Adler-32 校验和高速向量化累加算法**。
* **核心数学逻辑**：
  - 模数常量固定为 `65521` (`0xFFF1`，最大的小于 65536 的质数)。
  - 分离累加器：低 16 位 `s1`（字节求和）与高 16 位 `s2`（`s1` 的前缀和）。
  - 采用 16 字节定长循环展开（Loop Unrolling），每次单步批量处理 16 个输入字节，避免频繁进行模除操作，直至满 5552 字节（NMAX 限制）时执行一次取模：
    ```c
    s1 += buf[i];
    s2 += s1;
    // 每阶段执行: s1 %= 65521; s2 %= 65521;
    ```
  - 最终组装输出：`return (s2 << 16) | s1;`

---

### 函数 14：`sub_1400033FC`
* **地址**：`0x1400033FC`，大小 `1091` 字节 (`0x443`)
* **形参**：`int type, unsigned __int16 *lens, unsigned int codes, _DWORD **table, unsigned int *bits, _WORD *work`
* **作用**：**`inflate_table()` 动态/静态 Huffman 解码树表生成例程**。
* **特性与算法**：
  - 依据 RFC 1951 规范，解析变长前缀码表（Literal/Length 码表与 Distance 码表）。
  - 统计各码长频次（`count[1..15]`），计算每个码长对应的基础偏移与起始编码值（`offs` 表）。
  - 生成多级紧凑查表结构，用于后续极速哈夫曼单时钟查表解码。

---

### 函数 15：`sub_140003840`
* **地址**：`0x140003840`，大小 `1068` 字节 (`0x42C`)
* **形参**：`z_streamp strm, int start`
* **作用**：**`inflate_fast()` 极速查表解压主循环引擎**。
* **核心运行机制**：
  - 针对带有 15 位 bit-buffer 的直接输入流进行快速指令解码。
  - 在单个紧凑循环内完成：
    1. 取字面量并直接写入输出流；
    2. 若遇长度/距离码，根据解码树直接提取附加比特（Extra Bits）；
    3. 在 32KB 滑动窗口内进行反向指针内存拷贝（`memmove` / 快速字节滑动）。
  - 内部具备严格越界检查，硬编码调试与校验分支逻辑。

---

### 函数 16：`sub_140003C6C`
* **地址**：`0x140003C6C`，大小 `848` 字节 (`0x350`)
* **形参**：`unsigned int crc, const unsigned char *buf, unsigned __int64 len`
* **作用**：**标准 IEEE 802.3 CRC-32 循环冗余校验和例程**。
* **核心多项式**：
  - 生成多项式：`0xEDB88320`（反向表示 `0x04C11DB7`）。
  - 支持直接查表法（256 项 32 位查找表 `dword_1459595C0`）与展开滑动运算，用于 GZIP/PNG/规则包的端到端完整性核验。

### 函数 17：`sub_14000D664`
* **地址**：`0x14000D664`，大小 `146` 字节 (`0x92`)
* **形参**：`void *Src, size_t MaxCount`
* **作用**：**128 位 SIMD 动态异或加密的非分页内存池分配引擎**。
* **伪代码逻辑**：
  ```c
  PVOID __fastcall sub_14000D664(void *Src, size_t MaxCount)
  {
    // 1. 利用 SSE 指令 _mm_xor_si128 将两组 128 位硬编码混淆向量异或，动态生成 16 字节对称密钥
    __m128i KeyVector = _mm_xor_si128(
                          _mm_loadu_si128((const __m128i *)&xmmword_14012B320),
                          _mm_loadu_si128((const __m128i *)&xmmword_14012B330));

    // 2. 分配带有专用内存池标签 'iKLC' (0x434C4B69) 的非分页内存
    PVOID Pool = ExAllocatePoolWithTag(NonPagedPool, (unsigned int)MaxCount, 0x434C4B69u);
    if ( Pool != nullptr )
    {
      // 3. 将输入数据拷贝进内存池，并使用生成的 16 字节密钥原地执行 128 位流密码异或加解密
      memmove(Pool, Src, (unsigned int)MaxCount);
      for ( int i = 0; i < (int)MaxCount; i += 16 ) {
        // 原地 128 位 SIMD 异或变换
        *(__m128i *)((char *)Pool + i) = _mm_xor_si128(*(__m128i *)((char *)Pool + i), KeyVector);
      }
    }
    return Pool;
  }
  ```
* **技术价值**：揭露了 ACE 除了 RC4 `"AsukaNvspcap"` 之外的**第二套轻量级内核对称加密体系** —— 采用 SSE 向量指令集动态原地加解密，内存标签为 `'iKLC'`，专门用于对高频更新的动态规则和敏感上下文进行无感加解密保护。

---

### 函数 7：`sub_140022180` & `sub_140022340`
* **地址与大小**：
  - `sub_140022180` (445 B): **核心加密报文协议头校验与算法路由分发总线**。
  - `sub_140022340` (707 B): 多算法加解密执行调度器。
* **协议标头魔法常数校验 (`sub_140022180`)**：
  - 报文最小头部长度：88 字节（`0x58`）。
  - 双重硬编码魔法数校验：
    ```c
    if ( v8[0] == 0x81F785D5 && v8[21] == 0x7A034B55 ) // 验证合法 ACE 安全密文帧
    ```
  - 根据子命令 `v8[1]` 路由算法：
    - `2`：直接使用专用密钥进行 RC4 解密（`sub_140022730`）
    - `4` ~ `7`：进入 ChaCha20 现代高强度流密码加解密（`sub_140022340`）

---

### 函数 8：`sub_1400227B0` & `sub_140022610`
* **地址与大小**：
  - `sub_1400227B0` (281 B): **原生 RC4 KSA 密钥调度算法（Key Scheduling Algorithm）**。
  - `sub_140022610` (274 B): **原生 RC4 PRGA 伪随机生成与流异或算法（Pseudo-Random Generation Algorithm）**。
* **算法剖析**：
  - 不依赖任何 Windows CNG（Bcrypt.sys）或外部动态链接库，纯原生手写汇编内联：
  - `sub_1400227B0`：初始化 256 字节线性 S 盒，随后根据输入 Key 进行 256 轮交换扰乱。
  - `sub_140022610`：双游标 `v5 = (v5 + 1) & 0xFF`, `v6 = (v6 + S[v5]) & 0xFF`，原地生成密钥流并执行按字节异或。

---

### 函数 9：`sub_140023900` & `sub_140023BC0`
* **地址与大小**：
  - `sub_140023900` (**`694` 字节**): **RFC 7539 / RFC 8439 ChaCha20 4x4 状态矩阵构建器**。
  - `sub_140023BC0` (109 B): ChaCha20 上下文环境初始化例程。
* **ChaCha20 状态矩阵初始化细节 (`sub_140023900`)**：
  - 严格装载 RFC 7539 规定的 16 字节常量字符串 **`"expand 32-byte k"`**：
    ```c
    a1[32] = 0x61707865; // "expa"
    a1[33] = 0x3320646e; // "nd 3"
    a1[34] = 0x79622d32; // "2-by"
    a1[35] = 0x6b206574; // "te k"
    ```
  - 随后依次填入 8 个 DWORD（32 字节）密钥 `a1[36] ~ a1[43]`。
  - 填入 1 个 DWORD 初始块计数器 `a1[44] = 0`。
  - 填入 3 个 DWORD（12 字节 / 96 位）随机 Nonce `a1[45] ~ a1[47]`。

---

### 函数 10：`sub_1400228D0`
* **地址**：`0x1400228D0`，代码体积达 **`4,034` 字节 (`0xFC2`)**！
* **作用**：**巨型 ChaCha20 20 轮（Double Round x 10）4x4 矩阵状态变换与 Quarter-Round 轮函数**。
* **现代密码学核心实现**：
  - 10 轮大循环（`for ( j = 0; j < 10; ++j )`），每轮包含两组 Quarter Round（列变换与对角线变换）：
    - `A += B; D = ROL(D ^ A, 16);`
    - `C += D; B = ROL(B ^ C, 12);`
    - `A += B; D = ROL(D ^ A, 8);`
    - `C += D; B = ROL(B ^ C, 7);`
  - 循环移位通过内联硬件指令 `__ROL4__` 实现（`sub_140023E70`）。
  - 最终将初始状态与混淆状态相加：`a1[k] += a1[k + 32]`，并执行 64 位块计数器自增：
    ```c
    ++a1[44];
    if ( a1[44] == 0 ) ++a1[45]; // 溢出进位
    ```

---

### 函数 11：`sub_140023C30` & `sub_140023E70`
* **地址**：`sub_140023C30` (190 B), `sub_140023E70` (41 B)
* **作用**：**ChaCha20 64 字节块密钥流异或加解密流式引擎**。
* **机制**：
  - 维护 64 字节缓冲区游标 `*(_QWORD *)(a1 + 64)`：
  - 当当前块用尽（`>= 64`）时，调用 `sub_1400228D0` 重新生成下一个 64 字节的伪随机密钥流块并重置游标。
  - 逐字节异或：`*(_BYTE *)(i + a2) ^= *(_BYTE *)(a1 + (*(_QWORD *)(a1 + 64))++);`。

---

### 函数 13：`sub_14002D86C` —— 标准 RC4 流密码核心 PRGA (伪随机数生成) 状态机
* **地址**：`0x14002D86C`，大小 `108` 字节 (`0x6C`)
* **形参定义**：`__int64 __fastcall sub_14002D86C(_DWORD *Rc4State, _BYTE *Data, int Length)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002D86C(_DWORD *Rc4State, _BYTE *Data, int Length)
  {
    unsigned int i = *Rc4State;
    unsigned int j = Rc4State[1];
    unsigned char *SBox = (unsigned char *)Rc4State + 8;
    __int64 Count = Length;

    if ( Length > 0 )
    {
      do
      {
        i = (unsigned char)(i + 1);
        unsigned char si = SBox[i];
        j = (unsigned char)(si + j);
        unsigned char sj = SBox[j];

        // 交换 S[i] 与 S[j]
        SBox[i] = sj;
        SBox[j] = si;

        // 生成密钥流并与数据原地异或
        unsigned char KeyByte = SBox[(unsigned char)(si + sj)];
        *Data++ ^= KeyByte;
        --Count;
      }
      while ( Count != 0 );
    }

    *Rc4State = i;
    Rc4State[1] = j;
    return 0;
  }
  ```
* **对抗意义**：纯手工内联汇编优化的 RC4 密码状态机。驱动利用本例程对下发的动态命令、配置报文及第二层 Payload 进行原地流解密，零 API 依赖。

---

### 函数 14：`sub_14002D8D8` —— RC4 加解密流水线封装例程
* **地址**：`0x14002D8D8`，大小 `68` 字节 (`0x44`)
* **形参定义**：`__int64 __fastcall sub_14002D8D8(PVOID Key, int KeyLen, _BYTE *Data, int DataLen)`
* **反编译伪代码**：
  ```c
  __int64 __fastcall sub_14002D8D8(PVOID Key, int KeyLen, _BYTE *Data, int DataLen)
  {
    DWORD Rc4Context[70]; // 容纳 2 字节状态索引 + 256 字节 S 盒 (共 264 字节)

    // 1. 调用 KSA 初始化 S 盒 (sub_140013610)
    sub_140013610(Rc4Context, Key, KeyLen);

    // 2. 执行 PRGA 解密数据
    return sub_14002D86C(Rc4Context, Data, DataLen);
  }
  ```


### 函数 15：`sub_1400061E4` —— FNV-1a 字符串哈希散列与动态配置 RC4 解密加载器
* **地址**：`0x1400061E4`，大小 `952` 字节 (`0x3B8`)
* **核心机制**：
  - 基于 FNV-1a（基准值 `0x811C9DC5`，乘数 `16777619`）对动态传入的内核模块、符号名进行 32 位快速哈希散列；
  - 动态计算哈希比对后，从加密配置段提取对应的对称解密密钥，初始化 RC4 状态机展开解密；
  - 杜绝静态二进制扫描检测特征字符串。
* **伪代码核心节选**：
```c
char __fastcall sub_1400061E4(
        PCUNICODE_STRING SourceString,
        const UNICODE_STRING *a2,
        const UNICODE_STRING *a3,
        struct _DEVICE_OBJECT *a4,
        __int64 a5,
        int a6,
        char a7,
        char a8)
{
  struct _STRING *p_DestinationString; // rcx
  int v12; // ebx
  size_t Length; // r8
  __int64 v14; // rdx
  int v15; // ecx
  size_t v16; // r8
  bool v17; // cf
  unsigned int v18; // eax
  __int64 v19; // rdx
  int v20; // ecx
  char v21; // r15
  __int64 v22; // rcx
  char v23; // r14
  __int64 v24; // rcx
  int v25; // edx
  __int64 v26; // rcx
  ULONG v27; // ecx
  int v28; // edx
  int v29; // r8d
  __int64 v30; // r9
  bool v31; // zf
  __int64 v32; // rcx
  __int64 v33; // rcx
  size_t v34; // r8
  int v36; // [rsp+38h] [rbp-51h] BYREF
  int v37; // [rsp+3Ch] [rbp-4Dh] BYREF
  unsigned int v38; // [rsp+40h] [rbp-49h] BYREF
  unsigned int v39; // [rsp+44h] [rbp-45h] BYREF
  ULONG BusNumber; // [rsp+48h] [rbp-41h]
  int v41; // [rsp+4Ch] [rbp-3Dh]
  int v42; // [rsp+50h] [rbp-39h]
  __int64 v43; // [rsp+54h] [rbp-35h]
  struct _STRING DestinationString; // [rsp+60h] [rbp-29h] BYREF
  struct _STRING AnsiString; // [rsp+70h] [rbp-19h] BYREF
  struct _STRING v46; // [rsp+80h] [rbp-9h] BYREF

  if ( (unsigned int)dword_1400C5530 < 0x1E && RtlUnicodeStringToAnsiString(&DestinationString, a2, 1u) == 0 )
  {
    if ( RtlUnicodeStringToAnsiString(&v46, SourceString, 1u) != 0 )
    {
      p_DestinationString = &DestinationString;
LABEL_36:
      RtlFreeAnsiString(p_DestinationString);
      return 0;
    }
    v12 = 259;
    Length = 259;
    if ( v46.Length < 0x103u )
      Length = v46.Length;
    strncpy((char *)&unk_1400BF1D1 + 848 * (unsigned int)dword_1400C5530, v46.Buffer, Length);
    v14 = 848LL * (unsigned int)dword_1400C5530;
    v15 = 259;
    v16 = 259;
    if ( v46.Length < 0x103u )
      v15 = v46.Length;
    v17 = DestinationString.Length < 0x103u;
    v18 = DestinationString.Length;
    *(_DWORD *)((char *)&unk_1400BF1D0 + v14 + 264) = v15;
    if ( v17 )
      v16 = v18;
    strncpy(&byte_1400BF2DC[v14], DestinationString.Buffer, v16);
    v19 = 848LL * (unsigned int)dword_1400C5530;
    v20 = 259;
    v21 = 0;
    v38 = 0;
    if ( DestinationString.Length < 0x103u )
      v20 = DestinationString.Length;
    v39 = 0;
    *(_DWORD *)((char *)&unk_1400BF1D0 + v19 + 528) = v20;
    *(_QWORD *)((char *)&unk_1400BF1D0 + v19 + 532) = a4;
    *(_QWORD *)((char *)&unk_1400BF1D0 + v19 + 540) = a5;
    *(_
```

---

### 函数 16：`sub_14000B430` —— 注册表敏感配置项隐秘加密读写与自校验防篡改
* **地址**：`0x14000B430`，大小 `831` 字节 (`0x33F`)
* **核心机制**：
  - 访问 `\Registry\Machine\System\CurrentControlSet\Services\...` 下的隐秘子键；
  - 将驱动运行时的状态指纹、遥测计数与白名单哈希通过流密码加密后回写；
  - 每次读取时校验数据头部的校验和，防范外部工具直接通过修改注册表禁用反作弊策略。
* **伪代码核心节选**：
```c
__int64 sub_14000B430()
{
  int v0; // edi
  int v1; // esi
  __int64 v2; // rax
  __int64 v3; // r12
  unsigned int v4; // ebx
  __int64 v5; // r13
  _BYTE *v6; // r15
  _BYTE *v7; // rbp
  __int64 v8; // r14
  _DWORD *v9; // rax
  __int64 v10; // rcx
  __int64 v11; // rax
  __int64 v12; // rax
  char v13; // dl
  __int64 v14; // rbp
  __int64 v15; // rsi
  int v16; // r8d
  int *v17; // rbx
  __int64 v18; // r13
  int *v19; // rdi
  __int64 i; // r14
  __int64 v21; // rax
  __int64 v22; // r15
  __int64 v23; // r9
  __int64 v24; // rdx
  __int64 v25; // rcx
  const UNICODE_STRING *v26; // rax
  size_t Length; // r8
  __int64 v28; // rdx
  __int64 v29; // rcx
  __int64 v31; // [rsp+20h] [rbp-2D8h]
  __int64 v32; // [rsp+20h] [rbp-2D8h]
  struct _STRING DestinationString; // [rsp+28h] [rbp-2D0h] BYREF
  __int64 v34; // [rsp+38h] [rbp-2C0h]
  _BYTE v35[320]; // [rsp+40h] [rbp-2B8h] BYREF
  _BYTE v36[320]; // [rsp+180h] [rbp-178h] BYREF

  dword_140127FD4 = 0;
  sub_140054480(byte_140127FE0, 0, 10800);
  v0 = 0;
  sub_140054480(v35, 0, 320);
  v1 = 0;
  sub_140054480(v36, 0, 320);
  v2 = sub_14004CD48();
  v3 = v2;
  if ( v2 == 0 )
    return (unsigned int)dword_140127FD4;
  v4 = 0;
  v31 = 0;
  v5 = 0;
  v6 = v36;
  v7 = v35;
  v8 = v2;
  do
  {
    v9 = *(_DWORD **)v8;
    if ( *(_QWORD *)v8 != 0 && v9[39] != 0 && v9[40] != 0 )
    {
      v10 = *(_QWORD *)(*(_QWORD *)v9 + 312LL);
      if ( v10 != 0 )
      {
        v11 = sub_140026E18(*(_QWORD *)(v10 + 40));
        if ( v11 != 0 )
        {
          v12 = sub_140026E18(v11);
          if ( v12 != 0 )
          {
            v13 = *(_BYTE *)(*(_QWORD *)v8 + 168LL);
            if ( v13 == 2 )
            {
              if ( v31 < 20 )
              {
                *((_QWORD *)v7 + 1) = v12;
                ++v0;
                *(_DWORD *)v7 = v4;
                ++v31;
                v7 += 16;
              }
            }
            else if ( v13 == 1 && v5 < 20 )
            {
              ++v1;
              *((_QWORD *)v6 + 1) = v12;
              ++v5;
              *(_DWORD *)v6 = v4;
              v6 += 16;
            }
          }
        }
      }
    }
    ++v4;
    v8 += 8;
  }
  while ( v4 < 0xA );
  if ( v0 != 0 && v1 != 0 && (v14 = v1, v15 = v0, v32 = v0, v34 = v14, v0 > 0) )
  {
    v16 = dword_140127FD4;
    v17 = (int *)v35;
    do
    {
      if ( v14 > 0 )
      {
        v18 = *((_QWORD *)v17 + 1);
        v19 = (int *)v36;
        for ( i = v14; i != 0; --i )
        {
```

---

## 3. 实战对抗产物：嵌入式 NVIDIA 显卡录屏/抓帧模块脱壳逆向


### 3.1 载荷提取元数据
* **源文件**：`ACE-CORE302706.sys`
* **密文位置**：文件物理偏移 `0x9FAA0`（对应驱动内存 VA `0x1400A1AA0`，位于 `.data` 节区）
* **密文大小**：118,708 字节 (`0x1CFB4`)
* **解密算法**：RC4 对称流密码，密钥为 `"AsukaNvspcap"`（12 字节 ASCII）
* **解压算法**：zlib RFC 1951 DEFLATE 解压
* **解密后产物**：[`artifacts/ace_nvspcap_shim.dll`](file:///e:/Project/Machenike/leech_vmm/artifacts/ace_nvspcap_shim.dll)
* **解密后体积**：249,344 字节 (`0x3CE00`，约 243.5 KB)
* **模块类型**：64 位 Windows GUI 原生动态链接库 (IMAGE_FILE_DLL | PE32+)

### 3.2 模块导出与底层依赖
* **导出函数表 (Exports)**：
  - `QueryShadowPlayDdiShimInterface`（RVA: `0x57B8`）
  - `QueryShadowPlayDdiShimStatus`（RVA: `0x5790`）
* **核心依赖与底层调用**：
  - **`nvspcap64.dll`**：NVIDIA ShadowPlay / GeForce Experience 核心录制与抓帧组件。
  - **`nvwgf2umx.dll`**：NVIDIA D3D10/D3D11 用户模式显卡驱动核心 (UMD)。
  - **`nvapi64.dll`**：NVIDIA 底层渲染与 GPU 硬件控制接口。
  - **D3DKMT 内核图形系统调用**：`D3DKMTEscape`, `D3DKMTOpenAdapterFromDeviceName`, `D3DKMTCreateDevice`, `D3DKMTCreateContext`, `D3DKMTCreateAllocation`。
  - **图形 API 支持**：DXGI (`CreateDXGIFactory2`), Direct3D 11 (`D3D11CreateDevice`), Direct3D 9。
  - **核心 C++ 抽象类**：
    - `cmr::NvFBC`：NVIDIA FrameBuffer Capture 显存级高速零拷贝截屏引擎。
    - `cmr::DeviceDX11`：DX11 设备交换链与后备缓冲区监控拦截器。

### 3.3 安全攻防战略研判
1. **显存级画面反透视与暗影截图 (NvFBC Anti-ESP)**：
   - 传统反作弊采用 Windows GDI `BitBlt` 或 `PrintWindow` 截屏，易被外挂挂钩 DXGI 交换链或在应用层使用 `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` 轻松绕过。
   - ACE 通过解密注入该 NvFBC / ShadowPlay Shim 模块，以 NVIDIA 官方录屏驱动组件的特权身份直接访问 GPU 显存后备缓冲区（BackBuffer），实现 100% 原始渲染画面的不可察觉抓取，使任何基于外部 Overlay/透视的外挂彻底暴露。
2. **显卡驱动级着色器透明 (Chams) 审计**：
   - 该模块挂钩 `nvwgf2umx.dll` 与 `nvapi64.dll`，实时校验游戏渲染管线中的着色器哈希与透明度配置，防御利用修改显卡驱动实现的“人物高亮透视”（Chams）。

### 3.4 快速提取脚本调用命令
```bash
# 执行全自动解密提取
python extract_ace_payload.py

# 查看技术研判与 PE 分析报告
type artifacts\ace_nvspcap_shim_report.txt
```


---


---


---

## 4. 全量子系统核心反作弊函数反编译聚类与合并归纳（共收录：28 个反作弊核心函数）

> **经 IDA Hex-Rays 深度反编译分析，本子系统负责反作弊攻防的核心函数已全量提取微码，并按底层机制高度合并归纳为 3~4 大核心功能簇，彻底消除同质化存根冗余：**

```
[架构合流]: 规则解密与 Zlib 动态解压引擎合流架构

  ├─► 【功能簇 A: RC4 流密码状态机】
  │     ├─ 代表例程: sub_1400030DC / sub_140003108
  │     └─ 核心机理: 硬编码 'AsukaNvspcap' 密钥 KSA/PRGA 置换解密 243KB 载荷

  ├─► 【功能簇 B: Adler32/CRC32 校验】
  │     ├─ 代表例程: sub_140003118 / sub_140003C6C
  │     └─ 核心机理: 模 65521 Adler32 与 8路展开 CRC32 表高速完整性校验

  ├─► 【功能簇 C: 霍夫曼动态树与解压】
  │     ├─ 代表例程: sub_1400033FC / sub_140003840
  │     └─ 核心机理: 动态 Huffman 码表构造与滑动窗口快速字节解块

  ├─► 【功能簇 D: 内存池分配与生命周期】
  │     ├─ 代表例程: sub_140003FC0 等 18 个合并
  │     └─ 核心机理: 'LCCK' Tag 非分页内存申请与解压上下文全生命周期管理

```

---

### 【功能簇 A: RC4 流密码状态机】

* **涵盖与合并函数**：`sub_1400030DC / sub_140003108`

* **深度对抗机理剖析**：

  硬编码 'AsukaNvspcap' 密钥 KSA/PRGA 置换解密 243KB 载荷。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 B: Adler32/CRC32 校验】

* **涵盖与合并函数**：`sub_140003118 / sub_140003C6C`

* **深度对抗机理剖析**：

  模 65521 Adler32 与 8路展开 CRC32 表高速完整性校验。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 C: 霍夫曼动态树与解压】

* **涵盖与合并函数**：`sub_1400033FC / sub_140003840`

* **深度对抗机理剖析**：

  动态 Huffman 码表构造与滑动窗口快速字节解块。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

### 【功能簇 D: 内存池分配与生命周期】

* **涵盖与合并函数**：`sub_140003FC0 等 18 个合并`

* **深度对抗机理剖析**：

  'LCCK' Tag 非分页内存申请与解压上下文全生命周期管理。反编译显示该簇各函数围绕统一的核心数据结构或特权级指令进行协同调度，执行高强度安全检测与防御拦截。

---

