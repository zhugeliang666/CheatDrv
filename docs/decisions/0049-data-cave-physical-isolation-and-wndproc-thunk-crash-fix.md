# ADR-0049: Data Cave 读写区物理隔离与 WndProc Thunk 崩溃根除

- **状态**: 已采纳
- **日期**: 2026-10-20
- **上下文与痛点**:
  在部署 MapleStory 游戏封包收割与主线程调度 Thunk 时，驱动挂接原生 `WndProc` 后目标游戏进程瞬间崩溃退出。逆向与动态调试确证三大根因：
  1. **写保护缺页致命异常 (`#PF` -> `0xC0000005`)**: 驱动原先将共享数据结构 `g_SharedThunk`（包含 RingBuffer 及各类计数器）放置在 `CodeCaveSharedDataRva` (`0x032DD810`)，该地址位于主模块 `.text` 代码节（只读执行，`PAGE_EXECUTE_READ`）。当游戏收到高频网络消息 `0x401` 时，用户态 R3 线程执行 `mov [rdi], 1` 写入 RingBuffer，硬件 MMU 立即触发写保护缺页异常，引发无未决异常处理的 Access Violation 崩溃；
  2. **x64 ABI 栈对齐违规与局部栈越界踩踏**: 原 Shellcode 内部栈分配未遵循 16 字节边界对齐，且未提供 32 字节 Shadow Space；`COutPacket` 栈对象尺寸实际超过 1100 字节，原汇编仅分配 72 字节栈直接导致局部变量将保存的 `rbx, rsi, rdi, r15` 彻底覆写踩踏，函数返回恢复非法指针；
  3. **双重网络处理冲突**: 原 Shellcode 拦截 `0x401` 并在内部重复调用 `AppendBuffer` 等例程，与原生游戏 `OnRead(1)` 形成状态冲突。

- **技术决策与规范**:
  1. **代码区与数据区物理硬隔离 (Shellcode Engineering Rule 8.2)**:
     - **纯代码执行区**: 动态定位至 `.text` 节区纯零空洞（原生 `PAGE_EXECUTE_READ`，仅放纯汇编机器码）；
     - **纯数据读写区**: 彻底迁出 `.text` 节，动态定位至 `.data` 节区连续纯零空洞（原生 `PAGE_READWRITE`）；
     - `g_SharedThunk`（包含 RingBuffer、统计指针、静态发包对象 `StaticOutPacket`）全量驻留于 `.data` 空洞，彻底消灭 R3 写保护崩溃。
  2. **自适应 PE 节区逆向空洞探测引擎 (Adaptive Reverse Zero-Scan Engine)**:
     - 彻底废除写死硬编码空洞 RVA，改为通过 `MapleMemory::FindAdaptiveCodeCave` 和 `FindAdaptiveDataCave` 动态解算；
     - 驱动动态解析目标主模块的 `IMAGE_DOS_HEADER` 与 `IMAGE_NT_HEADERS64` 遍历节区头（Section Headers）；
     - 针对代码节（`MEM_EXECUTE | MEM_READ` 且非 `MEM_WRITE`）与数据节（`MEM_READ | MEM_WRITE` 且非 `MEM_EXECUTE`），采用反向回溯分块扫描（Reverse Scan）自节区末尾对齐边界（`SectionAlignment` 补零区）向前推进，几微秒内快速命中连续纯零对齐空洞；
     - 双重安全防线：若 PE 头遭篡改解析受阻，自动回退至已确证的保底基线并探针校验全零状态；
     - 生命周期原子清理：退出时严格根据探测记录的真实基址与尺寸执行动态物理清零，不留任何痕迹。
  3. **WndProc 零侵入极简消息透传**:
     - 彻底删除在 WndProc 里拦截 `0x401` 的脆弱逻辑；所有普通消息及原生 `0x401` 网络事件 100% 走 passthrough 补齐 7 个 push 后尾调用原入口 `pfnOrigWndProc + 12`；
     - WndProc 仅响应自定义 `0x777` 主线程发包调度，严格执行 16 字节栈对齐与 Shadow Space 规范。
  4. **发包收割双闭环**:
     - 驱动后台工作项轮询在收割 RingBuffer 的同时自动调用 `DrainSendQueue()`，从 `ClientSocket + 0x88` 收割发包明文并输出调试日志。

- **已知约束与避坑**:
  - 严禁将任何可写缓冲区、RingBuffer 放置在 `.text` 等只读节区；
  - 卸载清理时必须成对物理清零 `CodeCave` 与 `DataCave`，彻底抹除无驱动残留痕迹。
