# ADR-0047: 游戏主线程窗口子类化无痕封包拦截与主动发包架构规范

- **状态**: 已采纳
- **日期**: 2026-10-20
- **核心领域**: 游戏封包截获 / 逆向工程 / 反作弊对抗 / 纯静态类架构

---

## 上下文与痛点

1. **Themida 代码完整性校验红线**：
   `MapleStory.exe` 代码段（`.text`）与只读数据段（`.rdata`）受 Themida 虚拟机周期性哈希与 CRC 强校验，严禁直接写入 `E9` / `FF 25` Inline Hook 或硬件断点（DR0-DR7），否则会瞬间触发非法模块崩溃或封号。
2. **密文拼包与明文瞬时释放**：
   游戏接收包时，`ClientSocket + 0xB0` 存放的 `m_packetRecv` 始终为密文；当拼包完成调用原生 `DecryptData` 后，游戏立即调用 `ProcessPacket` 并调用 `~CInPacket` 释放明文，外部无法在事后被动扫描获取明文。
3. **跨线程并发发包断线**：
   `ClientSocket->m_lpSendBuff` (`+0x88`) 与 `m_uSeqSnd` (`+0xE8`) 缺失互斥锁保护，跨线程直接调用 `SendPacket` 会造成序列号乱序导致断线。

---

## 技术决策与规范

1. **纯静态类架构与零成本抽象**：
   在驱动端实现纯静态类 `MapleSubclassThunk` 与 `MapleRuntime`，0 虚函数（无 vtable 审计特征）、0 动态实例、0 单行垫片。
2. **原生 WndProc 前导中继挂接与 `OnRead` 接管收包**：
   - 痛点规避：Win10 1607+ 用户态桌面堆（Desktop Heap）去指针化且受保护，用户态不存在包含原生 `lpfnWndProc` 的可写槽位；
   - 核心决策：精确锁定原生主窗口过程 `WndProc`（RVA: `0x02CEAA90`）；在原生入口植入 12 字节前导中继跳转（`mov rax, ThunkBase; jmp rax`），完整覆盖前 7 个 push 寄存器指令，不多不少整 12 字节；
   - 透传分支：非目标消息在 Thunk 中补齐执行该 7 个 push 指令后直接跳回 `WndProc + 12`（即 `sub rsp, 0E0h`），保持原生栈帧与寄存器 100% 恒等；
   - 拦截 `uMsg == 0x0401` (`WM_USER + 1`) 且 `LOWORD(lParam) == 1` (`FD_READ`)：传参 `edx = 0` 调用原生 `OnRead(pSocket, 0)` 将分片收入 `m_lpRecvBuff` (`+0x70`)；
   - 在子类化例程中复刻 `ManipulatePacket` 循环：调用 `AppendBuffer`，并在 `DecryptData` 返回瞬时提取明文写入无锁环形队列（`RingBuffer[128]`），随后调用 `InnoHash` 步进序号并提交 `ProcessPacket`。
3. **`m_sock` 闸门滞留发送队列与主线程安全发包**：
   - 置 `m_sock = 0` 阻断 `Flush`，截获 `m_lpSendBuff` 中的外发包；
   - 通过自定义消息 `WM_USER + 0x777` 切换到游戏主线程栈，在主线程自身上下文调用 `COutPacket` 构造并发送，确保 100% 线程安全。
4. **.text 原生代码洞（Code Cave）分区与纯指令入口解耦**：
   - 严禁将代码注入 `.rdata`（PAGE_READONLY 会触发 DEP 0xC0000005 崩溃）；
   - 实测绑定 `.text` 尾部 `0x1432DD690 ~ 0x1432DE000`（RVA: `0x032DD690`）的 2,416 字节页面对齐纯零空洞；
   - **纯指令首字节入口**：严禁在 Thunk 执行首地址前混入数据指针（前置 8 字节数据指针会导致 CPU 将指针数值当成操作码执行，触发非法指令崩溃 `#UD / 0xC000001D`）；首字节必须为第一条汇编指令，并通过 `mov r15, Imm64` 动态装入数据区绝对地址；
   - **物理分区与防覆盖边界**：代码区限制 384 字节（`0x032DD690 ~ 0x032DD810`），数据区为 2,032 字节（`0x032DD810 ~ 0x032DE000`）；精简 Shellcode 尺寸（约 250 字节，预留 130+ 字节安全冗余），绝对禁止溢出覆盖数据区；
   - **双向真实跨进程交互**：`Initialize` 必须显式通过 `MapleMemory::WriteBuffer` 将驱动配置的函数表与上下文写入目标进程共享区；`PopCapturedPacket` 必须通过 `MapleMemory::ReadBuffer` 实时消费目标进程内的环形队列；
   - 卸载时必须成对执行物理内存全零覆写，彻底消除代码注入残留痕迹。

---

## 已知约束与避坑

1. **严禁在驱动后台开启高频定时器或工作项轮询**：
   收发包截获完全基于 Windows 消息泵（`FD_READ` 与消息分发）被动触发，零驱动轮询开销。
2. **结构体对齐与单槽契约**：
   跨环/共享内存结构体必须显式声明 `#pragma pack(push, 8)`；受限于 2,032 字节数据区容积，RingBuffer 容量设为 1 槽，Payload 设为 1,792 字节（结构体 1,944 字节，严格位于 2,032 字节上限内）。
3. **快路径零开销透传设计**：
   非 0x401 且非 0x777 消息在入口 3 条指令直接尾调用透传原生 WndProc，零栈分配与零寄存器破坏，杜绝消息泵吞吐性能衰减。

