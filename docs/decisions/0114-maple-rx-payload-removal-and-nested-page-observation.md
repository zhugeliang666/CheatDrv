# ADR-0114: MapleRxPayload 映射链移除与 NPT/EPT 只读页事件观测统一
- **状态**: 已采纳
- **日期**: 2026-10-29
- **上下文与痛点**: 原 MapleStory 路径包含独立映像节、RW 共享节、目标进程扫描、User APC、窗口过程替换以及收发包主动读写。该链路与 VT 页事件层耦合，生命周期复杂，卸载和并发异常时难以证明无悬垂引用。
- **技术决策与规范**:
  1. 从 Machenike 工程和解决方案移除 Maple 映射/注入源文件与 `MapleRxPayload` 子工程；兼容源文件只保留返回 `STATUS_NOT_SUPPORTED` 的无副作用桩，不再创建映像、节、APC、窗口子类或目标写入。
  2. 新增 `NestedPageInstrumentation`，统一 AMD NPT 与 Intel EPT 的页违例事件格式。事件固定 64 字节，写入只使用原子游标和静态非分页环，不分配池、不阻塞、不访问 Guest 指针。
  3. 事件环默认关闭，只有诊断控制面显式 Arm 才记录；停止虚拟化前先撤销 Arm 并清空环。页违例观测不等同于封包边界，协议解析必须在自有测试目标的应用日志/测试代理层完成。
- **已知约束与避坑**:
  - VM-Exit 快路径不得执行分页遍历、复杂协议解析、等待或网络 I/O。
  - 不得恢复 SEC_IMAGE、共享节、User APC、GWLP_WNDPROC、第三方目标进程扫描/写入、发包或重放路径。
  - 新增字段必须保持独立的诊断 ABI；修改控制面前同步更新 Loader/Bootstrap/ResidentPayload 并执行布局检查。
