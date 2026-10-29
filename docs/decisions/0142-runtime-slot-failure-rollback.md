# ADR-0142: RuntimeSlot 初始化失败的驱动侧轮询与 Hook 回滚

- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: Notepad 调试 Shellcode 在 `RuntimeInitWithInput(&slot->value, NULL)` 失败时以原子写入将 `RuntimeSlot::state` 置为 `3`。原驱动只在卸载阶段清理，无法在运行期间及时识别失败并恢复入口 Hook、Shellcode 双视图和目标进程页。
- **技术决策与规范**: 驱动在既有 PASSIVE_LEVEL 系统工作项中轮询目标进程数据页 `dataBase + 0x10` 的 `LONG state`；读取到 `3` 后调用唯一的 `CleanupNotepadNptTest()` 路径。该路径先恢复原始 Hook，再移除 Shellcode 视图，释放目标代码/数据页，解除进程引用并将状态归零；不新增内核线程，不在 VM-Exit 快路径执行清理。
- **已知约束与避坑**: `RuntimeSlot` 的 `value/input/state` 布局必须保持 `0x00/0x08/0x10`；读取必须使用目标 CR3 的受控虚拟内存原语并校验地址回绕；状态读取失败不等同于初始化失败，保留到后续轮询或统一卸载处理；不得直接删除无关进程的其他 Hook。
