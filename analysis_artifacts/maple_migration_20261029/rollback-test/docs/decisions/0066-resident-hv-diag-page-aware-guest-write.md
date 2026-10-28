# ADR-0066：Resident Hypervisor 诊断记录跨页写入

- 状态：已采纳
- 日期：2026-10-25
- 范围：`hypercall_get_resident_hv_diag`（AMD SVM / Intel VMX）与 Guest GVA 写入原语

## 上下文与证据

WinDbg 现场把用户堆损坏定位为 `HEAP_FAILURE_BUFFER_OVERRUN`。损坏页中的字段与
`resident_hv_diag_record` 从 `0x40` 起完全一致，且末端函数地址对应记录偏移
`0x2A0/0x2A8`。调用方记录起点位于页内 `0xFC0`，而原处理器只翻译首个 GVA 页面，
随后把固定 `0x640` 字节结构体当作连续 HVA 写入，因此越过当前物理页并覆盖相邻、
与第二个 Guest 虚拟页不相干的用户堆物理页。

## 路径比较

1. **调用方强制页对齐 scratch**：能保护当前 Bootstrap 调用点，但其他调用方仍可传入
   合法的跨页缓冲；Hypercall 服务端仍违反 GVA/HVA 映射契约。
2. **服务端逐页写 Guest GVA**：先预检完整目标区间，再按页重新翻译和复制；AMD 与
   Intel 共用同一实现，覆盖所有调用方。每个页面增加一次预检翻译，诊断 Hypercall
   的低频路径可接受。

选择路径 2。记录先在当前 vCPU 的 64 KiB Host Stack 中构造，固定占用 `0x640`
字节，不引入池分配、锁或阻塞；写回过程只执行页表翻译与 `memcpy_safe`，适用于
VM-exit 上下文。普通翻译失败在写入首字节前返回 0，Hypercall 仅在完整写入后返回
`0x640`。

## 接口契约

- 新增 `write_guest_virtual_memory(cr3, gva, buffer, size)` 及当前 Guest CR3 重载。
- `gva == nullptr`、`buffer == nullptr`、`size == 0`、地址加法回绕或任一页翻译失败时
  返回 0。
- 成功返回精确写入字节数；复制期间发生异常时返回已完成字节数，调用方不得把部分
  成功报告为完整成功。
- AMD 先使用 VMCB 的 Guest CR3，Intel 先使用 VMCS Guest CR3；两者仅在完整写入失败
  后尝试既有 `system_cr3` 兼容路径。
- `resident_hv_diag_record` ABI 保持 `0x640`，字段布局、版本号和 Hypercall 编号不变。

## 已知约束

预检与复制之间仍存在其他处理器修改共享页表的理论竞态；VM-exit 阻止当前 vCPU 的
Guest 执行，但不冻结其他 vCPU。复制阶段因此继续逐页翻译并检查异常，且服务端只把
精确 `0x640` 视为成功。若后续需要强原子快照，应引入调用方 pin/锁页契约，而不是
缓存裸 HVA。

## 回滚

恢复 `vt/VtHypervisor/vt/mm.h`、`mm.cpp`、`vt/hypercalls.cpp`、
`amd/svm-exit.cpp`、本 ADR 与索引；回滚后行为恢复为首地址单次翻译，因而只可用于
复现和二分，不可作为跨页缓冲的运行配置。

## 验证证据

- 离线回归以页内 `0xFC0` 为起点写入 `0x640` 字节，第二个 Guest 页映射到非连续
  物理页，并验证相邻物理页 canary 未改变。
- 源码门禁要求 AMD/Intel 处理器都经 `write_guest_virtual_memory` 写回，且处理器内
  不再对首个翻译所得 HVA 执行整结构体 `memset`/直接字段写入。
- `verify_vt_layout.py` 必须继续证明 `resident_hv_diag_record == 0x640`；完整 Release|x64
  构建用于验证编译和链接。构建成功不替代下一轮实机 Hypercall 与 Application Verifier
  堆检查。
