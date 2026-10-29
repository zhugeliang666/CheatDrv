# ADR-0138: hv::Call/CallK 伪造堆栈跨页与返回值安全加固

- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: `hv::Call` 与 `hv::CallK` 通过改写 Guest `RSP/RIP` 保留伪造堆栈调用能力，但原实现把 `gva2hva()` 返回的单页 HVA 当作连续 `0x400` 字节使用，并使用裸 `ULONG64` 强转读写参数；Guest 栈跨页、无效 VPID/目标地址、浮点返回和栈恢复失败时可能形成空指针访问、非法栈写入或错误返回值。
- **技术决策与规范**: 保留现有伪造堆栈与 `RET -> 0xCC -> #BP -> vt_call_exit` 返回链；`Call/CallK` 的栈快照与恢复统一使用 `read_guest_virtual_memory`/`write_guest_virtual_memory` 按页处理；参数通过 `memcpy` 打包为单个 64 位 ABI 槽位；入口校验 VPID、vCPU 数量、目标地址规范性、栈算术和返回陷阱地址；`float` 返回值从捕获的 `XMM0.Low` 读取；补全 `vt_call_entry/exit` 的 `void` 声明。
- **已知约束与避坑**: 该接口仍限定为 Windows x64 单槽、平凡可复制参数；伪造栈必须在 Guest CR3 下完整读写成功后才切换 Guest `RSP/RIP`；恢复失败必须在恢复 Guest `RSP/RIP`、上下文、亲和性和节点生命周期后返回失败；不得恢复在 VM-exit 高频路径中递归调用 `CallK(DbgPrintEx)` 的日志方案；本次只改 `Call/CallK`，其他历史 `Call2/Call3/Call4` 不属于本接口准入路径。
