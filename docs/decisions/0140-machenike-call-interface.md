# ADR-0140: Machenike CallUser/CallKernel 接口接入 ResidentPayload
- **状态**: 已采纳
- **日期**: 2026-10-30
- **上下文与痛点**: 旧 `hv::Call`/`hv::CallK` 位于备份 GameCommon，不属于 Machenike 当前驱动编译图；重命名后的调用能力需要落到 `Stealth::VtEngine`，并复用已有伪造 Guest 堆栈与跨 VCPU 返回恢复路径。
- **技术决策与规范**: Machenike 暴露 `VtEngine::CallUser` 与 `VtEngine::CallKernel` 模板接口，同时提供 `CallUserRaw`/`CallKernelRaw` 数组接口；两者通过 `VT_HC_DBG_DISPATCH` 的 `0x7000/0x7001` 子命令进入 ResidentPayload。调用请求和返回使用 `vt_call_abi.h` 的 `#pragma pack(push, 8)`、固定宽度字段、最多 12 个 `ULONG64` 参数；用户态目标使用用户返回桩，内核态目标使用内核返回桩，Guest 栈按原有按页读写路径保存和恢复。
- **已知约束与避坑**: 只有 ResidentPayload 已驻留、目标地址为规范地址且模式与地址高半区匹配时才执行；调用失败通过固定状态码返回；不得恢复 `Call`/`CallK` 旧别名；结构体不得加入裸指针、`size_t` 或未对齐字段；修改后必须同步重建 Machenike 与 ResidentPayload，并通过回滚验证。
