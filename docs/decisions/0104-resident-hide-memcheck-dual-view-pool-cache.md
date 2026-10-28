# ADR-0104: Resident 隐藏验证分页、双视图语义与 Pool 快照缓存
- **状态**: 已采纳
- **日期**: 2026-10-28
- **上下文与痛点**: AMD handoff 在释放 VtHypervisor 映像后仍通过 PoolManager 链表读取常驻池块，导致 `count=50/valid=0`；memcheck 单次最多检查 1024 页，Arena 完整范围无法一次完成；Payload `.text` 双视图保留执行原页，旧验证却要求 `visible_pages==0`，把 42 个合法执行页判为失败。
- **技术决策与规范**: 接管 PoolManager 块时在 Bootstrap 侧保存有效记录快照，释放旧映像后优先使用该快照；DROPCTL 验证使用游标循环直到 `done=1` 并汇总所有分页计数；新增 `MAPCTL_MEMCHECK_FLAG_ALLOW_IMAGE_DUAL_VIEW`，仅允许 IMAGE 范围的可见页，且可见页数必须等于已安装的 Payload `.text` 双视图页数，DIRECT、Arena、Host Stack、Pool 范围仍要求全部隐藏。
- **已知约束与避坑**: 双视图允许的是执行侧 PFN 可见，不代表普通读取可见；不能放宽非 IMAGE 范围。Pool 快照必须在 `adopt_pool_blocks` 成功后发布，并在复制完成后执行内存屏障；memcheck 分页遇到不前进的游标必须终止并计入 `verify_fail`。修改后必须同批重建 ResidentPayload、VtHypervisor 与 Bootstrap 并重新嵌入映像。
