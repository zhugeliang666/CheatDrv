# ADR-0079: Payload `.text` 执行原页、读取零页双视图
- **状态**: 已采纳
- **日期**: 2026-10-25
- **上下文与痛点**: AMD SVM/NPT 下把 Payload `.text` 的 PFN 直接替换为 dummy PFN 会同时改变 Guest 的指令取数与普通读取。强制重载时 CPU 从全零页取指，零字节被解码为 `add [rax], al`，在 `rax=1` 时触发 `KMODE_EXCEPTION_NOT_HANDLED (0x1E)`，故障现场落在 Payload 文本页的 dummy GPA。
- **技术决策与规范**: `VT_HIDE_PAYLOAD_IMAGE` 的 `.text` 路径改用 `hypercall_eh_install`，每个完整 `.text` 页在所有活动 CPU 上安装 EH 条目，参数 `args[0]=0` 使用 system CR3，`args[1]=page VA`，`args[2]=3` 表示 `full_zero + is_fake_page`。NPT/EPT 保持执行视图指向原始 PFN，普通 Guest 读取视图指向全零页，实现“执行原页、读取零页”。安装要求全核成功；任一 CPU 或页面失败时，立即对已安装页面执行 `hypercall_eh_remove` 回滚并报告 0。卸载顺序为先全核移除 `.text` EH 条目，再执行其余 arena/direct/pool/host-stack PFN 恢复。`.data/.rdata/.pdata/.xdata` 不进入图像双视图；arena/direct/pool 仍由各自宏独立控制。
- **已知约束与避坑**: 仅处理 PE `.text` 中完全落在节范围内的 4KB 页，首尾混合页跳过；EH 表容量不足、地址解析失败或 VMCALL 异常必须回滚，禁止部分 CPU 生效。不得把活动代码页再次送入 `hypercall_hide_pfn_list`/直接 dummy PFN 替换；该路径会复现 0x1E。卸载后必须等待所有 CPU 完成 `hypercall_eh_remove`，再释放 Payload 或清理其页表映射。
