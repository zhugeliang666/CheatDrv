# ADR-0185：以太网组装竞态与 USB FIFO 失步恢复闭环

- 状态：已采纳，待真机验证
- 日期：2026-11-11
- 关联代码：Transport/eth_server.cpp、Transport/miniport_direct.cpp、Transport/usb_server.c、Transport/usb_hub.c、Transport/usb_hub.h
- 证据范围：源码静态复核；具体虚拟网卡 MAC 与桥接芯片 FIFO 残留需动态日志/硬件实测确认。

## 1. 决策

1. EthWorkerThreadRoutine 在 RecvLock 内再次校验 fProcessing，残留唤醒不得消费未收齐组装缓冲区；RpcDispatcher 已拥有协议校验错误上报权时，EthWorker 不重复上报。
2. DirectMiniport 先于 OID 包过滤器绑定。STATUS_NOT_FOUND 的单适配器不兼容结果只记 DBG，最终由 EthServer_Init 的 MkDm_IsReady() 统一判定；地址/版本/参数校验错误仍由底层立即上报。
3. 包过滤器按 0x2B -> 0x8B -> 0x0B 降级，只有最终失败才上报；失败时解绑 DirectMiniport、关闭 NDIS 绑定，不进入适配器链表。
4. Hub 模式启动/重连执行 20ms 可取消 Drain Read；读到的数据保留给同一解析器。非法外层长度或 Magic 先扫描完整合法帧锚点，恢复成功不 Flush、不上报；连续两次无法重同步才上报。

## 2. 已知约束

- Drain Read 使用专用超时与取消路径，不能复用固定 500ms 的常规提交等待。
- 重同步候选必须同时满足 Nonce 非零、Magic、cbPayload == pHdr->cbMsg、消息类型范围和完整帧边界。
- 本 ADR 未固化任何未动态核验的 NDIS 私有偏移或硬件 FIFO 行为。
