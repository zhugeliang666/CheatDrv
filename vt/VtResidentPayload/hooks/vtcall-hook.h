#pragma once

#include <ntddk.h>
#include <stdint.h>

namespace hv {

struct vcpu;

inline bool return_old_func(vcpu*) { return false; }
inline bool vmcall_hook_dispatch(vcpu*) { return false; }
inline bool is_vmcall_blank_rip(uint64_t) { return false; }

#define VMCALL_DISPATCH_SELF 1
#define VMCALL_DISPATCH_RETABS 2
#define VMCALL_HOOK_MAX 32

struct VMCALLHookData
{
    PVOID address;             // 要 Hook 的地址
    PVOID nextAddress;         // 下一条指令地址
    UCHAR oldByte[20];         // 原始字节
    UCHAR nextOldByte[20];     // 下一条指令原始字节
    UCHAR retByte;             // 返回字节
    UCHAR originalBytes[15];   // 原始字节
    ULONG size;                // Hook 大小
    bool isSetJmpCode;         // 是否设置跳转代码
    PEPROCESS process;         // 进程对象
    ULONG64 blankMemory;       // 空白内存页
    ULONG64 fakeMemoryAddress; // 伪内存地址
    PETHREAD thread;           // 线程对象
    bool isEnable;             // 是否启用
    bool isSwitchCr3;          // 是否切换 CR3
    UINT64 type;
    PMDL addressMdl;
    PMDL blankAddressMdl;
    ULONG64 trampleAddress;
    UINT8 dispatch_mode;
    bool filter_by_process;
};

struct vt_hook_slot
{
    VMCALLHookData data;
    void *fake_mem_hva;
    uint64_t trampoline_va; // 0xCC 槽位起始地址 (在 ntdll/ntoskrnl)
    uint64_t bp_rip;        // = trampoline_va + oldByte_size
    uint64_t target_resume; // = (uint64_t)data.address + data.size
    bool occupied;
};

extern vt_hook_slot *g_vt_hook_table;

namespace vh {

// 初始化 Host 端 VTCall 钩子子系统
void init_vtcall_hook_subsystem();

}  // namespace vh

// Host-internal 安装 path: callable from any host root-模式 code, bypasses
// the driver-side broadcast vmcall. Returns true on 执行成功. process=nullptr
// → system process / system_cr3 (use for kernel 函数 hooks).
//
// process is void* not PEPROCESS to avoid type-decoration mismatch between
// TUs that include ntddk.h directly (_EPROCESS*) vs fltKernel.h indirectly
// (_KPROCESS*) — the underlying 指针 is opaque to this layer anyway.
bool vh_install_host(vcpu* cpu, void* process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable);

// DEFERRED variant of vh_install_host. 当前 vCPU installs OWN ept tree
// immediately; other vCPUs are enqueued and 安装 their own ept tree on
// their next vmexit. Avoids the cross-vCPU EPT-写入 race when 目标 page
// is hot (e.g. dxgi GetBuffer page during DWM rendering).
bool vh_install_host_deferred(vcpu* cpu, void* process, uint64_t target_va,
                  uint64_t blank_mem, uint8_t type, uint8_t dispatch_mode,
                  bool filter_by_process, bool auto_enable);

// Host-internal blank scanner. Pass target_cr3=0 to use system_cr3 (kernel
// scan). Returns the 地址 of the byte just past a 4-byte 0xCC run inside
// [start, start+max_scan), or 0 if none found.
uint64_t vh_find_blank_host(uint64_t start, uint64_t max_scan, uint64_t target_cr3);

}  // namespace hv
