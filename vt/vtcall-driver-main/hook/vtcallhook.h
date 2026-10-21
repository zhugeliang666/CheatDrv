#pragma once
#include "../gamecommon/game.h"

namespace vtcallhook {

ULONG64 find_blank(ULONG64 start, ULONG max_scan = 0x100000);
ULONG64 find_blank_system(ULONG64 start, ULONG max_scan = 0x100000);

bool install(PEPROCESS process, PVOID target, ULONG64 blank_mem,
             UINT64 type, bool lock_mdl, bool filter_by_process,
             UINT8 dispatch_mode = VMCALL_DISPATCH_NORMAL,
             bool auto_enable = true);

bool install_ret_abs(PEPROCESS process, PVOID target, ULONG64 blank_mem,
                     UINT64 type, PVOID hook_fn, PVOID* original_out,
                     ULONG64 trample_addr, bool filter_by_process = false,
                     bool auto_enable = true);

void enable(PVOID target);
void disable(PVOID target);
void remove(PVOID target);
void uninit();

} // namespace vtcallhook
