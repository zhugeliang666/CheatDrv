# Agent memory for resident payload work

## TestDriver VMCALL dispatch parity

When migrating or debugging TestDriver hooks in resident payload, do not treat
hook-site VMCALL dispatch as a trampoline-pool reverse lookup.

TestDriver's exact split is:

1. Hook-site VMCALL dispatch (`..\TestDriver\gamecommon\game.cpp::vmcall_hook_dispatch`)
   walks `g_vt_hook_table`, matches `VMCS_GUEST_RIP == slot.data.address`, calls
   the registered handler when the process filter allows it, and if the handler
   did not change RIP, writes `VMCS_GUEST_RIP = slot.trampoline_va`.
2. Trampoline-pool scanning is only the later `#BP` stage: after the trampoline
   runs copied bytes and hits `0xCC`, the #BP handler matches `slot.bp_rip` and
   rewrites RIP to `slot.target_resume`.
3. Resident payload hook-site dispatch must therefore prefer direct
   `vt_hook_table` slot lookup (`data.address`, `trampoline_va`, `bp_rip`,
   `target_resume`) over `tramp_pool` reverse scan.  A pool scan miss after a
   hook-site VMCALL is not harmless; returning 0 can let generic VMCALL skip
   logic advance RIP into fake-page tail bytes and look like a random jump.
4. Do not attribute `dxgi!GetBuffer` crashes to a remembered GS-cookie/prologue
   pattern without current disassembly.  First verify whether dispatch had a
   valid slot-backed `trampoline_va` and whether it returned 0 after the
   hook-site VMCALL fired.

## Payload host-stack slots

Do not confuse payload host-stack slots with trampoline slots or a generic
"slot stack" concept.

1. `g_host_stack_base/size/slot_size/slot_count` describe the payload-owned host
   stack slab used for VMX-root host stacks.
2. The first `g_cached_hv_diag.vcpu_count` host-stack slots are permanent
   `VMCS_HOST_RSP` stacks installed by mapDriver during handoff.
3. Temporary PMO `CallUser` continuations must allocate only from slots after
   those permanent per-vCPU slots; see `src\bridge\pmo\pmo_callout_state.inl`.
4. TestDriver's `vtcallstack` pool is a separate inline `ghv` buffer and should
   not be conflated with payload host-stack slab or trampoline pool slots.

### MM ext hook symbol dependency

Resident payload MM ext hooks (type 29/27/28) consume kernel symbol VAs from TestDriver's HV diag handoff. A loaded payload with `img_size=0x5B000`, `mm4_inst mask=0xF`, `fmask=0x70`, and `last_target=0` means the ext handlers are compiled in but TestDriver handed off zero addresses (`mm_is_address_valid_ex_va`, `nt_query_virtual_memory_va`, `mm_get_physical_address_va`). Fix/verify `TestDriver\vt\hv.cpp` ext symbol macros and `[YVT-DIAG] ext mm symbols` before changing trampoline or handler logic.

### Final low-footprint resident mode

In final mode the resident payload control device is compiled out (`PAYLOAD_RESIDENT_CTL_ENABLED=0`). Payload status must still remain reachable through the resident VMX hypercall path (`hypercall_get_payload_status`, code 91), and vtcall has `payload` / `waitunld` commands for this. Do not re-enable resident ctl just to inspect final builds; use vtcall unless debugging an earlier lifecycle phase.

Unload trace cleanup is not performed by payload ctl. mapDriver resolves `MmUnloadedDrivers`/`MmLastUnloadedDriver` before returning failure and passes those addresses plus the driver BaseDllName in `payload_boot_context.trace_unload_*`; payload retries a delayed scrub from `PayloadBridgePostDispatchTraceScrub` until `trace_unload_clean_count` moves or max attempts is reached.

CI hash trace cleanup is also delayed in final mode. mapDriver still does an in-DriverEntry best-effort `g_KernelHashBucketList` cleanup with logs available when `MAPDRIVER_LOG_ENABLED=1`, but final `/onekeyfail:1` can leave/refresh CI hash state after `DriverEntry` returns failure. mapDriver therefore also resolves CI's `g_KernelHashBucketList`/HashCacheLock and passes them in `payload_boot_context.trace_hash_*`; payload unlinks and sanitizes a matching hash bucket entry from the VM-exit post-dispatch path. Inspect with `vtcall.exe payload` / `vtcall.exe waithash`.

WdFilter is not cleaned or verified from VT by default. The safe path is still mapDriver's in-DriverEntry cleanup, because WdFilter removal mutates a list, array, count, and may call `MpFreeDriverInfoEx`, which is not safe to execute from VMX-root. A previous delayed read-only WdFilter verifier was removed after causing instability; do not reintroduce it unless explicitly requested for a named bisect.

### ABI85 stable baseline memory

The confirmed stable resident line is ABI85, but the stable reference is the
exact 2026-06-11 21:14 binary set rather than an unverified rebuild:

```text
mapDriver.sys      len=448512 sha256=135563269B08370F6749F71A17F48884BA23B7F6642F42C70225740321564F46
payloadRuntime.sys len=180224 sha256=1EA58799207FC13260AFD04095C6B860FD25028976CC236213C44B9E3688AD2D
vtcall.exe         len=46080  sha256=B9CEF0B6DD117E2022D1FD1C73B6D1B10F5C2D4CD46EA5D16C1DAEA77C72ADD6
```

Do not reintroduce the manual `PTE_SEAL`/`pterw` handler or RW automation into
the stable payload path; a build with that handler became unstable and was
reverted.  Any new RW/PTE work must be isolated behind a named bisect/test
build.  After the user confirms stability, promote the matching commits to the
remote `stable` branch and record the exact binary hashes.
