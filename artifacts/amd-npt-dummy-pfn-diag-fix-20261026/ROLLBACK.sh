#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
ART="$(cd "$(dirname "$0")" && pwd)"
cp "$ART/baseline_vt_VtBootstrapDriver_common_mapctl_ioctl.h" "$ROOT/vt/VtBootstrapDriver/common/mapctl_ioctl.h"
cp "$ART/baseline_vt_VtHypervisor_amd_svm-exit.cpp" "$ROOT/vt/VtHypervisor/amd/svm-exit.cpp"
cp "$ART/baseline_vt_VtHypervisor_vt_hypercalls.cpp" "$ROOT/vt/VtHypervisor/vt/hypercalls.cpp"
cp "$ART/baseline_vt_VtResidentPayload_bridge_hypercall_resident_commands.inl" "$ROOT/vt/VtResidentPayload/bridge/hypercall/resident_commands.inl"
cp "$ART/baseline_vt_VtResidentPayload_bridge_memcheck_runtime_verify_ranges.inl" "$ROOT/vt/VtResidentPayload/bridge/memcheck/runtime/verify_ranges.inl"
cp "$ART/baseline_vt_VtResidentPayload_bridge_memcheck_runtime_hide_pfn_commands.inl" "$ROOT/vt/VtResidentPayload/bridge/memcheck/runtime/hide_pfn_commands.inl"
cp "$ART/baseline_vt_VtResidentPayload_bridge_entry_bridge_entry.inl" "$ROOT/vt/VtResidentPayload/bridge/entry/bridge_entry.inl"
cp "$ART/baseline_vt_VtResidentPayload_payload.cpp" "$ROOT/vt/VtResidentPayload/payload.cpp"
printf 'ROLLBACK: restored AMD NPT diagnostic fields and dummy-PFN readers\n'
