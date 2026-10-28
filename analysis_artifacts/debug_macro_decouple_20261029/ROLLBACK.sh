#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="${ROLLBACK_WORKSPACE_ROOT:-$(cd "$script_dir/../.." && pwd)}"
cp "$script_dir/vt__common__vt_config.h.BASELINE" "$workspace_root/vt/common/vt_config.h"
cp "$script_dir/loader__loader.vcxproj.BASELINE" "$workspace_root/loader/loader.vcxproj"
cp "$script_dir/loader__vt_loader.h.BASELINE" "$workspace_root/loader/vt_loader.h"
cp "$script_dir/vt__VtBootstrapDriver__VtBootstrapDriver.vcxproj.BASELINE" "$workspace_root/vt/VtBootstrapDriver/VtBootstrapDriver.vcxproj"
cp "$script_dir/vt__VtHypervisor__VtHypervisor.vcxproj.BASELINE" "$workspace_root/vt/VtHypervisor/VtHypervisor.vcxproj"
cp "$script_dir/vt__VtResidentPayload__VtResidentPayload.vcxproj.BASELINE" "$workspace_root/vt/VtResidentPayload/VtResidentPayload.vcxproj"
cp "$script_dir/vt__VtBootstrapDriver__main.cpp.BASELINE" "$workspace_root/vt/VtBootstrapDriver/main.cpp"
cp "$script_dir/docs__decisions__0112-debug-control-retain-with-production-hide.md.BASELINE" "$workspace_root/docs/decisions/0112-debug-control-retain-with-production-hide.md"
cp "$script_dir/docs__decisions__README.md.BASELINE" "$workspace_root/docs/decisions/README.md"
printf 'ROLLBACK_RESULT: restored pre-follow-up macro coupling state\n'
