#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: ROLLBACK.sh <workspace-root>" >&2
    exit 2
fi

script_path="${BASH_SOURCE[0]}"
script_dir="${script_path%/*}"
if [[ "$script_dir" == "$script_path" ]]; then
    script_dir="."
fi
script_dir="$(cd "$script_dir" && pwd)"
workspace_root="$1"
mkdir -p "$workspace_root/loader"
cp "$script_dir/main.cpp.BASELINE" "$workspace_root/loader/main.cpp"
cp "$script_dir/vt_loader.h.BASELINE" "$workspace_root/loader/vt_loader.h"
mkdir -p "$workspace_root/vt/VtBootstrapDriver" "$workspace_root/vt/VtHypervisor" "$workspace_root/vt/VtResidentPayload"
cp "$script_dir/loader.vcxproj.BASELINE" "$workspace_root/loader/loader.vcxproj"
cp "$script_dir/VtBootstrapDriver.vcxproj.BASELINE" "$workspace_root/vt/VtBootstrapDriver/VtBootstrapDriver.vcxproj"
cp "$script_dir/VtHypervisor.vcxproj.BASELINE" "$workspace_root/vt/VtHypervisor/VtHypervisor.vcxproj"
cp "$script_dir/VtResidentPayload.vcxproj.BASELINE" "$workspace_root/vt/VtResidentPayload/VtResidentPayload.vcxproj"
cp "$script_dir/vt_config.h.BASELINE" "$workspace_root/vt/common/vt_config.h"
mkdir -p "$workspace_root/docs/decisions"
cp "$script_dir/README.BASELINE" "$workspace_root/docs/decisions/README.md"
cp "$script_dir/ADR0110.BASELINE" "$workspace_root/docs/decisions/0110-amd-resident-migration-release-gate.md"
rm -f "$workspace_root/docs/decisions/0112-debug-control-retain-with-production-hide.md"
printf 'ROLLBACK_RESULT: restored loader sources, VT project profiles, config and ADR index from baseline\n'
