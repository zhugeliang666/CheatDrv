#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="${ROLLBACK_WORKSPACE_ROOT:-$(cd "$script_dir/../.." && pwd)}"
cp "$script_dir/main.cpp.BASELINE" "$workspace_root/vt/VtBootstrapDriver/main.cpp"
cp "$script_dir/vt_loader.h.BASELINE" "$workspace_root/loader/vt_loader.h"
cp "$script_dir/ADR0112.BASELINE" "$workspace_root/docs/decisions/0112-debug-control-retain-with-production-hide.md"
cp "$script_dir/README.BASELINE" "$workspace_root/docs/decisions/README.md"
printf 'ROLLBACK_RESULT: restored Debug DROPCTL guard sources and ADR index from baseline\n'
