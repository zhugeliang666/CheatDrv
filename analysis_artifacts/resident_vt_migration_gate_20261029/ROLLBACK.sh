#!/usr/bin/env bash
set -euo pipefail
ART_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${1:-$(cd "$ART_DIR/../.." && pwd)}"
cp "$ART_DIR/ORIGINAL_vt_config.h" "$ROOT/vt/common/vt_config.h"
cp "$ART_DIR/ORIGINAL_main.cpp" "$ROOT/vt/VtBootstrapDriver/main.cpp"
cp "$ART_DIR/ORIGINAL_vt_loader.h" "$ROOT/Loader/vt_loader.h"
printf 'ROLLBACK_ROOT=%s\n' "$ROOT"
printf 'ROLLBACK_EXIT=0\n'
