#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET="${ROLLBACK_TARGET:-$ROOT}"
copy_back() {
  local snapshot="$1"
  local destination="$2"
  mkdir -p "$(dirname "$TARGET/$destination")"
  cp "$SCRIPT_DIR/$snapshot" "$TARGET/$destination"
}
copy_back 'vt__VtBootstrapDriver__poolmanager__PoolManager.h.ORIGINAL' 'vt/VtBootstrapDriver/poolmanager/PoolManager.h'
copy_back 'vt__VtBootstrapDriver__poolmanager__PoolManager.cpp.ORIGINAL' 'vt/VtBootstrapDriver/poolmanager/PoolManager.cpp'
copy_back 'vt__VtBootstrapDriver__main.cpp.ORIGINAL' 'vt/VtBootstrapDriver/main.cpp'
printf 'ROLLBACK_TARGET=%s\n' "$TARGET"
printf 'ROLLBACK_STATUS=restored-original-snapshots\n'
