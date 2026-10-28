#!/usr/bin/env bash
set -euo pipefail
target="${1:?target path required}"
baseline="${2:?baseline path required}"
cp -- "$baseline" "$target"
printf 'ROLLBACK_TARGET=%s\n' "$target"
printf 'RESTORED_SHA256='
sha256sum "$target" | awk '{print $1}'
