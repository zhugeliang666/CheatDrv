#!/usr/bin/env bash
set -euo pipefail
ART="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$ART/../.." && pwd)"
cp "$ART/vt__VtBootstrapDriver__main.cpp.original" "$ROOT/vt/VtBootstrapDriver/main.cpp"
cp "$ART/docs__decisions__README.md.original" "$ROOT/docs/decisions/README.md"
cp "$ART/docs__decisions__0079-payload-text-dual-view-stability-fix-0x1e.md.original" "$ROOT/docs/decisions/0079-payload-text-dual-view-stability-fix-0x1e.md"
rm -f "$ROOT/docs/decisions/0080-payload-image-pool-overlap-exclusion.md"
printf 'ROLLBACK_STATUS=restored\n'
