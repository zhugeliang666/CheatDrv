#!/usr/bin/env bash
set -euo pipefail
ART="$(cd "$(dirname "$0")" && pwd)"
ROOT="${ROLLBACK_WORKSPACE_ROOT:-$(cd "$ART/../.." && pwd)}"
BASE="$ART/baseline_files"
# 删除本次新增文件/目录，保持回滚副本没有迁移产物。
rm -f "$ROOT/vt/VtHypervisor/vt/nested-page-instrumentation.cpp" \
      "$ROOT/vt/VtHypervisor/vt/nested-page-instrumentation.h" \
      "$ROOT/docs/decisions/0114-maple-rx-payload-removal-and-nested-page-observation.md"
# 还原基线文件（包含被移入 retired_mapping_chain 的旧映射链）。
while IFS= read -r -d '' file; do
  rel="${file#$BASE/}"
  mkdir -p "$ROOT/$(dirname "$rel")"
  cp -f "$file" "$ROOT/$rel"
done < <(find "$BASE" -type f -print0)
printf 'ROLLBACK_RESTORED_ROOT=%s\n' "$ROOT"
