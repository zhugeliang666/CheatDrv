#!/usr/bin/env bash
set -euo pipefail
target="${1:?target required}"
baseline="${2:-}"
codex_bin="C:/Users/123/AppData/Local/OpenAI/Codex/bin/896a0166b774037a/codex.exe"
if [[ "$target" == "global" ]]; then
  "$codex_bin" plugin remove ida-mcp@HexRaysSA --json
  "$codex_bin" plugin marketplace remove HexRaysSA --json
  echo "ROLLBACK_APPLIED target=global plugin=removed marketplace=removed"
  exit 0
fi
case "$target" in
  */games/IdaMcpInstall/.transaction/rollback-test) ;;
  *) echo "ROLLBACK_REJECTED target=$target"; exit 64 ;;
esac
cp "$baseline/ORIGINAL_STATE" "$target/MODIFIED_FILE"
echo "ROLLBACK_APPLIED target=$target state=original"
