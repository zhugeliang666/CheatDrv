#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "usage: ROLLBACK.sh <modified-copy> <baseline-file>" >&2
  exit 2
fi
cp -- "$2" "$1"
sha256sum -- "$1"