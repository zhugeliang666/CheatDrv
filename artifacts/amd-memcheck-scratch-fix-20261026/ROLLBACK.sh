#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
ART="$(cd "$(dirname "$0")" && pwd)"
cp "$ART/baseline_vcpu.h" "$ROOT/vt/VtHypervisor/vt/vcpu.h"
cp "$ART/baseline_svm-exit.cpp" "$ROOT/vt/VtHypervisor/amd/svm-exit.cpp"
printf 'ROLLBACK: restored vcpu.h and svm-exit.cpp from baseline\n'
