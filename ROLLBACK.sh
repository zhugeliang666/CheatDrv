#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SNAPSHOT="$SCRIPT_DIR/original_snapshot.zip"
python - "$ROOT" "$SNAPSHOT" <<'PY'
from pathlib import Path
import sys, zipfile
root=Path(sys.argv[1]).resolve()
snapshot=Path(sys.argv[2]).resolve()
if root.name != 'CheatDrv' or not (root/'Machenike.sln').is_file():
    raise SystemExit('ROLLBACK_REFUSED=unexpected workspace root')
with zipfile.ZipFile(snapshot) as z:
    for name in z.namelist():
        target=(root/name).resolve()
        if root not in target.parents:
            raise SystemExit('ROLLBACK_REFUSED=path escape')
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(z.read(name))
source=root/'bin/vt/VtBootstrapDriver.sys'
if source.is_file():
    (root/'bin/VtBootstrapDriver.sys').write_bytes(source.read_bytes())
    (root/'bin/mapDriver.sys').write_bytes(source.read_bytes())
print('ROLLBACK_RESULT=restored pre-change source selection and legacy alias behavior')
PY