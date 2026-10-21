# Agent memory for mapDriver

## ABI85 stable baseline and promotion rule

The confirmed stable final resident line is ABI85, but the trusted reference is
the exact 2026-06-11 21:14 binary set:

```text
mapDriver.sys      len=448512 sha256=135563269B08370F6749F71A17F48884BA23B7F6642F42C70225740321564F46
payloadRuntime.sys len=180224 sha256=1EA58799207FC13260AFD04095C6B860FD25028976CC236213C44B9E3688AD2D
vtcall.exe         len=46080  sha256=B9CEF0B6DD117E2022D1FD1C73B6D1B10F5C2D4CD46EA5D16C1DAEA77C72ADD6
```

The local archive is:

```text
C:\Users\Administrator\Desktop\newdriver\stable_20260611_2114_abi85_exact_desktoproot\
```

Do not overwrite that baseline with a clean rebuild and call it equivalent until
the user retests and confirms stability.  A later manual `PTE_SEAL`/`pterw`
handler build became unstable and was reverted; keep RW/PTE experiments in
separate named bisect builds.

After the user confirms a build is stable, push the matching TestDriver,
mapDriver, and payload commits to the remote `stable` branch and record exact
binary hashes.
