$ErrorActionPreference = 'Stop'
$baseline = Get-Content -Raw -LiteralPath 'analysis_artifacts/amd_ack_fix_20261028/main.cpp.BASELINE'
$modified = Get-Content -Raw -LiteralPath 'analysis_artifacts/amd_ack_fix_20261028/MODIFIED_FILE'
if ($baseline.Contains('g_amd_resident_ack_snapshot')) { throw 'baseline unexpectedly contains ACK snapshot' }
$required = @(
  'g_amd_resident_ack_snapshot',
  'g_amd_resident_vcpu_count_snapshot',
  'g_amd_resident_ghv_snapshot',
  'g_amd_resident_vcpus_snapshot',
  'if (ack != check->diag.vcpu_count && mapdriver_hv_ready())',
  'snapshot_ghv == check->diag.ghv',
  'snapshot_vcpus == check->diag.vcpus'
)
foreach ($needle in $required) { if (!$modified.Contains($needle)) { throw "missing: $needle" } }
function Resolve-Ack([UInt64]$live, [UInt64]$expected, [bool]$hvReady, [UInt64]$snapAck, [UInt64]$snapCount, [UInt64]$snapGhv, [UInt64]$snapVcpus, [UInt64]$diagGhv, [UInt64]$diagVcpus) {
  if ($live -eq $expected) { return $live }
  if ($hvReady -and $snapAck -eq $expected -and $snapCount -eq $expected -and $snapGhv -eq $diagGhv -and $snapVcpus -eq $diagVcpus) { return $snapAck }
  return $live
}
$case1 = Resolve-Ack 0 8 $true 8 8 0x1000 0x2000 0x1000 0x2000
$case2 = Resolve-Ack 0 8 $true 8 8 0x1000 0x2000 0x1001 0x2000
$case3 = Resolve-Ack 0 8 $false 8 8 0x1000 0x2000 0x1000 0x2000
if ($case1 -ne 8 -or $case2 -ne 0 -or $case3 -ne 0) { throw "simulation mismatch: $case1/$case2/$case3" }