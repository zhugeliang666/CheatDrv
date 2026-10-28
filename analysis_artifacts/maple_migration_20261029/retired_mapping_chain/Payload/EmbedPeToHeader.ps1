param(
    [Parameter(Mandatory=$true)][string]$InputDll,
    [Parameter(Mandatory=$true)][string]$OutputHeader
)

$ErrorActionPreference = 'Stop'
$bytes = [System.IO.File]::ReadAllBytes($InputDll)

# Parse PE Export Directory from raw file bytes to extract SubclassInitEntry & CustomWndProc RVAs
$e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
$numSections = [BitConverter]::ToUInt16($bytes, $e_lfanew + 6)
$sizeOfOptHeader = [BitConverter]::ToUInt16($bytes, $e_lfanew + 20)
$secTableOff = $e_lfanew + 24 + $sizeOfOptHeader

function RvaToFileOffset([uint32]$rva) {
    for ($s = 0; $s -lt $numSections; $s++) {
        $secOff = $secTableOff + ($s * 40)
        $virtSize = [BitConverter]::ToUInt32($bytes, $secOff + 8)
        $virtAddr = [BitConverter]::ToUInt32($bytes, $secOff + 12)
        $rawSize  = [BitConverter]::ToUInt32($bytes, $secOff + 16)
        $rawPtr   = [BitConverter]::ToUInt32($bytes, $secOff + 20)
        $span = [Math]::Max($virtSize, $rawSize)
        if ($rva -ge $virtAddr -and $rva -lt ($virtAddr + $span)) {
            return ($rva - $virtAddr + $rawPtr)
        }
    }
    throw "Unable to map RVA 0x$($rva.ToString('X')) to file offset"
}

$exportDirRva = [BitConverter]::ToUInt32($bytes, $e_lfanew + 24 + 112)
$exportDirOff = RvaToFileOffset $exportDirRva
$numNames     = [BitConverter]::ToUInt32($bytes, $exportDirOff + 24)
$addrFuncsRva = [BitConverter]::ToUInt32($bytes, $exportDirOff + 28)
$addrNamesRva = [BitConverter]::ToUInt32($bytes, $exportDirOff + 32)
$addrOrdsRva  = [BitConverter]::ToUInt32($bytes, $exportDirOff + 36)

$addrFuncsOff = RvaToFileOffset $addrFuncsRva
$addrNamesOff = RvaToFileOffset $addrNamesRva
$addrOrdsOff  = RvaToFileOffset $addrOrdsRva

$initRva = 0
$wndProcRva = 0

for ($i = 0; $i -lt $numNames; $i++) {
    $nameRva = [BitConverter]::ToUInt32($bytes, $addrNamesOff + ($i * 4))
    $nameOff = RvaToFileOffset $nameRva
    $endOff = $nameOff
    while ($bytes[$endOff] -ne 0) { $endOff++ }
    $fnName = [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $endOff - $nameOff)
    $ord = [BitConverter]::ToUInt16($bytes, $addrOrdsOff + ($i * 2))
    $fnRva = [BitConverter]::ToUInt32($bytes, $addrFuncsOff + ($ord * 4))
    if ($fnName -eq 'SubclassInitEntry') { $initRva = $fnRva }
    elseif ($fnName -eq 'CustomWndProc') { $wndProcRva = $fnRva }
}

if ($initRva -eq 0 -or $wndProcRva -eq 0) {
    throw "Failed to resolve SubclassInitEntry or CustomWndProc from $InputDll"
}
if ((($initRva -band 0xF) -ne 0) -or (($wndProcRva -band 0xF) -ne 0)) {
    throw "CFG requires 16-byte aligned export RVAs (SubclassInitEntry=0x$($initRva.ToString('X')), CustomWndProc=0x$($wndProcRva.ToString('X')))"
}

$dllName = Split-Path $InputDll -Leaf
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("#pragma once")
[void]$sb.AppendLine("// Auto-generated from $dllName by EmbedPeToHeader.ps1")
[void]$sb.AppendLine("")
[void]$sb.AppendLine("static const unsigned int g_MapleRxPayloadSubclassInitRva = 0x$($initRva.ToString('X8'))U;")
[void]$sb.AppendLine("static const unsigned int g_MapleRxPayloadCustomWndProcRva = 0x$($wndProcRva.ToString('X8'))U;")
[void]$sb.AppendLine("static const unsigned int g_MapleRxPayloadSize = $($bytes.Length)U;")
[void]$sb.AppendLine("static const unsigned char g_MapleRxPayloadBytes[$($bytes.Length)] = {")

for ($i = 0; $i -lt $bytes.Length; $i += 16) {
    $chunkEnd = [Math]::Min($i + 15, $bytes.Length - 1)
    $lineParts = @()
    for ($j = $i; $j -le $chunkEnd; $j++) {
        $lineParts += ("0x{0:X2}" -f $bytes[$j])
    }
    $comma = if ($chunkEnd -lt ($bytes.Length - 1)) { "," } else { "" }
    [void]$sb.AppendLine("    " + ($lineParts -join ", ") + $comma)
}

[void]$sb.AppendLine("};")

$utf8Bom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($OutputHeader, $sb.ToString(), $utf8Bom)
Write-Host "[+] Generated $OutputHeader ($($bytes.Length) bytes, SubclassInitEntry=0x$($initRva.ToString('X')), CustomWndProc=0x$($wndProcRva.ToString('X')))"
