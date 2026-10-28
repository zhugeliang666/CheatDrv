#!/usr/bin/env pwsh
param([Parameter(Mandatory=$true)][string]$Target,[Parameter(Mandatory=$true)][string]$Baseline)
$ErrorActionPreference = "Stop"
Copy-Item -LiteralPath $Baseline -Destination $Target -Force
Write-Output "ROLLBACK_RESTORED=$Target"
