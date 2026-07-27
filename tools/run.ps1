#Requires -Version 5
<#
.SYNOPSIS
    Run a built ProxiMight binary.
.PARAMETER Preset
    Which preset's output to run. Default: windows-debug.
#>
[CmdletBinding()]
param(
    [string]$Preset = "windows-debug"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $repo "build\$Preset\bin\proximight.exe"

if (-not (Test-Path $exe)) {
    Write-Host "Not built yet: $exe" -ForegroundColor Yellow
    Write-Host "Build it first:  tools/build.ps1 -Preset $Preset"
    exit 1
}

Write-Host "==> Launching $exe" -ForegroundColor Cyan
& $exe @args
