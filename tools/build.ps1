#Requires -Version 5
<#
.SYNOPSIS
    Configure and build ProxiMight on Windows using the Visual Studio 2022
    developer environment (MSVC + the VS-bundled CMake & Ninja).

.DESCRIPTION
    You do NOT need CMake or Ninja on PATH. This script finds Visual Studio via
    vswhere, activates its developer shell (which puts cl/cmake/ninja on PATH),
    then configures and builds the chosen preset.

    Requires the "Desktop development with C++" workload in Visual Studio 2022.

.PARAMETER Preset
    CMake preset to build. Default: windows-debug.

.PARAMETER Clean
    Delete the preset's build directory first.

.EXAMPLE
    tools/build.ps1
.EXAMPLE
    tools/build.ps1 -Preset windows-release -Clean
#>
[CmdletBinding()]
param(
    [string]$Preset = "windows-debug",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

function Find-VsInstall {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe not found. Install Visual Studio 2022 (with the 'Desktop development with C++' workload)."
    }
    $path = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    if (-not $path) {
        throw "No Visual Studio install with the C++ toolset (VC.Tools) was found. Open the Visual Studio Installer and add 'Desktop development with C++'."
    }
    return $path
}

function Enter-DevShell([string]$vsPath) {
    $dll = Join-Path $vsPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
    if (-not (Test-Path $dll)) { throw "DevShell module not found at $dll" }
    Import-Module $dll
    Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64 -no_logo" | Out-Null
}

Write-Host "==> Locating Visual Studio..." -ForegroundColor Cyan
$vs = Find-VsInstall
Write-Host "    $vs"

Write-Host "==> Activating developer environment (x64)..." -ForegroundColor Cyan
Enter-DevShell $vs

foreach ($t in @("cmake", "ninja", "cl")) {
    $c = Get-Command $t -ErrorAction SilentlyContinue
    if (-not $c) { throw "'$t' still not on PATH after activating the dev shell." }
    Write-Host ("    {0,-6} {1}" -f $t, $c.Source)
}

$buildDir = Join-Path $repo "build\$Preset"
if ($Clean -and (Test-Path $buildDir)) {
    Write-Host "==> Cleaning $buildDir" -ForegroundColor Cyan
    Remove-Item -Recurse -Force $buildDir
}

Push-Location $repo
try {
    Write-Host "==> Configuring preset '$Preset' (first run fetches deps; needs internet)..." -ForegroundColor Cyan
    cmake --preset $Preset
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed ($LASTEXITCODE)." }

    Write-Host "==> Building..." -ForegroundColor Cyan
    cmake --build --preset $Preset
    if ($LASTEXITCODE -ne 0) { throw "Build failed ($LASTEXITCODE)." }

    $exe = Join-Path $buildDir "bin\proximight.exe"
    Write-Host ""
    Write-Host "==> Build OK." -ForegroundColor Green
    if (Test-Path $exe) { Write-Host "    $exe" }
    Write-Host "    Run it with:  tools/run.ps1 -Preset $Preset"
}
finally {
    Pop-Location
}
