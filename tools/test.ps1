#Requires -Version 5
<#
.SYNOPSIS
    Run ProxiMight's CTest suite for a preset, using the Visual Studio 2022
    developer environment (so ctest/cmake resolve without being on PATH).

.DESCRIPTION
    Mirrors tools/build.ps1's dev-shell activation, then runs ctest against the
    preset's build directory (build/<preset>). Works for windows-release too,
    which has no dedicated CTest *preset* — ctest just needs the build dir.

    Build first with tools/build.ps1 -Preset <preset>; this only runs the tests.

.PARAMETER Preset
    Which build to test. Default: windows-debug.

.EXAMPLE
    tools/test.ps1
.EXAMPLE
    tools/test.ps1 -Preset windows-release
#>
[CmdletBinding()]
param([string]$Preset = "windows-debug")

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $repo "build\$Preset"
if (-not (Test-Path $buildDir)) {
    throw "Build directory $buildDir not found. Build it first: tools/build.ps1 -Preset $Preset"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found. Install Visual Studio 2022 (Desktop development with C++)."
}
$vs = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vs) { throw "No Visual Studio install with the C++ toolset was found." }

Import-Module (Join-Path $vs "Common7\Tools\Microsoft.VisualStudio.DevShell.dll")
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation `
    -DevCmdArguments "-arch=x64 -host_arch=x64 -no_logo" | Out-Null

Push-Location $buildDir
try {
    Write-Host "==> ctest ($Preset)" -ForegroundColor Cyan
    ctest --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "Tests failed ($LASTEXITCODE)." }
    Write-Host "==> Tests OK." -ForegroundColor Green
}
finally {
    Pop-Location
}
