# Phase 14EI — build helper (mirrors phase14d11/phase14e harness convention).
# Usage: powershell -File p14ei_build.ps1 -Source <file.cpp> [-Out <file.exe>]
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [string]$Out
)
$ErrorActionPreference = "Stop"

$HipRoot = "C:\Program Files\AMD\ROCm\6.4"
$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $Out) { $Out = [System.IO.Path]::ChangeExtension($Source, ".exe") }
if (-not [System.IO.Path]::IsPathRooted($Source)) { $Source = Join-Path $Here $Source }
if (-not [System.IO.Path]::IsPathRooted($Out))    { $Out = Join-Path $Here $Out }

if (-not (Test-Path $HipRoot)) { throw "HIP 6.4 root not found: $HipRoot" }
$Clang = Join-Path $HipRoot "bin\clang++.exe"
if (-not (Test-Path $Clang)) { throw "clang++.exe not found at $Clang" }

$env:HIP_PATH = $HipRoot
$env:HIP_PLATFORM = "amd"
$env:Path = "$($HipRoot)\bin;$env:Path"

if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
    try {
        $VS = $null
        $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vsWhere) {
            $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
            if ($vsPath) {
                $DevShell = Join-Path $vsPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
                if (Test-Path $DevShell) {
                    Import-Module $DevShell
                    Enter-VsDevShell -InstallPath $vsPath -SkipAutomaticLocation -Arch amd64 -HostArch amd64 -DevCmdArguments '-no_logo'
                }
            }
        }
        if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
            $VS = Get-CimInstance MSFT_VSInstance | Sort-Object -Property Version -Descending | Select-Object -First 1
            if ($VS -and $VS.InstallLocation) {
                $DevShell = Join-Path $VS.InstallLocation "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
                if (Test-Path $DevShell) {
                    Import-Module $DevShell
                    Enter-VsDevShell -InstallPath $VS.InstallLocation -SkipAutomaticLocation -Arch amd64 -HostArch amd64 -DevCmdArguments '-no_logo'
                }
            }
        }
    }
    catch { }
}
if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
    Write-Host "STOP: Microsoft C++ build tools are missing/not active."
    exit 10
}

if (Test-Path $Out) { Remove-Item $Out -Force }

& $Clang "-x" "hip" "--offload-arch=gfx1030" "--hip-path=$HipRoot" "-O3" "-std=c++17" $Source "-o" $Out
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Out)) {
    throw "Compilation failed (exit $LASTEXITCODE)."
}
Write-Host "Built: $Out"
exit 0
