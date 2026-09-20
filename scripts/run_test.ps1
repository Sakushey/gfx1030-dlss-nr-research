<#
.SYNOPSIS
    Build (and optionally run) the bounded gfx1030 dense soft-matrix fixture.

.DESCRIPTION
    Safe by construction: no Administrator rights, no persistent environment
    changes, no clocks/voltage/BIOS/power changes. The GPU workload, when the
    run phase is reached at all, is one 32-thread block and one 16x16x16
    matrix tile.

    Two phases, and they are separable:

      * BUILD. Resolves the toolchain (HIP clang++ plus the MSVC host linker)
        and compiles the fixture. `-BuildOnly` stops here. It performs NO
        device enumeration and does NOT invoke the produced executable, so it
        is safe on a machine with no GPU, no display, and no driver.

      * RUN. Only reached without `-BuildOnly`: enumerate the device, require
        gfx1030, then execute the fixture once.

    HIP root resolution order (first hit wins):
      1. -HipRoot <path>
      2. $env:GFX1030_HIP_ROOT
      3. the default below
    The root is never inferred from PATH: two ROCm versions can be installed
    side by side and `clang++` on PATH is not necessarily the one whose
    runtime the fixture will load.

    Visual Studio discovery is deliberately layered. The `MSFT_VSInstance` WMI
    class is the *last* resort rather than the only mechanism, because it is
    not registered on every host: on a Build Tools-only machine it can raise
    "Invalid class" and a script that depends on it alone silently concludes
    that no C++ compiler is installed.

.PARAMETER BuildOnly
    Resolve dependencies, find the toolchain, compile, print the artifact
    path, and exit 0. Does not enumerate the GPU and does not run the
    executable.

.PARAMETER HipRoot
    Explicit HIP installation root. Overrides $env:GFX1030_HIP_ROOT.

.PARAMETER Source
    Fixture source. Defaults to tests\soft_wmma_test.cpp relative to the
    repository root.

.PARAMETER Exe
    Output executable path. Defaults to
    tests\soft_wmma_test.exe relative to the repository root.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\run_test.ps1 -BuildOnly

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\run_test.ps1 -HipRoot 'C:\Program Files\AMD\ROCm\6.4'
#>
[CmdletBinding()]
param(
    [switch]$BuildOnly,
    [string]$HipRoot,
    [string]$Source,
    [string]$Exe
)

$ErrorActionPreference = "Stop"

# Repo root = parent of this script's directory. The launch script was moved
# into scripts\ but the fixtures live in tests\, so the paths are resolved
# from the repository root rather than from $PSScriptRoot.
$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo    = Split-Path -Parent $Here
$DefaultHipRoot = Join-Path ${env:ProgramFiles} "AMD\ROCm\6.4"

if (-not $HipRoot -or $HipRoot.Trim() -eq "") {
    if ($env:GFX1030_HIP_ROOT -and $env:GFX1030_HIP_ROOT.Trim() -ne "") {
        $HipRoot = $env:GFX1030_HIP_ROOT
    }
    else {
        $HipRoot = $DefaultHipRoot
    }
}

if (-not $Source -or $Source.Trim() -eq "") {
    $Source = Join-Path $Repo "tests\soft_wmma_test.cpp"
}
if (-not $Exe -or $Exe.Trim() -eq "") {
    $Exe = Join-Path $Repo "tests\soft_wmma_test.exe"
}

Write-Host ""
Write-Host "=== SAFE gfx1030 SOFT-WMMA PHASE 1 ===" -ForegroundColor Cyan
Write-Host "No admin rights, no persistent environment changes, no clocks/voltage/BIOS changes."
Write-Host "The GPU workload is one 32-thread block and one 16x16x16 matrix tile."
if ($BuildOnly) {
    Write-Host "Mode: -BuildOnly (compile only; no device enumeration, fixture NOT run)." -ForegroundColor Cyan
}
Write-Host "HIP root: $HipRoot"

# ---------------------------------------------------------------------------
# Dependency resolution
# ---------------------------------------------------------------------------
if (-not (Test-Path $HipRoot)) {
    throw "HIP root not found: $HipRoot. Pass -HipRoot <path> or set GFX1030_HIP_ROOT."
}

$Clang = Join-Path $HipRoot "bin\clang++.exe"
$HipInfo = Join-Path $HipRoot "bin\hipInfo.exe"

if (-not (Test-Path $Clang)) {
    throw "clang++.exe not found at $Clang"
}
if (-not (Test-Path $Source)) {
    throw "Source file not found: $Source"
}
# hipInfo.exe is a RUN-phase dependency only. -BuildOnly must not require it,
# because requiring it would be the first step of device enumeration.
if (-not $BuildOnly -and -not (Test-Path $HipInfo)) {
    throw "hipInfo.exe not found at $HipInfo"
}

# ---------------------------------------------------------------------------
# MSVC host toolchain
#
# Layered on purpose. Each strategy is recorded so a failure report says which
# ones were tried, and the WMI class is consulted last.
# ---------------------------------------------------------------------------
function Test-LinkerAvailable {
    return [bool](Get-Command link.exe -ErrorAction SilentlyContinue)
}

function Get-VsInstallFromVswhere {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { return @() }
    $found = @()
    # -latest first; -all/-prerelease as a fallback so a preview-only or
    # side-by-side install is still discoverable.
    foreach ($extra in @(@('-latest'), @('-all', '-prerelease'))) {
        # $vsArgs, not $args: $args is a PowerShell automatic variable.
        $vsArgs = @('-products', '*',
                    '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
                    '-property', 'installationPath') + $extra
        try {
            $out = & $vswhere @vsArgs 2>$null
        }
        catch {
            continue
        }
        foreach ($line in @($out)) {
            if ($line -and $line.Trim() -ne "" -and (Test-Path $line.Trim())) {
                $found += $line.Trim()
            }
        }
        if ($found.Count -gt 0) { break }
    }
    return $found
}

function Get-VsInstallFromWellKnownRoots {
    $roots = @()
    foreach ($base in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
        if (-not $base) { continue }
        foreach ($year in @("2022", "2019")) {
            foreach ($edition in @("Enterprise", "Professional", "Community", "BuildTools")) {
                $roots += (Join-Path $base "Microsoft Visual Studio\$year\$edition")
            }
        }
    }
    if ($env:VSINSTALLDIR) { $roots += $env:VSINSTALLDIR.TrimEnd('\') }
    return @($roots | Where-Object { $_ -and (Test-Path $_) })
}

function Get-VsInstallFromWmi {
    # Last resort. Not registered on every host -- on this project's host this
    # call raises "Invalid class", which is exactly why it cannot be the only
    # mechanism.
    try {
        $inst = Get-CimInstance MSFT_VSInstance -ErrorAction Stop
    }
    catch {
        return @()
    }
    $out = @()
    foreach ($i in @($inst)) {
        if ($i.InstallLocation -and (Test-Path $i.InstallLocation)) {
            $out += $i.InstallLocation
        }
    }
    return $out
}

function Enter-VsDevShellFor([string]$installPath) {
    $devShell = Join-Path $installPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
    if (-not (Test-Path $devShell)) { return $false }
    try {
        Import-Module $devShell -ErrorAction Stop
        Enter-VsDevShell -InstallPath $installPath `
            -SkipAutomaticLocation -Arch amd64 -HostArch amd64 `
            -DevCmdArguments '-no_logo' | Out-Null
    }
    catch {
        return $false
    }
    return (Test-LinkerAvailable)
}

if (-not (Test-LinkerAvailable)) {
    $strategies = [ordered]@{
        'vswhere'          = { Get-VsInstallFromVswhere }
        'well-known-roots' = { Get-VsInstallFromWellKnownRoots }
        'MSFT_VSInstance'  = { Get-VsInstallFromWmi }
    }
    $tried = @()
    foreach ($name in $strategies.Keys) {
        $candidates = @(& $strategies[$name])
        if ($candidates.Count -eq 0) {
            $tried += "$name (no install found)"
            continue
        }
        foreach ($candidate in $candidates) {
            if (Enter-VsDevShellFor $candidate) {
                Write-Host "MSVC toolchain: found via $name at $candidate" -ForegroundColor Green
                $tried = @()
                break
            }
            # ${candidate} not $candidate: a bare `$candidate:` parses as a
            # scoped variable reference and is a parse error.
            $tried += "$name (${candidate}: dev shell did not provide link.exe)"
        }
        if (Test-LinkerAvailable) { break }
    }
    if ($tried.Count -gt 0) {
        Write-Host ""
        Write-Host "STOP: Microsoft C++ build tools are missing/not active." -ForegroundColor Yellow
        Write-Host "Install Visual Studio 2022 Build Tools -> Desktop development with C++,"
        Write-Host "including MSVC v143 and a Windows SDK. Then rerun this script."
        Write-Host "Strategies tried:"
        foreach ($t in $tried) { Write-Host "  - $t" }
        exit 10
    }
}
else {
    Write-Host "MSVC toolchain: link.exe already on PATH" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== COMPILER ===" -ForegroundColor Cyan
& $Clang --version | Select-Object -First 2

Write-Host ""
Write-Host "=== COMPILE FOR gfx1030 ===" -ForegroundColor Cyan

if (Test-Path $Exe) {
    Remove-Item $Exe -Force
}

# Session-only environment. This does NOT change Machine/User environment
# variables.
$env:HIP_PATH = $HipRoot
$env:HIP_PLATFORM = "amd"
$env:Path = "$($HipRoot)\bin;$env:Path"

$CompileArgs = @(
    "-x", "hip",
    "--offload-arch=gfx1030",
    "--hip-path=$HipRoot",
    "-O3",
    "-std=c++17",
    "-I", (Split-Path -Parent $Source),
    $Source,
    "-o", $Exe
)

& $Clang @CompileArgs

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Exe)) {
    throw "Compilation failed."
}

Write-Host ""
Write-Host "Compiled: $Exe" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Build-only stop. Everything below this point touches the device, so it is
# gated rather than merely skipped: -BuildOnly returns before the first
# hipInfo invocation and before the fixture is ever executed.
# ---------------------------------------------------------------------------
if ($BuildOnly) {
    Write-Host ""
    Write-Host "BUILD-ONLY: compile complete. No device was enumerated and the fixture was not run." -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "=== HIP 6.4 DEVICE CHECK ===" -ForegroundColor Cyan
$HipText = (& $HipInfo 2>&1 | Out-String)
$HipText | Select-String -Pattern "Name:|gcnArchName|gfx1030" | ForEach-Object { $_.Line }

if ($HipText -notmatch "gfx1030") {
    throw "STOP: HIP 6.4 did not report gfx1030. The test will not compile/run."
}

Write-Host ""
Write-Host "=== RUN ONE TINY GPU TILE ===" -ForegroundColor Cyan
& $Exe
$RunCode = $LASTEXITCODE

Write-Host ""
if ($RunCode -eq 0) {
    Write-Host "PHASE 1 PASSED." -ForegroundColor Green
    Write-Host "Next step: disassemble this gfx1030 kernel and then add a short bounded benchmark."
}
else {
    Write-Host "PHASE 1 did not pass (exit code $RunCode)." -ForegroundColor Yellow
    Write-Host "Paste the complete output; do not change clocks, drivers, BIOS, or power settings."
}

exit $RunCode
