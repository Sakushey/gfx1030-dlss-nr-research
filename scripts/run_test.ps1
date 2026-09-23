$ErrorActionPreference = "Stop"

$HipRoot = "C:\Program Files\AMD\ROCm\6.4"
$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source  = Join-Path (Split-Path -Parent $Here) "tests\soft_wmma_test.cpp"
$Exe     = Join-Path $Here "soft_wmma_test.exe"

Write-Host ""
Write-Host "=== SAFE gfx1030 SOFT-WMMA PHASE 1 ===" -ForegroundColor Cyan
Write-Host "No admin rights, no persistent environment changes, no clocks/voltage/BIOS changes."
Write-Host "The GPU workload is one 32-thread block and one 16x16x16 matrix tile."

if (-not (Test-Path $HipRoot)) {
    throw "HIP 6.4 root not found: $HipRoot"
}

$Clang = Join-Path $HipRoot "bin\clang++.exe"
$HipInfo = Join-Path $HipRoot "bin\hipInfo.exe"

if (-not (Test-Path $Clang)) {
    throw "clang++.exe not found at $Clang"
}
if (-not (Test-Path $HipInfo)) {
    throw "hipInfo.exe not found at $HipInfo"
}
if (-not (Test-Path $Source)) {
    throw "Source file not found: $Source"
}

# Session-only environment. This does NOT change Machine/User environment variables.
$env:HIP_PATH = $HipRoot
$env:HIP_PLATFORM = "amd"
$env:Path = "$($HipRoot)\bin;$env:Path"

Write-Host ""
Write-Host "=== HIP 6.4 DEVICE CHECK ===" -ForegroundColor Cyan
$HipText = (& $HipInfo 2>&1 | Out-String)
$HipText | Select-String -Pattern "Name:|gcnArchName|gfx1030" | ForEach-Object { $_.Line }

if ($HipText -notmatch "gfx1030") {
    throw "STOP: HIP 6.4 did not report gfx1030. The test will not compile/run."
}

# AMD's Windows HIP compiler needs the MSVC/Windows SDK host toolchain.
# If link.exe is not already visible, try to enter the latest VS developer shell.
if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
    try {
        $VS = Get-CimInstance MSFT_VSInstance |
            Sort-Object -Property Version -Descending |
            Select-Object -First 1

        if ($VS -and $VS.InstallLocation) {
            $DevShell = Join-Path $VS.InstallLocation "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
            if (Test-Path $DevShell) {
                Import-Module $DevShell
                Enter-VsDevShell `
                    -InstallPath $VS.InstallLocation `
                    -SkipAutomaticLocation `
                    -Arch amd64 `
                    -HostArch amd64 `
                    -DevCmdArguments '-no_logo'
            }
        }
    }
    catch {
        # Fall through to the clean diagnostic below.
    }
}

if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "STOP: Microsoft C++ build tools are missing/not active." -ForegroundColor Yellow
    Write-Host "Install Visual Studio 2022 Build Tools -> Desktop development with C++,"
    Write-Host "including MSVC v143 and a Windows SDK. Then rerun this script."
    exit 10
}

Write-Host ""
Write-Host "=== COMPILER ===" -ForegroundColor Cyan
& $Clang --version | Select-Object -First 2

if (Test-Path $Exe) {
    Remove-Item $Exe -Force
}

Write-Host ""
Write-Host "=== COMPILE FOR gfx1030 ===" -ForegroundColor Cyan

$CompileArgs = @(
    "-x", "hip",
    "--offload-arch=gfx1030",
    "--hip-path=$HipRoot",
    "-O3",
    "-std=c++17",
    $Source,
    "-o", $Exe
)

& $Clang @CompileArgs

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Exe)) {
    throw "Compilation failed."
}

Write-Host ""
Write-Host "Compiled: $Exe" -ForegroundColor Green

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
