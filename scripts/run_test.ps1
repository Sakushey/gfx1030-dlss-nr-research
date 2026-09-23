[CmdletBinding()]
param(
    [ValidateSet("gfx1030", "gfx1031", "gfx1032")]
    [string]$Target = "gfx1030"
)

$ErrorActionPreference = "Stop"

$HipRoot = "C:\Program Files\AMD\ROCm\6.4"
$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source  = Join-Path $Here "..\tests\soft_wmma_test.cpp"
$Exe     = Join-Path $Here "soft_wmma_test.exe"

Write-Host ""
Write-Host "=== SAFE RDNA2 SOFT-WMMA PHASE 1 ===" -ForegroundColor Cyan
Write-Host "Requested target: $Target"
Write-Host "No admin rights, no persistent environment changes, no clocks/voltage/BIOS changes."
Write-Host "The GPU workload is one 32-thread block and one 16x16x16 matrix tile."

if (Test-Path Env:HSA_OVERRIDE_GFX_VERSION) {
    throw "STOP: HSA_OVERRIDE_GFX_VERSION is set. Clear it before target qualification; architecture overrides are not accepted evidence."
}

if (-not (Test-Path $HipRoot)) {
    throw "HIP 6.4 root not found: $HipRoot"
}

$Hipcc = Join-Path $HipRoot "bin\hipcc.exe"
$HipInfo = Join-Path $HipRoot "bin\hipInfo.exe"

if (-not (Test-Path $Hipcc)) {
    throw "hipcc.exe not found at $Hipcc"
}
if (-not (Test-Path $HipInfo)) {
    throw "hipInfo.exe not found at $HipInfo"
}
if (-not (Test-Path $Source)) {
    throw "Source file not found: $Source"
}

# Session-only environment. This does NOT change Machine/User environment variables.
# On Windows, hipcc uses HIP_PATH. Do not also pass --hip-path with this
# "Program Files" installation: ROCm 6.4 hipcc can split that wrapper argument.
$env:HIP_PATH = $HipRoot
$env:HIP_PLATFORM = "amd"
$env:Path = "$($HipRoot)\bin;$env:Path"

Write-Host ""
Write-Host "=== HIP 6.4 DEVICE CHECK ===" -ForegroundColor Cyan
$HipText = (& $HipInfo 2>&1 | Out-String)
$HipText | Select-String -Pattern "Name:|gcnArchName|gfx103" | ForEach-Object { $_.Line }

$ArchMatches = [regex]::Matches($HipText, 'gcnArchName\s*[:=]\s*(gfx[0-9A-Za-z_:+-]+)')
if ($ArchMatches.Count -lt 1) {
    throw "STOP: could not parse gcnArchName from hipInfo output."
}

$DetectedTarget = ($ArchMatches[0].Groups[1].Value -split ':')[0]
if ($DetectedTarget -ne $Target) {
    throw "STOP: HIP reported $DetectedTarget but the requested compile target is $Target. Nothing will compile or run."
}

# AMD's Windows HIP driver needs the MSVC/Windows SDK host toolchain.
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
& $Hipcc --version | Select-Object -First 3

if (Test-Path $Exe) {
    Remove-Item $Exe -Force
}

Write-Host ""
Write-Host "=== COMPILE FOR $Target ONLY ===" -ForegroundColor Cyan

$ExpectedDefine = "-DEXPECTED_GFX=`"$Target`""
$CompileArgs = @(
    "-x", "hip",
    "--offload-arch=$Target",
    "-O3",
    "-std=c++17",
    $ExpectedDefine,
    $Source,
    "-o", $Exe
)

& $Hipcc @CompileArgs

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Exe)) {
    throw "Compilation failed before physical execution."
}

# Fail closed if the output does not carry exactly the requested gfx103x bundle.
$Bytes = [System.IO.File]::ReadAllBytes($Exe)
$Ascii = [System.Text.Encoding]::ASCII.GetString($Bytes)
$ExpectedBundle = "hipv4-amdgcn-amd-amdhsa--$Target"

if (-not $Ascii.Contains($ExpectedBundle)) {
    throw "STOP: compiled executable does not contain the expected offload bundle $ExpectedBundle."
}

foreach ($OtherTarget in @("gfx1030", "gfx1031", "gfx1032")) {
    if ($OtherTarget -ne $Target) {
        $OtherBundle = "hipv4-amdgcn-amd-amdhsa--$OtherTarget"
        if ($Ascii.Contains($OtherBundle)) {
            throw "STOP: compiled executable also contains $OtherBundle. Qualification requires a single-target build."
        }
    }
}

$ExeHash = (Get-FileHash -Algorithm SHA256 $Exe).Hash
Write-Host ""
Write-Host "Compiled single-target executable: $Exe" -ForegroundColor Green
Write-Host "Target bundle: $ExpectedBundle"
Write-Host "Executable SHA-256: $ExeHash"

Write-Host ""
Write-Host "=== RUN ONE TINY GPU TILE ===" -ForegroundColor Cyan
& $Exe
$RunCode = $LASTEXITCODE

Write-Host ""
if ($RunCode -eq 0) {
    Write-Host "PHASE 1 PASSED for $Target." -ForegroundColor Green
    Write-Host "Preserve this complete output and executable hash as the bounded evidence record."
}
else {
    Write-Host "PHASE 1 did not pass for $Target (exit code $RunCode)." -ForegroundColor Yellow
    Write-Host "Preserve the complete output; do not retry blindly or change clocks, drivers, BIOS, TDR, or power settings."
}

exit $RunCode
