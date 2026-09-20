$ErrorActionPreference = "Stop"

$HipRoot = "C:\Program Files\AMD\ROCm\6.4"
$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source  = Join-Path $Here "p16f_swin_host.cpp"
$Exe     = Join-Path $Here "p16f_swin_host.exe"

if (-not (Test-Path $HipRoot)) {
    throw "HIP 6.4 root not found: $HipRoot"
}
$Clang = Join-Path $HipRoot "bin\clang++.exe"
if (-not (Test-Path $Clang)) {
    throw "clang++.exe not found at $Clang"
}

$env:HIP_PATH = $HipRoot
$env:HIP_PLATFORM = "amd"
$env:Path = "$($HipRoot)\bin;$env:Path"

if (Test-Path $Exe) {
    Remove-Item $Exe -Force
}

& $Clang "-x" "hip" "--hip-path=$HipRoot" "-O2" "-std=c++17" $Source "-o" $Exe
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Exe)) {
    throw "Host harness compilation failed (exit $LASTEXITCODE)."
}
Write-Host "Built: $Exe"
exit 0
