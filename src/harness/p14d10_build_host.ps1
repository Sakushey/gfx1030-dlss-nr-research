$ErrorActionPreference = "Stop"

$HipRoot = "C:\Program Files\AMD\ROCm\6.4"
$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$Source  = Join-Path $Here "p14d10_entry_probe_host.cpp"
$Exe     = Join-Path $Here "p14d10_entry_probe_host.exe"

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
    Write-Host "STOP: Microsoft C++ build tools are missing/not active."
    exit 10
}

if (Test-Path $Exe) {
    Remove-Item $Exe -Force
}

& $Clang "-x" "hip" "--hip-path=$HipRoot" "-O2" "-std=c++17" $Source "-o" $Exe
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Exe)) {
    throw "Host harness compilation failed (exit $LASTEXITCODE)."
}
Write-Host "Built: $Exe"
exit 0
