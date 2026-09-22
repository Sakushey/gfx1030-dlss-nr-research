# Phase 16AT RAW_DUMP -- build script.
#
# HOST-ONLY. Every binary produced here is checked, after the build, to import
# no HIP runtime at all. The bridge DLL built here has
# -DDLSSNR_BRIDGE_TESTING, so its backend is the project's EXISTING no-GPU mock
# (phase10_hip_bridge/mock_hip6.dll). No GPU, no HIP call, no launch.
#
# Builds:
#   build/rawdump_bridge.dll              shipping recorder, capture point wired in
#   build/rawdump_bridge_<arm>.dll        one per capture mutant (arm name = the
#                                        defect the mutation models)
#   build/rehearsal_driver.exe            the no-GPU rehearsal driver
#   build/recorder_selftest.exe           the recorder's own checks
#
# Run:  powershell -ExecutionPolicy Bypass -File build_raw_dump.ps1
param(
    [string]$ClangPath = '<ROCM_ROOT>\6.4\bin\clang++.exe'
)
$ErrorActionPreference = "Stop"

$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path   # ...\p16at\raw_dump\src
$RawDump = Split-Path -Parent $Here                          # ...\p16at\raw_dump
$Root    = Split-Path -Parent (Split-Path -Parent $RawDump)  # project root
$Src     = $Here
$Build   = Join-Path $RawDump "build"
$Work    = Join-Path $RawDump "_work"
$Bridge  = Join-Path $Root "phase16_bridge_telemetry\src"

if (-not (Test-Path $ClangPath)) { throw "clang++ not found: $ClangPath" }
foreach ($d in @($Build, $Work)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}

$CFLAGS = @("-std=c++17", "-O1", "-DNDEBUG", "-D_CRT_SECURE_NO_WARNINGS",
            "-D_WINSOCK_DEPRECATED_NO_WARNINGS")
$INCS   = @("-I$Src", "-I$Bridge")

function Build-Pe([string]$Out, [string[]]$Sources, [string[]]$Extra) {
    if (Test-Path $Out) { Remove-Item $Out -Force }
    $a = $CFLAGS + $INCS + $Extra + $Sources + @("-o", $Out)
    Write-Host ("  clang++ -> {0}" -f (Split-Path -Leaf $Out)) -ForegroundColor DarkCyan
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & $ClangPath @a 2>&1 | ForEach-Object { Write-Host "    $_" }
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($rc -ne 0 -or -not (Test-Path $Out)) {
        throw "build failed for $Out (exit $rc)"
    }
    return $Out
}

# ---------------------------------------------------------------- generation
Write-Host "--- generators (all three must pass before anything is built) ---" -ForegroundColor Cyan
& python (Join-Path $Src "p16at_emit_blob_table.py") --check
if ($LASTEXITCODE -ne 0) { throw "blob table is stale or missing" }
& python (Join-Path $Src "p16at_apply_capture_point.py")
if ($LASTEXITCODE -ne 0) { throw "capture point application refused" }
& python (Join-Path $Src "p16at_emit_mutants.py")
if ($LASTEXITCODE -ne 0) { throw "mutant generation refused" }

$Transformed = Join-Path $Work "amdhip64_7_capture.cpp"
if (-not (Test-Path $Transformed)) { throw "transformed bridge source missing" }

# ------------------------------------------------------------------- builds
Write-Host ""
Write-Host "--- bridge with the capture point wired in ---" -ForegroundColor Cyan
$regsrc = Join-Path $Bridge "registry_ident.cpp"
$shipping = Join-Path $Src "raw_dump_recorder.cpp"
$bridgeDll = Build-Pe (Join-Path $Build "rawdump_bridge.dll") `
    @($Transformed, $regsrc, $shipping) @("-DDLSSNR_BRIDGE_TESTING", "-shared")

Write-Host ""
Write-Host "--- one bridge per capture mutant ---" -ForegroundColor Cyan
$mutRoot = Join-Path $Work "mutants"
$mutNames = @("shift", "truncate", "declared_size", "ordinal", "identity")
$mutDlls = @{}
foreach ($m in $mutNames) {
    $msrc = Join-Path $mutRoot "$m\raw_dump_recorder.cpp"
    if (-not (Test-Path $msrc)) { throw "mutant source missing: $msrc" }
    $mutDlls[$m] = Build-Pe (Join-Path $Build "rawdump_bridge_$m.dll") `
        @($Transformed, $regsrc, $msrc) @("-DDLSSNR_BRIDGE_TESTING", "-shared")
}

Write-Host ""
Write-Host "--- rehearsal driver and recorder self-test ---" -ForegroundColor Cyan
$driver = Build-Pe (Join-Path $Build "rehearsal_driver.exe") `
    @((Join-Path $Src "rehearsal_driver.cpp")) @()
$selftest = Build-Pe (Join-Path $Build "recorder_selftest.exe") `
    @((Join-Path $Src "recorder_selftest.cpp"), $shipping) @()

# ------------------------------------------------ import-table assertion
# A build that silently linked a HIP runtime would be an experiment whose stated
# mechanism is not its real one. Read the import table back out of every PE.
function Get-PeImports([string]$Path) {
    $b = [System.IO.File]::ReadAllBytes($Path)
    if ($b.Length -lt 0x40) { throw "not a PE: too small" }
    $peOff = [System.BitConverter]::ToInt32($b, 0x3C)
    if ([System.Text.Encoding]::ASCII.GetString($b, $peOff, 4) -ne "PE`0`0") { throw "not a PE" }
    $coff = $peOff + 4
    $nSec = [System.BitConverter]::ToUInt16($b, $coff + 2)
    $optSz = [System.BitConverter]::ToUInt16($b, $coff + 16)
    $opt = $coff + 20
    $magic = [System.BitConverter]::ToUInt16($b, $opt)
    if ($magic -eq 0x20B) { $dd = $opt + 112 }
    elseif ($magic -eq 0x10B) { $dd = $opt + 96 }
    else { throw "unknown PE magic" }
    $impRva = [System.BitConverter]::ToUInt32($b, $dd + 8)
    if ($impRva -eq 0) { return @() }
    $secTab = $opt + $optSz
    $secs = @()
    for ($i = 0; $i -lt $nSec; $i++) {
        $s = $secTab + $i * 40
        $secs += [pscustomobject]@{
            Va = [System.BitConverter]::ToUInt32($b, $s + 12)
            Vs = [System.BitConverter]::ToUInt32($b, $s + 8)
            Pr = [System.BitConverter]::ToUInt32($b, $s + 20)
            Rs = [System.BitConverter]::ToUInt32($b, $s + 16) }
    }
    $names = @()
    $d = $impRva
    while ($true) {
        $f = $null
        foreach ($s in $secs) {
            $span = [Math]::Max($s.Vs, $s.Rs)
            if ($d -ge $s.Va -and $d -lt $s.Va + $span) { $f = $s.Pr + ($d - $s.Va); break }
        }
        if ($null -eq $f) { break }
        $orig = [System.BitConverter]::ToUInt32($b, $f)
        $nameRva = [System.BitConverter]::ToUInt32($b, $f + 12)
        if ($orig -eq 0 -and $nameRva -eq 0) { break }
        foreach ($s in $secs) {
            $span = [Math]::Max($s.Vs, $s.Rs)
            if ($nameRva -ge $s.Va -and $nameRva -lt $s.Va + $span) {
                $nf = $s.Pr + ($nameRva - $s.Va); $e = $nf
                while ($e -lt $b.Length -and $b[$e] -ne 0) { $e++ }
                $names += [System.Text.Encoding]::ASCII.GetString($b, $nf, $e - $nf)
                break
            }
        }
        $d += 20
    }
    return $names
}

Write-Host ""
Write-Host "--- import-table assertion: no HIP runtime anywhere ---" -ForegroundColor Cyan
$manifest = @()
$bad = 0
$all = @($bridgeDll) + @($mutDlls.Values) + @($driver, $selftest)
foreach ($p in $all) {
    $imps = @(Get-PeImports $p)
    $lower = $imps | ForEach-Object { $_.ToLower() }
    $hip = @($lower | Where-Object { $_ -like "*hip*" })
    $sha = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
    $ok = ($hip.Count -eq 0)
    if (-not $ok) { $bad++; Write-Host "    !! imports $($hip -join ', ')" -ForegroundColor Red }
    Write-Host ("  {0,-34} {1,8} B  imports: {2}" -f (Split-Path -Leaf $p), (Get-Item $p).Length, ($imps -join ', '))
    $manifest += [pscustomobject]@{ file = (Split-Path -Leaf $p); sha256 = $sha
                                    bytes = (Get-Item $p).Length; imports = $imps
                                    imports_any_hip_runtime = ($hip.Count -gt 0) }
}
if ($bad) { throw "$bad build(s) import a HIP runtime" }

# NOT Set-Content -Encoding UTF8: in PowerShell 5.1 that emits a UTF-8 BOM, and
# a leading EF BB BF makes the file unreadable to a standard JSON reader
# ("Unexpected UTF-8 BOM"). WriteAllText with a BOM-less UTF8Encoding does not.
$manifestPath = Join-Path $Build "raw_dump_build_manifest.json"
$manifestJson = $manifest | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($manifestPath, $manifestJson,
                               (New-Object System.Text.UTF8Encoding($false)))
$mb = [System.IO.File]::ReadAllBytes($manifestPath)
if ($mb.Length -ge 3 -and $mb[0] -eq 0xEF -and $mb[1] -eq 0xBB -and $mb[2] -eq 0xBF) {
    throw "build manifest still carries a UTF-8 BOM"
}
Write-Host ""
Write-Host "RAW_DUMP_BUILD_OK  ($($all.Count) binaries, none import a HIP runtime)" -ForegroundColor Yellow
exit 0
