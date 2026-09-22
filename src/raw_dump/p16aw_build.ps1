# Phase 16AW RAW_DUMP -- build script for the REPAIRED capture layer.
#
# HOST-ONLY. Both binaries are checked, after the build, to import no HIP runtime
# at all. The bridge DLL built here has -DDLSSNR_BRIDGE_TESTING, so its backend
# resolves to the project's EXISTING no-GPU mock (phase10_hip_bridge/mock_hip6.dll)
# and no launch can reach a device. The rehearsal leaves the launch gate OFF, and
# the capture point sits BEFORE the gate's early return, so every rehearsal launch
# fires the capture and then returns without a submission.
#
# Builds:
#   build/rawdump_bridge_16aw.dll   the bridge with the 16AW capture point wired in
#   build/p16aw_driver.exe          the no-GPU rehearsal driver (also links the
#                                   layer directly, for the frame machine replay
#                                   and the layer's own self-test)
#
# Run:  powershell -ExecutionPolicy Bypass -File p16aw_build.ps1
param(
    [string]$ClangPath = '<ROCM_ROOT>\6.4\bin\clang++.exe'
)
$ErrorActionPreference = "Stop"

$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path   # ...\p16aw\raw_dump
$RawDump = $Here
$Root    = Split-Path -Parent (Split-Path -Parent $RawDump)  # project root
$Src     = Join-Path $RawDump "src"
$Build   = Join-Path $RawDump "build"
$Work    = Join-Path $RawDump "_work"
$Bridge  = Join-Path $Root "phase16_bridge_telemetry\src"

if (-not (Test-Path $ClangPath)) { throw "clang++ not found: $ClangPath" }
foreach ($d in @($Build, $Work)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}

$CFLAGS = @("-std=c++17", "-O1", "-DNDEBUG", "-D_CRT_SECURE_NO_WARNINGS")
$INCS   = @("-I$Src", "-I$Bridge")

function Build-Pe([string]$Out, [string[]]$Sources, [string[]]$Extra) {
    if (Test-Path $Out) { Remove-Item $Out -Force }
    $a = $CFLAGS + $INCS + $Extra + $Sources + @("-o", $Out)
    Write-Host ("  clang++ -> {0}" -f (Split-Path -Leaf $Out)) -ForegroundColor DarkCyan
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & $ClangPath @a 2>&1 | ForEach-Object { Write-Host "    $_" }
    $rc = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($rc -ne 0 -or -not (Test-Path $Out)) { throw "build failed for $Out (exit $rc)" }
    return $Out
}

# ---------------------------------------------------------------- generation
Write-Host "--- generators (both must pass before anything is built) ---" -ForegroundColor Cyan
& python (Join-Path $RawDump "p16aw_author_argspec.py") --check
if ($LASTEXITCODE -ne 0) { throw "argument-spec table is stale or missing" }
& python (Join-Path $Src "p16aw_apply_capture_point.py")
if ($LASTEXITCODE -ne 0) { throw "capture point application refused" }

$Transformed = Join-Path $Work "amdhip64_7_16aw.cpp"
if (-not (Test-Path $Transformed)) { throw "transformed bridge source missing" }

# ------------------------------------------------------------------- builds
Write-Host ""
Write-Host "--- bridge with the repaired capture point wired in ---" -ForegroundColor Cyan
$regsrc   = Join-Path $Bridge "registry_ident.cpp"
$repair   = Join-Path $Src "raw_dump_repair_16aw.cpp"
$bridgeDll = Build-Pe (Join-Path $Build "rawdump_bridge_16aw.dll") `
    @($Transformed, $regsrc, $repair) @("-DDLSSNR_BRIDGE_TESTING", "-shared")

Write-Host ""
Write-Host "--- rehearsal driver ---" -ForegroundColor Cyan
$driver = Build-Pe (Join-Path $Build "p16aw_driver.exe") `
    @((Join-Path $Src "p16aw_driver.cpp"), $repair) @()

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
$all = @($bridgeDll, $driver)
foreach ($p in $all) {
    $imps = @(Get-PeImports $p)
    $lower = $imps | ForEach-Object { $_.ToLower() }
    $hip = @($lower | Where-Object { $_ -like "*hip*" })
    $sha = (Get-FileHash $p -Algorithm SHA256).Hash.ToLower()
    $ok = ($hip.Count -eq 0)
    if (-not $ok) { $bad++; Write-Host "    !! imports $($hip -join ', ')" -ForegroundColor Red }
    Write-Host ("  {0,-30} {1,9} B  imports: {2}" -f (Split-Path -Leaf $p), (Get-Item $p).Length, ($imps -join ', '))
    $manifest += [pscustomobject]@{ file = (Split-Path -Leaf $p); sha256 = $sha
                                    bytes = (Get-Item $p).Length; imports = $imps
                                    imports_any_hip_runtime = ($hip.Count -gt 0) }
}
if ($bad) { throw "$bad build(s) import a HIP runtime" }

# NOT Set-Content -Encoding UTF8: in PowerShell 5.1 that emits a UTF-8 BOM, and a
# leading EF BB BF makes the file unreadable to a standard JSON reader. WriteAllText
# with a BOM-less UTF8Encoding does not.
$manifestPath = Join-Path $Build "raw_dump_16aw_build_manifest.json"
$manifestJson = $manifest | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($manifestPath, $manifestJson,
                               (New-Object System.Text.UTF8Encoding($false)))
$mb = [System.IO.File]::ReadAllBytes($manifestPath)
if ($mb.Length -ge 3 -and $mb[0] -eq 0xEF -and $mb[1] -eq 0xBB -and $mb[2] -eq 0xBF) {
    throw "build manifest still carries a UTF-8 BOM"
}
Write-Host ""
Write-Host "RAW_DUMP_16AW_BUILD_OK  ($($all.Count) binaries, none import a HIP runtime)" -ForegroundColor Yellow
exit 0
