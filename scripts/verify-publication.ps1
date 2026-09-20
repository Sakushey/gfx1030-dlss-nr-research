<#
.SYNOPSIS
    Publication verifier entry point (Windows).

.DESCRIPTION
    Fails closed on: obvious secrets, personal absolute paths, prohibited
    binary/artifact categories, oversized tracked files, invalid JSON/YAML,
    missing required community files, publication-manifest drift, broken
    README relative links, and stray bytecode caches.

    The checks themselves live in `scripts/verify_publication.py`, which is
    the single source of truth. It is deliberately cross-platform so the
    same logic runs locally and in CI (see .github/workflows). This script
    exists so Windows users have a native entry point and so the repository
    has a documented PowerShell verifier.

    Matched secret content is never printed: only path, category, and a
    redacted fingerprint.

.PARAMETER GitHead
    Verify the committed blob at HEAD instead of the working tree. This is
    the check that catches staging mistakes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify-publication.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\verify-publication.ps1 -GitHead
#>
[CmdletBinding()]
param(
    [switch]$GitHead
)

$ErrorActionPreference = "Stop"

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Repo = Split-Path -Parent $Here
$Py   = Join-Path $Here "verify_publication.py"

if (-not (Test-Path $Py)) {
    Write-Host "FAIL: verifier not found at $Py" -ForegroundColor Red
    exit 2
}

$Python = $null
foreach ($candidate in @("python", "python3", "py")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source; break }
}

if (-not $Python) {
    Write-Host "FAIL: no Python interpreter found on PATH." -ForegroundColor Red
    Write-Host "      This verifier needs Python 3.8+ (host-only; no GPU needed)."
    exit 2
}

$Args = @($Py)
if ($GitHead) { $Args += "--git-head" }

Write-Host "verify-publication (PowerShell wrapper)"
Write-Host "  repo:   $Repo"
Write-Host "  python: $Python"
Write-Host ""

Push-Location $Repo
try {
    & $Python @Args
    $code = $LASTEXITCODE
}
finally {
    Pop-Location
}

if ($code -eq 0) {
    Write-Host ""
    Write-Host "PUBLICATION VERIFY: PASS" -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host "PUBLICATION VERIFY: FAIL" -ForegroundColor Red
}

exit $code
