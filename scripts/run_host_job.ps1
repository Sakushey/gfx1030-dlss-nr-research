<#
run_host_job.ps1 -- reusable long-host-computation runner (Phase 16I).

Records producer PID, start time, periodic CPU time / RSS / log size+mtime
heartbeats, captures the exit code, and writes an explicit completion JSON
plus a DONE/FAILED marker.  The heartbeat file is the authoritative liveness
signal -- never a `tail -f` on the log.

Usage:
  .\run_host_job.ps1 -Name <job> -ArgList @('a','b') -WorkDir <dir> `
                     -PythonExe <exe> [-TimeoutSec N] [-HeartbeatSec N]

Writes into <WorkDir>\<Name>\ :
  stdout.log, stderr.log, heartbeat.csv, completion.json, DONE | FAILED
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string[]]$ArgList,
    [string]$WorkDir = (Join-Path $PSScriptRoot 'phase16i_host_jobs'),
    [string]$PythonExe = 'python',
    [int]$TimeoutSec = 0,
    [int]$HeartbeatSec = 30,
    [hashtable]$Env = @{}
)

$ErrorActionPreference = 'Stop'
$jobDir = Join-Path $WorkDir $Name
New-Item -ItemType Directory -Force -Path $jobDir | Out-Null

$stdout = Join-Path $jobDir 'stdout.log'
$stderr = Join-Path $jobDir 'stderr.log'
$hb     = Join-Path $jobDir 'heartbeat.csv'
$doneJ  = Join-Path $jobDir 'completion.json'
$doneM  = Join-Path $jobDir 'DONE'
$failM  = Join-Path $jobDir 'FAILED'

Remove-Item $doneM,$failM,$doneJ -ErrorAction SilentlyContinue

foreach ($k in $Env.Keys) { Set-Item -Path "Env:$k" -Value $Env[$k] }

$startUtc = (Get-Date).ToUniversalTime()
$argsQuoted = ($ArgList | ForEach-Object { '"' + ($_ -replace '"','\"') + '"' }) -join ' '

# Do NOT use `Start-Process -PassThru` here: on this host its returned
# Process object yields a $null ExitCode even after WaitForExit(), which
# labelled every successful job FAILED.  A directly-constructed
# System.Diagnostics.Process reports ExitCode reliably (verified: a child
# exiting 7 reads back as 7).  cmd.exe is interposed only to redirect the
# streams to files, since ProcessStartInfo cannot redirect to a path; cmd
# propagates the last command's exit code, so ExitCode is still the
# interpreter's.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'cmd.exe'
$psi.Arguments = '/c ' + $PythonExe + ' ' + $argsQuoted + `
                 ' > "' + $stdout + '" 2> "' + $stderr + '"'
$psi.WorkingDirectory = $PSScriptRoot
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $false
$psi.RedirectStandardError = $false
$proc = [System.Diagnostics.Process]::Start($psi)
$pid_ = $proc.Id

# `python` on this host resolves to the WindowsApps execution-alias shim,
# which immediately spawns the real interpreter as a CHILD.  The shim's own
# CPU/working set are ~0, so measuring only `$proc` reports a process that
# never appears to work.  Measure the whole subtree instead.
function Get-DescendantIds([int]$root) {
    $all = Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId `
             -ErrorAction SilentlyContinue
    $ids = New-Object System.Collections.Generic.HashSet[int]
    [void]$ids.Add($root)
    $added = $true
    while ($added) {
        $added = $false
        foreach ($p in $all) {
            if ($ids.Contains([int]$p.ParentProcessId) -and
                -not $ids.Contains([int]$p.ProcessId)) {
                [void]$ids.Add([int]$p.ProcessId); $added = $true
            }
        }
    }
    return $ids
}

"utc,elapsed_s,cpu_s,rss_mb,log_bytes,log_mtime_utc,alive" | Set-Content $hb
$t0 = Get-Date
$timedOut = $false
while (-not $proc.HasExited) {
    Start-Sleep -Seconds $HeartbeatSec
    $proc.Refresh()
    $el = [int]((Get-Date) - $t0).TotalSeconds
    $logLen = 0; $logMt = ''
    if (Test-Path $stdout) {
        $fi = Get-Item $stdout
        $logLen = $fi.Length
        $logMt = $fi.LastWriteTimeUtc.ToString('o')
    }
    $cpu = 0.0; $rss = 0.0
    try {
        foreach ($id in (Get-DescendantIds $pid_)) {
            $p = Get-Process -Id $id -ErrorAction SilentlyContinue
            if ($p) {
                $cpu += $p.CPU
                $rss += $p.WorkingSet64
            }
        }
        $cpu = [math]::Round($cpu,1)
        $rss = [math]::Round($rss / 1MB,1)
    } catch {}
    "$((Get-Date).ToUniversalTime().ToString('o')),$el,$cpu,$rss,$logLen,$logMt,$(-not $proc.HasExited)" |
        Add-Content $hb
    if ($TimeoutSec -gt 0 -and $el -ge $TimeoutSec) { $timedOut = $true; break }
}
if ($timedOut) {
    try { Stop-Process -Id $pid_ -Force -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Seconds 3
}
try { $proc.WaitForExit(15000) | Out-Null } catch {}
$exitCode = $null
try { $exitCode = $proc.ExitCode } catch {}
$endUtc = (Get-Date).ToUniversalTime()
$elapsed = [int]($endUtc - $startUtc).TotalSeconds

$status = if ($timedOut) { 'TIMEOUT' }
          elseif ($null -eq $exitCode) { 'UNKNOWN' }
          elseif ($exitCode -eq 0) { 'DONE' } else { 'FAILED' }
$rec = [ordered]@{
    job              = $Name
    pid              = $pid_
    python           = $PythonExe
    argv             = $ArgList
    env              = $Env
    start_utc        = $startUtc.ToString('o')
    end_utc          = $endUtc.ToString('o')
    elapsed_s        = $elapsed
    exit_code        = $exitCode
    timed_out        = $timedOut
    status           = $status
    stdout           = $stdout
    stderr           = $stderr
    heartbeat        = $hb
    stdout_bytes     = if (Test-Path $stdout) { (Get-Item $stdout).Length } else { 0 }
    stderr_bytes     = if (Test-Path $stderr) { (Get-Item $stderr).Length } else { 0 }
}
$rec | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 $doneJ
if ($status -eq 'DONE') { Set-Content -Encoding utf8 $doneM "DONE $($endUtc.ToString('o')) exit=0" }
else { Set-Content -Encoding utf8 $failM "$status $($endUtc.ToString('o')) exit=$exitCode" }
Write-Output "[$Name] $status exit=$exitCode elapsed=${elapsed}s pid=$pid_"
