#!/usr/bin/env python3
"""Phase 16J -- per-job status record for the split J4 runs.

The Phase 16J J4 work is split per SWIN variant so a result is checkpointed
as each variant finishes instead of at the end of one long queue.  That only
helps if the state of each job is legible at a glance, so this emits, per
job: process id, CPU seconds, RSS, heartbeat freshness, the dispatch
currently executing, the dispatches already persisted, result paths and exit
status.

The "current dispatch" is derived, not guessed: the tool walks the job's
declared (tag, pattern, core) order and reports the first combination with
no result file on disk.  If that walk says a dispatch is current but the
process is gone, the job is reported as stopped mid-dispatch rather than
quietly shown as idle.

usage:
  p16j_job_status.py --dir phase16j_host_jobs \
      --job p16j_j4_variants:swin32t,swin64f,swin128f,swin256f:A,B \
      --job p16j_j4_swin256f:swin256f:A \
      [--out out/p16j_j4_status.json]

Host-only.  No GPU.  Reads only.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys

CORES = ("scratch", "lds")


def last_heartbeat(path):
    if not os.path.exists(path):
        return None
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    return rows[-1] if rows else None


def live_pids(driver_job):
    """Windows PIDs whose command line carries `--job <driver_job>`, via CIM.

    The match is anchored to the `--job` token and closed with a non-word
    boundary.  A plain substring test is not good enough here: the job
    names in use are `J4` and `J4_swin256f`, so `"J4" in cmdline` reports
    the swin256f producer as a member of the four-variant job and each
    job's CPU/RSS record silently absorbs the other's.

    The value may be quoted -- `run_host_job.ps1` passes `-ArgList` through
    and the resulting command line reads `"--job" "J4"` -- so an optional
    quote is allowed between the flag and the value.

    Two PIDs match per job: the `python` launcher shim on PATH and the real
    `pythoncore-3.14-64\\python.exe` interpreter it spawns.  They carry
    identical command lines.  Both are returned; the one holding the CPU
    time is the producer, and `producer_pid` names it.

    The culture is forced to invariant first.  On this machine PowerShell
    renders `[math]::Round(14.7, 1)` as `14,7`, and a comma is also this
    tool's field separator -- so without this the CPU/RSS columns either
    split into extra fields or fail to parse as numbers at all.  That is a
    real failure mode of this box, not a hypothetical one.
    """
    rx = re.compile(r"--job[\"'= ]+[\"']?" + re.escape(driver_job)
                    + r"(?![A-Za-z0-9_])")
    ps = ("[System.Threading.Thread]::CurrentThread.CurrentCulture = "
          "[System.Globalization.CultureInfo]::InvariantCulture; "
          "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | "
          "ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.ProcessId, "
          "[math]::Round($_.UserModeTime/10000000,0), "
          "[math]::Round($_.WorkingSetSize/1MB,1), $_.CommandLine }")
    try:
        p = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, timeout=60)
    except Exception:                                   # noqa: BLE001
        return []
    out = []
    for line in (p.stdout or "").splitlines():
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        pid, cpu, ws, cmd = parts
        if rx.search(cmd):
            out.append({"pid": int(pid), "cpu_s": float(cpu),
                        "rss_mb": float(ws), "cmd": cmd.strip()})
    return out


def result_path(outdir, job, tag, pat, core):
    return os.path.join(outdir, "p16j_%s_%s_%s_%s.json"
                        % (job.lower(), tag, pat, core))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="phase16j_host_jobs")
    ap.add_argument("--outdir", default="phase16j_pre_gta/out")
    ap.add_argument("--job", action="append", required=True,
                    help="hostdir:driverjob:tag1,tag2:pat1,pat2  -- hostdir is "
                         "the run_host_job name (its heartbeat/completion "
                         "live there); driverjob is the --job value passed to "
                         "p16j_j2_freeze.py, which is what the result files "
                         "are named after.  They differ, and conflating them "
                         "makes every result look missing.")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    report = {"jobs": [], "generated_from": a.dir}
    print("=" * 100)
    print("Phase 16J -- J4 per-job status")
    print("=" * 100)

    for spec in a.job:
        name, driver_job, tags_s, pats_s = spec.split(":")
        tags = [t for t in tags_s.split(",") if t]
        pats = [p for p in pats_s.split(",") if p]
        jdir = os.path.join(a.dir, name)
        hb_path = os.path.join(jdir, "heartbeat.csv")
        comp_path = os.path.join(jdir, "completion.json")

        hb = last_heartbeat(hb_path)
        comp = None
        if os.path.exists(comp_path):
            try:
                comp = json.load(open(comp_path, encoding="utf-8"))
            except Exception:                           # noqa: BLE001
                comp = {"status": "unreadable"}

        procs = live_pids(driver_job)
        done, current = [], None
        for tag in tags:
            for pat in pats:
                for core in CORES:
                    fp = result_path(a.outdir, driver_job, tag, pat, core)
                    if os.path.exists(fp):
                        done.append({"tag": tag, "pattern": pat, "core": core,
                                     "path": fp,
                                     "mtime": os.path.getmtime(fp)})
                    elif current is None:
                        current = {"tag": tag, "pattern": pat, "core": core}
        total = len(tags) * len(pats) * len(CORES)

        if comp is not None:
            state = comp.get("status", "?")
        elif procs:
            state = "RUNNING"
        elif current is not None:
            state = "STOPPED_MID_DISPATCH (no live process)"
        else:
            state = "FINISHED_NO_COMPLETION_JSON"

        producer = max(procs, key=lambda p: p["cpu_s"]) if procs else None

        print("\n%-22s %-28s %s" % (name, state, "dispatches %d/%d"
                                    % (len(done), total)))
        if procs:
            for p in procs:
                print("    pid=%-7d cpu=%-8.0fs rss=%-8.1f MB%s"
                      % (p["pid"], p["cpu_s"], p["rss_mb"],
                         "   <- producer" if p is producer else ""))
        else:
            print("    pid=-       (no live process)")
        if hb:
            print("    heartbeat: %s  elapsed=%ss cpu=%ss rss=%s MB alive=%s"
                  % (hb.get("utc"), hb.get("elapsed_s"), hb.get("cpu_s"),
                     hb.get("rss_mb"), hb.get("alive")))
        else:
            print("    heartbeat: (none)")
        if current:
            print("    CURRENT   %s / pattern %s / %s"
                  % (current["tag"], current["pattern"], current["core"]))
        for d in sorted(done, key=lambda x: x["mtime"]):
            print("    done      %-9s pattern %-2s %-7s  %s"
                  % (d["tag"], d["pattern"], d["core"],
                     os.path.basename(d["path"])))
        if comp:
            print("    exit_code=%s elapsed=%ss"
                  % (comp.get("exit_code"), comp.get("elapsed_s")))

        report["jobs"].append({
            "job": name, "driver_job": driver_job, "state": state,
            "tags": tags, "patterns": pats,
            "total_dispatches": total, "done": done, "current": current,
            "processes": procs, "producer_pid": producer["pid"] if producer
            else None, "producer_cpu_s": producer["cpu_s"] if producer
            else None, "producer_rss_mb": producer["rss_mb"] if producer
            else None, "heartbeat_last": hb,
            "completion": comp,
            "result_paths": [d["path"] for d in done],
        })

    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        json.dump(report, open(a.out, "w", encoding="utf-8"), indent=1)
        print("\nwrote " + a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
