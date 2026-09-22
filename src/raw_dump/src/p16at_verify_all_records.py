#!/usr/bin/env python3
"""Phase 16AT RAW_DUMP -- parse every emitted record with a STANDARD JSON reader.

WHY THIS EXISTS
  p16at_run_controls.py re-parsed the seven top-level ARTEFACTS this phase
  writes. It never parsed the RECORDS the recorder produces, and six of those
  were not valid RFC-8259 JSON: two carried a Windows path with unescaped
  backslashes, two carried a hex literal (`[0x0,0x20]`), one carried an
  unescaped path in driver_result.json, and the build manifest carried a UTF-8
  BOM. "Verify the artefact, not the exit code" -- the artefacts were checked,
  the product was not.

WHAT IT DOES
  Decodes every *.json under each --root as strict UTF-8 (a BOM is a FAILURE,
  not something to skip past via utf-8-sig) and parses it with the standard
  `json` module. One failure anywhere is a failure of the whole run.

VACUITY GUARD
  A scan that finds zero files FAILS. A verifier that passes because it looked
  at nothing is the defect this project has recorded more than once.

CAN-FAIL PROOF
  --expect-reject points at a directory of files that are KNOWN to be
  unparseable (quarantined from before the fix). Every one of them must be
  REJECTED. If any of them parses, the verifier cannot detect the defect it
  exists to detect, and the run fails with exit 2. This is run every time, so
  the proof cannot rot.

USAGE
  python p16at_verify_all_records.py --root out --root build \
      --expect-reject _work/known_bad_records \
      --json _work/all_records_parse.json
"""
import argparse
import glob
import hashlib
import json
import os
import sys

SCHEMA = "p16at/all-records-parse/1"

BOM = b"\xef\xbb\xbf"


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def try_parse(path):
    """Return (ok, detail). Strict: utf-8 only, no BOM tolerance."""
    raw = open(path, "rb").read()
    has_bom = raw[:3] == BOM
    if has_bom:
        return False, {
            "error_type": "UTF8BOM",
            "error_message": "Unexpected UTF-8 BOM (a standard JSON reader "
                             "cannot read this file)",
            "line": 1, "column": 1, "bom": True,
        }
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        return False, {"error_type": "UnicodeDecodeError",
                       "error_message": str(exc), "line": None, "column": None,
                       "bom": False}
    try:
        json.loads(text)
        return True, {"error_type": None, "error_message": None,
                      "line": None, "column": None, "bom": False}
    except json.JSONDecodeError as exc:
        return False, {"error_type": "JSONDecodeError",
                       "error_message": exc.msg, "line": exc.lineno,
                       "column": exc.colno, "bom": False}


def scan(paths):
    """Every *.json under each root, sorted, de-duplicated."""
    found = []
    for root in paths:
        if os.path.isfile(root):
            found.append(os.path.abspath(root))
            continue
        for dirpath, _dirnames, filenames in os.walk(root):
            for name in filenames:
                if name.endswith(".json"):
                    found.append(os.path.abspath(os.path.join(dirpath, name)))
    return sorted(set(found))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", action="append", default=[],
                    help="directory (or single file) to scan; repeatable")
    ap.add_argument("--expect-reject", default=None,
                    help="directory of files KNOWN to be unparseable; every one "
                         "must be rejected or the can-fail proof fails")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--min-files", type=int, default=1,
                    help="a scan finding fewer than this many files is vacuous "
                         "and FAILS")
    ap.add_argument("--quarantine-to", default=None,
                    help="copy every failing file (byte-exact) into this "
                         "directory and write a manifest there")
    args = ap.parse_args()

    if not args.root:
        args.root = ["out"]
    out = {"schema": SCHEMA,
           "scan_roots": [os.path.abspath(r) for r in args.root]}

    files = scan(args.root)
    out["n_files_scanned"] = len(files)
    out["min_files_required"] = args.min_files
    out["vacuity_guard_passed"] = len(files) >= args.min_files

    failures = []
    parsed = 0
    for path in files:
        ok, detail = try_parse(path)
        if ok:
            parsed += 1
        else:
            failures.append({
                "path": path,
                "sha256": sha256_file(path),
                "bytes": os.path.getsize(path),
                **detail,
            })
    out["n_parsed"] = parsed
    out["n_failed"] = len(failures)
    out["failures"] = failures

    # ---- the can-fail proof -------------------------------------------
    proof = {"supplied": args.expect_reject is not None, "n_expected": 0,
             "n_rejected": 0, "n_wrongly_parsed": 0, "files": [],
             "verifier_can_fail": False}
    if args.expect_reject:
        bad = scan([args.expect_reject])
        proof["root"] = os.path.abspath(args.expect_reject)
        proof["n_expected"] = len(bad)
        for path in bad:
            ok, detail = try_parse(path)
            proof["files"].append({
                "path": path,
                "sha256": sha256_file(path),
                "rejected": (not ok),
                "error_type": detail["error_type"],
                "error_message": detail["error_message"],
                "line": detail["line"],
                "column": detail["column"],
            })
            if ok:
                proof["n_wrongly_parsed"] += 1
            else:
                proof["n_rejected"] += 1
        proof["verifier_can_fail"] = (proof["n_expected"] > 0
                                      and proof["n_wrongly_parsed"] == 0)
    out["can_fail_proof"] = proof

    # ---- quarantine (optional) ----------------------------------------
    if args.quarantine_to:
        qdir = os.path.abspath(args.quarantine_to)
        os.makedirs(qdir, exist_ok=True)
        manifest = []
        for f in failures:
            base = os.path.basename(f["path"])
            dest = os.path.join(qdir, base)
            # Collision-safe: driver_result.json exists in every arm directory,
            # so a bare basename is not unique across failures.
            if os.path.exists(dest) and sha256_file(dest) != f["sha256"]:
                dest = os.path.join(qdir, f["sha256"][:8] + "__" + base)
            with open(f["path"], "rb") as src:
                blob = src.read()
            with open(dest, "wb") as dst:
                dst.write(blob)
            manifest.append({
                "quarantined_path": dest,
                "original_path": f["path"],
                "sha256": f["sha256"],
                "bytes": f["bytes"],
                "error_type": f["error_type"],
                "error_message": f["error_message"],
                "line": f["line"],
                "column": f["column"],
            })
        mpath = os.path.join(os.path.dirname(qdir),
                             os.path.basename(qdir) + "_MANIFEST.json")
        with open(mpath, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"schema": "p16at/known-bad-records/1",
                       "why": "Records emitted BEFORE the RFC-8259 escaping "
                              "fix. Kept byte-exact so the verifier's can-fail "
                              "proof stays reproducible.",
                       "n_files": len(manifest), "files": manifest},
                      fh, indent=1)
            fh.write("\n")
        out["quarantined"] = {"dir": qdir, "n_files": len(manifest),
                              "manifest": mpath}

    ok = (out["vacuity_guard_passed"] and out["n_failed"] == 0
          and (proof["verifier_can_fail"] if proof["supplied"] else True))
    out["verdict"] = ("ALL_EMITTED_RECORDS_PARSE" if ok
                      else "SOME_EMITTED_RECORD_DOES_NOT_PARSE")
    out["ok"] = ok

    print("--- every emitted .json, standard reader ---")
    print("  scanned      %d file(s) under %d root(s)"
          % (out["n_files_scanned"], len(args.root)))
    print("  parsed       %d" % out["n_parsed"])
    print("  FAILED       %d" % out["n_failed"])
    for f in failures:
        print("    %s" % f["path"])
        print("      %s: %s (line %s column %s)"
              % (f["error_type"], f["error_message"], f["line"], f["column"]))
    if not out["vacuity_guard_passed"]:
        print("  VACUOUS: found %d file(s), fewer than the required %d"
              % (out["n_files_scanned"], args.min_files))
    if proof["supplied"]:
        print("--- can-fail proof (known-bad must be REJECTED) ---")
        print("  known-bad files   %d" % proof["n_expected"])
        print("  rejected          %d" % proof["n_rejected"])
        print("  wrongly parsed    %d" % proof["n_wrongly_parsed"])
        for f in proof["files"]:
            print("    %-9s %s" % ("REJECTED" if f["rejected"] else "PARSED!",
                                   os.path.basename(f["path"])))
            print("      %s: %s" % (f["error_type"], f["error_message"]))
        print("  verifier_can_fail %s" % proof["verifier_can_fail"])
    print("  VERDICT      %s" % out["verdict"])

    if args.json_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)),
                    exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(out, fh, indent=1)
            fh.write("\n")
        print("  wrote        %s" % os.path.abspath(args.json_out))

    if not out["vacuity_guard_passed"]:
        return 3
    if not ok:
        return 2 if (proof["supplied"] and not proof["verifier_can_fail"]) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
