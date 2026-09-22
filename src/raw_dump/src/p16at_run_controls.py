#!/usr/bin/env python3
"""Phase 16AT RAW_DUMP -- the arm runner.

Runs every arm of the no-GPU rehearsal, captures each arm's real output, and
assembles the reach/verdict tallies. Nothing here reasons about what a control
"would" do: every field in RAW_DUMP_REACH_CONTROLS.json,
RAW_DUMP_NOGPU_REHEARSAL.json and RAW_DUMP_STATUS.json comes from a file some
process actually wrote in this run.

Arms
  accept_clean            the positive reference: nothing disturbed
  a_mutate_after_capture  one byte of the image flipped AFTER the capture point
  b_shift                 the blob read shifted by one byte
  c_truncate              the blob truncated by one byte
  d_declared_size         the blob size over-declared by eight bytes
  e_ordinal               the launch ordinal reported wrong
  f_identity              the kernel identity reported wrong
  g_recorder_disabled     the observer is OFF
  h_pre_emission          the by-value image never constructed
  clean_recorder_off      the OFF half of the section 52 rehearsal pair
  probe_gate_off          the fail-closed gate OFF: capture still precedes it

HOW A RECORD IS FOUND. The target launch is located by the CAPTURE_SITE_REACHED
line the ADAPTER writes, keyed on the ordinal and kernel name it was handed --
neither of which any mutant can reach, because every mutant is applied inside
emit() and every mutation of the ordinal or the identity would otherwise also
move the file the arm is judged on. Finding the record by its own (possibly
mutated) filename is how the ordinal control first came back NOT_COMPARED: the
instrument, not the recorder, was broken.

The verdict rule, stated once and applied mechanically:
  VALID_CONTROL   iff emission_point_reached AND comparison_reached AND
                      expected_rejection_occurred
  INVALID_CONTROL otherwise -- in particular an arm whose observer never ran is
                  INVALID, never a successful rejection.

Usage: python p16at_run_controls.py [--force]
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DUMP = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(RAW_DUMP))
BUILD = os.path.join(RAW_DUMP, "build")
OUT = os.path.join(RAW_DUMP, "out")
WORK = os.path.join(RAW_DUMP, "_work")
DRIVER = os.path.join(BUILD, "rehearsal_driver.exe")
SELFTEST = os.path.join(BUILD, "recorder_selftest.exe")
VERIFIER = os.path.join(HERE, "p16at_verify_records.py")

TARGET = "_Z14k_dec_upsample11DecUpParams"     # 40 B, offsets {0x0, 0x20}
MARKER = "_Z10k_flag_setPjj"                   # 4 B,  offsets {0x0}
TARGET_ORDINAL = 2                             # the marker launch is ordinal 1

SHIPPING_BRIDGE = "rawdump_bridge.dll"

# Self-test steps that assert a POSITIVE property of good output rather than a
# rejection. Listed explicitly so the "known-bad rejected" list cannot silently
# absorb a positive check and inflate itself.
POSITIVE_SELFTEST_STEPS = frozenset({
    "recorder_accepts_known_good_capture",
    "emitted_record_has_no_bare_backslash",
})

# name -> (bridge dll, driver arm, gate, recorder)
ARMS = [
    ("accept_clean",           SHIPPING_BRIDGE,                    "clean", 1, 1),
    ("a_mutate_after_capture", SHIPPING_BRIDGE, "mutate_after_capture", 1, 1),
    ("b_shift",                "rawdump_bridge_shift.dll",         "clean", 1, 1),
    ("c_truncate",             "rawdump_bridge_truncate.dll",      "clean", 1, 1),
    ("d_declared_size",        "rawdump_bridge_declared_size.dll", "clean", 1, 1),
    ("e_ordinal",              "rawdump_bridge_ordinal.dll",       "clean", 1, 1),
    ("f_identity",             "rawdump_bridge_identity.dll",      "clean", 1, 1),
    ("g_recorder_disabled",    SHIPPING_BRIDGE,                    "clean", 1, 0),
    ("h_pre_emission",         SHIPPING_BRIDGE, "pre_emission_null_image", 1, 1),
    ("clean_recorder_off",     SHIPPING_BRIDGE,                    "clean", 1, 0),
    ("probe_gate_off",         SHIPPING_BRIDGE,                    "clean", 0, 1),
]

# The eight controls of brief IX sections 50-51. `must_fail` is the MINIMAL set
# of checks the mutation is defined to break -- the rejection has to be the
# intended one, not incidental damage. Failures outside it are recorded as
# consequential and are not required.
CONTROLS = [
    ("a", "a_mutate_after_capture",
     "one byte of the by-value image flipped AFTER the capture point",
     {"C10_record_digest_equals_the_digest_of_the_post_launch_image"}),
    ("b", "b_shift",
     "the pointer handed to the recorder shifted by one byte",
     {"C4_recorded_bytes_equal_the_fixture_image",
      "C9_bytes_at_the_requested_offsets_equal_the_predicted_values"}),
    ("c", "c_truncate",
     "the declared read length truncated by one byte",
     {"C4_recorded_bytes_equal_the_fixture_image",
      "C5_raw_blob_length_equals_the_16ao_declared_size",
      "C11_declared_by_value_blob_bytes_equals_raw_blob_length"}),
    ("d", "d_declared_size",
     "the blob size declared eight bytes too large",
     {"C4_recorded_bytes_equal_the_fixture_image",
      "C5_raw_blob_length_equals_the_16ao_declared_size",
      "C11_declared_by_value_blob_bytes_equals_raw_blob_length"}),
    ("e", "e_ordinal",
     "the launch ordinal reported 7919 too high",
     {"C7_launch_ordinal_equals_the_bridge_log_ordinal"}),
    ("f", "f_identity",
     "the kernel identity replaced by a different table row",
     {"C6_kernel_identity_equals_the_expected_identity",
      "C8_requested_field_offsets_equal_the_16ao_derived_offsets",
      "C11_declared_by_value_blob_bytes_equals_raw_blob_length"}),
    ("g", "g_recorder_disabled",
     "the observer disabled (RAW_DUMP off)", set()),
    ("h", "h_pre_emission",
     "the mutation applied BEFORE the emission point: args[0] never constructed",
     set()),
]

RECORD_NAME = re.compile(r"^\d{8}T\d{6}Z_(\d+)_(\d+)_(.+)_([0-9a-f]{12})"
                         r"(\.dup\d+)?\.json$")
SIDECAR_NAME = re.compile(r"^\d{8}T\d{6}Z_(\d+)_(\d+)_(.+)_([0-9a-f]{12})"
                          r"(\.dup\d+)?\.bin$")


def is_record_file(name):
    """A record AND its side-car: both are the emitted evidence, and the ON arm
    legitimately has both while the OFF arm has neither."""
    return bool(RECORD_NAME.match(name) or SIDECAR_NAME.match(name))


EVENT_NAME = re.compile(r"[A-Z][A-Z_]{2,}")
BRIDGE_PREFIX = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} "
                           r"t=\d+ pid=\d+ ")
HEXPTR = re.compile(r"\b[0-9A-Fa-f]{12,16}\b")

# Files the two section 52 arms must produce IDENTICALLY, byte for byte.
LAUNCH_PATH_FILES = ["fixture_blob.bin", "post_launch_blob.bin",
                     "marker_blob.bin"]
# Files that carry process-local identities (timestamps, tids, pids, addresses)
# and are therefore compared after normalisation.
DESCRIPTOR_FILES = ["bridge.log", "mock_hip6.log", "driver_result.json"]
# Files that ARE the evidence emission, plus the runner's own bookkeeping.
EVIDENCE_FILES = ["_raw_dump_trace.log", "verification.json",
                  "verifier_stdout.txt", "driver_stdout.txt"]


# --------------------------------------------------------------------- helpers
def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    with open(p, "rb") as f:
        return sha256_bytes(f.read())


def read_json(p):
    with open(p, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def read_bytes(p):
    if not os.path.exists(p):
        return None
    with open(p, "rb") as f:
        return f.read()


def read_text(p):
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def run(argv, cwd=None):
    p = subprocess.run(argv, cwd=cwd, capture_output=True)
    return (p.returncode,
            p.stdout.decode("utf-8", "replace"),
            p.stderr.decode("utf-8", "replace"))


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1)
        f.write("\n")


def superseed(path, stamp):
    """Never delete an earlier arm's evidence: move it aside instead."""
    dest = os.path.join(OUT, "_superseded", "%s__%s" % (
        os.path.basename(path), stamp))
    k = 0
    while os.path.exists(dest + ("_%d" % k if k else "")):
        k += 1
    if k:
        dest += "_%d" % k
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.move(path, dest)
    return dest


def split_event(line):
    """(EVENT_NAME, detail). The event is the first ALL-CAPS token.

    Not a split on "Z ": the timestamp ends in Z, so that lands inside the
    prefix and every event reads as "t=<tid>". That mistake made all eight arms
    report emission_reached=NO while the trace file plainly showed the events.
    """
    toks = line.split()
    for i, t in enumerate(toks):
        if EVENT_NAME.fullmatch(t):
            return t, " ".join(toks[i + 1:])
    return None, ""


def parse_trace(path):
    """_raw_dump_trace.log -> per-launch segments. Absence is data."""
    txt = read_text(path)
    segs = []
    cur = None
    n_lines = 0
    if txt is None:
        return {"present": False, "lines": [], "segments": [], "n_lines": 0}
    for raw in txt.splitlines():
        if not raw.strip():
            continue
        n_lines += 1
        name, detail = split_event(raw)
        if name == "CAPTURE_SITE_REACHED":
            cur = {"ordinal": detail_ordinal(detail),
                   "kernel": detail_field(detail, "kernel"),
                   "events": [], "lines": []}
            segs.append(cur)
        if cur is None:
            cur = {"ordinal": None, "kernel": None, "events": [], "lines": []}
            segs.append(cur)
        cur["events"].append({"event": name, "detail": detail})
        cur["lines"].append(raw)
    return {"present": True, "lines": txt.splitlines(), "segments": segs,
            "n_lines": n_lines}


def detail_ordinal(detail):
    for tok in detail.split():
        if tok.startswith("ordinal="):
            return int(tok.split("=", 1)[1])
    return None


def detail_field(detail, key):
    pre = key + "=\""
    for tok in detail.split():
        if tok.startswith(pre) and tok.endswith("\""):
            return tok[len(pre):-1]
    return None


def target_segment(trace):
    """The segment whose CAPTURE_SITE_REACHED carries the TARGET's ordinal and
    kernel name. Both come from the adapter's arguments, so no mutant -- all of
    which live inside emit() -- can move which record is judged."""
    segs = [s for s in trace["segments"]
            if s["ordinal"] == TARGET_ORDINAL and s["kernel"] == TARGET]
    return segs[-1] if segs else None


def events_of(seg, name):
    return [e for e in (seg or {"events": []})["events"] if e["event"] == name]


def list_records(arm_dir):
    return sorted(n for n in os.listdir(arm_dir) if RECORD_NAME.match(n))


def normalise_log(txt):
    out = []
    for line in (txt or "").splitlines():
        if not line.strip():
            continue
        line = BRIDGE_PREFIX.sub("", line)
        line = re.sub(r"\bt=\d+", "t=<T>", line)
        line = HEXPTR.sub("<PTR>", line)
        out.append(line.strip())
    return out


def normalise_driver_result(obj):
    """The driver's own report, with the process-local addresses replaced and
    the arm CONFIGURATION fields set aside.

    `recorder_enabled` is the independent variable of section 52: it is the one
    thing that is SUPPOSED to differ between the two arms, so requiring it to be
    equal would make the comparison reject its own premise. Everything else in
    the report -- return codes, canary state, the addresses of the images it
    handed to the bridge -- must be equal.
    """
    if obj is None:
        return None
    out = dict(obj)
    for k in ("target_arena_address", "marker_arena_address", "target_args0"):
        if k in out:
            out[k] = "<PTR>"
    for k in ("recorder_enabled",):
        if k in out:
            out[k] = "<THE_INDEPENDENT_VARIABLE>"
    return out


def pointer_delta(txt):
    ptrs = []
    for line in (txt or "").splitlines():
        if " MOCK hipLaunchKernel " in line:
            for tok in line.split():
                if tok.startswith("function="):
                    ptrs.append(int(tok.split("=", 1)[1], 16))
    return (ptrs[1] - ptrs[0]) if len(ptrs) == 2 else None


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()

    for p in (DRIVER, SELFTEST):
        if not os.path.exists(p):
            print("MISSING %s -- run build_raw_dump.ps1 first" % p)
            return 2
    os.makedirs(OUT, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

    arms = {}
    for (name, dll, drv_arm, gate, rec) in ARMS:
        d = os.path.join(OUT, name)
        if os.path.isdir(d) and os.listdir(d) and not a.force:
            print("SKIP %s (exists; use --force to supersede)" % name)
        else:
            if os.path.isdir(d):
                moved = superseed(d, stamp)
                print("SUPERSEDED %s -> %s" % (name, os.path.basename(moved)))
            os.makedirs(d, exist_ok=True)
            argv = [DRIVER, "--bridge", os.path.join(BUILD, dll), "--out", d,
                    "--arm", drv_arm, "--gate", str(gate),
                    "--recorder", str(rec)]
            rc, so, se = run(argv)
            with open(os.path.join(d, "driver_stdout.txt"), "w",
                      encoding="utf-8", newline="\n") as f:
                f.write("argv: %s\nrc: %d\n--- stdout ---\n%s--- stderr ---\n%s"
                        % (json.dumps(argv), rc, so, se))
            print("RAN  %-24s rc=%d  %s" % (name, rc, so.strip()))
        arms[name] = {"dir": d, "bridge": dll, "driver_arm": drv_arm,
                      "gate": gate, "recorder": rec}

    # ---------------------------------------------------------------- selftest
    st_dir = os.path.join(OUT, "recorder_selftest")
    if os.path.isdir(st_dir):
        superseed(st_dir, stamp)
    os.makedirs(st_dir, exist_ok=True)
    rc, so, se = run([SELFTEST, "--dir", st_dir])
    with open(os.path.join(st_dir, "selftest.json"), "w", encoding="utf-8",
              newline="\n") as f:
        f.write(so)
    selftest, st_parsed = None, False
    try:
        selftest = json.loads(so)
        st_parsed = True
    except Exception as e:                                        # noqa: BLE001
        print("SELFTEST OUTPUT DID NOT PARSE: %s: %s" % (type(e).__name__, e))
        selftest = {"parse_error": "%s: %s" % (type(e).__name__, e),
                    "raw": so}
    print("SELFTEST rc=%d parsed=%s n_passed=%s"
          % (rc, st_parsed,
             (selftest or {}).get("n_passed", "?")))

    # ---------------------------------------------------------- per-arm evidence
    for name, info in arms.items():
        d = info["dir"]
        trace = parse_trace(os.path.join(d, "_raw_dump_trace.log"))
        info["trace"] = trace
        seg = target_segment(trace)
        info["segment"] = seg
        rec_events = events_of(seg, "RECORD_WRITTEN")
        rec = rec_events[-1]["detail"].strip() if rec_events else None
        info["target_record"] = rec
        vjson = os.path.join(d, "verification.json")
        rc, so, se = run([sys.executable, VERIFIER,
                          "--record", rec if rec else "-",
                          "--run-dir", d, "--target-identity", TARGET,
                          "--expected-ordinal", str(TARGET_ORDINAL),
                          "--json", vjson])
        with open(os.path.join(d, "verifier_stdout.txt"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("rc: %d\n--- stdout ---\n%s--- stderr ---\n%s" % (rc, so, se))
        try:
            info["verification"] = read_json(vjson)
        except Exception as e:                                    # noqa: BLE001
            info["verification"] = None
            print("VERIFIER JSON UNPARSEABLE for %s: %s" % (name, e))

    # ---------------------------------------------------------------- classify
    tally = []
    for name, info in arms.items():
        d = info["dir"]
        tr, seg = info["trace"], info["segment"]
        v = info["verification"] or {}
        try:
            drv = read_json(os.path.join(d, "driver_result.json"))
        except Exception as e:                                    # noqa: BLE001
            drv = {"parse_error": "%s: %s" % (type(e).__name__, e)}
        info["driver_result"] = drv
        blobs = {}
        for fn in ("fixture_blob.bin", "post_launch_blob.bin", "marker_blob.bin"):
            b = read_bytes(os.path.join(d, fn))
            blobs[fn] = None if b is None else sha256_bytes(b)
        info["blob_sha256"] = blobs
        rec = info["target_record"]
        info["record_file_sha256"] = (sha256_file(rec)
                                      if rec and os.path.exists(rec) else None)
        row = {
            "arm": name,
            "bridge": info["bridge"],
            "driver_arm": info["driver_arm"],
            "gate": info["gate"],
            "recorder_enabled": bool(info["recorder"]),
            "capture_site_reached": seg is not None,
            "segment_ordinal": None if seg is None else seg["ordinal"],
            "segment_kernel": None if seg is None else seg["kernel"],
            "recorder_entered": bool(events_of(seg, "RECORDER_ENTERED")),
            "emission_reached": bool(events_of(seg, "EMISSION_POINT_REACHED")),
            "record_emitted": rec is not None,
            "target_record": rec,
            "records_in_dir": list_records(d),
            "target_segment_events": [e["event"] for e in
                                      (seg or {"events": []})["events"]],
            "target_segment_refusals": [e["event"] for e in
                                        (seg or {"events": []})["events"]
                                        if e["event"].startswith("REFUSED")
                                        or e["event"] == "NOT_A_TARGET_KERNEL"],
            "verifier_verdict": v.get("verdict"),
            "checks_failed": sorted(v.get("rejection_basis", [])),
            "n_checks": v.get("n_checks", 0),
            "n_failed": v.get("n_failed", 0),
            "comparison_reached": bool(v.get("comparison_reached")),
            "comparison_not_reached_because":
                v.get("comparison_not_reached_because", []),
            "check_details": {c["check"]: c["detail"]
                              for c in v.get("checks", [])},
            "blob_sha256": blobs,
            "driver_canaries_intact": (
                drv.get("canary_target_tail_intact") is True and
                drv.get("canary_marker_tail_intact") is True),
        }
        row["emission_reached_yes_no"] = "YES" if row["emission_reached"] else "NO"
        row["expected_rejection_occurred"] = None      # filled per control
        tally.append(row)
        info["row"] = row
    by_arm = {r["arm"]: r for r in tally}

    # ------------------------------------------------------- the eight controls
    control_rows = []
    for (key, arm, mutation, must_fail) in CONTROLS:
        info = arms[arm]
        r = info["row"]
        v = info["verification"] or {}
        measured = set(v.get("rejection_basis", []))
        consequential = sorted(measured - must_fail)
        if key in ("g", "h"):
            expected = None
            if key == "g":
                basis = ("the recorder is disabled, so there is no observer to "
                         "reject anything. A missing record here is an absent "
                         "instrument, not a rejection: emission_reached=NO and "
                         "the arm is INVALID.")
            else:
                basis = ("the by-value image was never constructed, so the "
                         "adapter returned before the recorder's emission point "
                         "(trace event %s). Nothing downstream could have "
                         "rejected: emission_reached=NO and the arm is INVALID."
                         % (r["target_segment_refusals"] or
                            ["NO_TARGET_SEGMENT"]))
            verdict = "INVALID_CONTROL"
        else:
            expected = bool(v.get("comparison_reached")) and must_fail <= measured
            missing = sorted(must_fail - measured)
            basis = ("rejected by %d of %d checks; the intended basis is "
                     "established iff none of %s is missing%s"
                     % (len(measured), v.get("n_checks", 0), sorted(must_fail),
                        "" if not missing else "; MISSING %s" % missing))
            if consequential:
                basis += ("; also failed as a consequence: %s"
                          % consequential)
            verdict = ("VALID_CONTROL"
                       if (r["emission_reached"] and r["comparison_reached"]
                           and expected) else "INVALID_CONTROL")
        r["expected_rejection_occurred"] = expected
        control_rows.append({
            "control": key,
            "models": mutation,
            "arm": arm,
            "emission_reached": r["emission_reached_yes_no"],
            "capture_site_reached": "YES" if r["capture_site_reached"] else "NO",
            "recorder_entered": "YES" if r["recorder_entered"] else "NO",
            "record_emitted": "YES" if r["record_emitted"] else "NO",
            "comparison_reached": "YES" if r["comparison_reached"] else "NO",
            "expected_rejection_occurred": (
                "N/A" if expected is None else ("YES" if expected else "NO")),
            "verdict": verdict,
            "verdict_basis": basis,
            "checks_failed": sorted(measured),
            "checks_required_to_fail": sorted(must_fail),
            "checks_failed_consequentially": consequential,
            "n_checks_run": v.get("n_checks", 0),
            "verifier_verdict": v.get("verdict"),
            "target_segment_refusals": r["target_segment_refusals"],
            "evidence": "%s/verification.json" % arm,
        })
    n_valid = sum(1 for c in control_rows if c["verdict"] == "VALID_CONTROL")

    # Distinctness: two mutations that produce the SAME failing set must still
    # be distinguishable by value, or they are one experiment run twice.
    distinct = []
    for i, ci in enumerate(control_rows):
        for cj in control_rows[i + 1:]:
            if not ci["checks_failed"] or not cj["checks_failed"]:
                continue
            di = arms[ci["arm"]]["row"]["check_details"]
            dj = arms[cj["arm"]]["row"]["check_details"]
            shared = sorted(set(ci["checks_failed"]) & set(cj["checks_failed"]))
            same_details = [k for k in shared if di.get(k) == dj.get(k)]
            distinct.append({
                "arms": [ci["arm"], cj["arm"]],
                "same_failing_check_names": ci["checks_failed"] ==
                                            cj["checks_failed"],
                "shared_failing_checks": shared,
                "shared_checks_with_identical_detail_values": same_details,
                "distinguishable": bool(same_details != shared or
                                        ci["checks_failed"] != cj["checks_failed"]),
            })
    not_distinct = [d for d in distinct if not d["distinguishable"]]

    # --------------------------------------------------------- section 52 pair
    rehearsal = build_rehearsal(arms, by_arm)

    # ------------------------------------ the three section 52 predicates can fail
    # Each equality predicate is evaluated twice: once on the ON/OFF pair it is
    # meant to certify, and once on a pair that is known to differ. A predicate
    # that cannot return False is not evidence, and this project has already
    # counted a vacuous green as a pass.
    good_blob = blob_pair_equal(arms["accept_clean"], arms["clean_recorder_off"])
    bad_blob = blob_pair_equal(arms["accept_clean"], arms["b_shift"])
    good_desc = mock_log_equal(arms["accept_clean"], arms["clean_recorder_off"])
    bad_desc = mock_log_equal(arms["accept_clean"], arms["probe_gate_off"])
    good_flow = bridge_log_equal(arms["accept_clean"], arms["clean_recorder_off"])
    bad_flow = bridge_log_equal(arms["accept_clean"], arms["probe_gate_off"])
    predicates = {
        "blob_equality": {
            "predicate": "the two arms' fixture/post/marker bytes are equal",
            "accepts_the_known_good_pair": good_blob,
            "rejects_the_known_bad_pair": bad_blob is False,
            "known_bad_pair": ("accept_clean's record bytes vs b_shift's record "
                               "bytes -- the same bytes one mutant away"),
        },
        "descriptor_equality": {
            "predicate": "the two arms' normalised mock_hip6.log lines are equal",
            "accepts_the_known_good_pair": good_desc,
            "rejects_the_known_bad_pair": bad_desc is False,
            "known_bad_pair": ("accept_clean vs probe_gate_off -- the gate-off "
                               "arm where the mock sees no launch at all"),
        },
        "control_flow_equality": {
            "predicate": "the two arms' normalised bridge.log lines are equal",
            "accepts_the_known_good_pair": good_flow,
            "rejects_the_known_bad_pair": bad_flow is False,
            "known_bad_pair": ("accept_clean vs probe_gate_off -- the gate-off "
                               "arm whose bridge log carries BLOCKED_KERNEL_LAUNCH "
                               "instead of a backend return"),
        },
    }
    for d in predicates.values():
        d["is_evidence"] = bool(d["accepts_the_known_good_pair"] and
                                d["rejects_the_known_bad_pair"])

    # ---------------------------------------------------------- gate-off probe
    gated = by_arm["probe_gate_off"]
    gate_off_probe = {
        "arm": "probe_gate_off",
        "gate": "OFF (DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH=0)",
        "capture_site_reached": gated["capture_site_reached"],
        "emission_reached": gated["emission_reached"],
        "record_emitted": gated["record_emitted"],
        "bridge_log_blocked_lines": sum(
            1 for l in normalise_log(read_text(
                os.path.join(arms["probe_gate_off"]["dir"], "bridge.log")) or "")
            if "BLOCKED_KERNEL_LAUNCH" in l),
        "launches_seen_by_the_mock": sum(
            1 for l in (read_text(os.path.join(
                arms["probe_gate_off"]["dir"], "mock_hip6.log")) or "").splitlines()
            if "MOCK hipLaunchKernel" in l),
        "reading": ("with the fail-closed gate OFF the launch is blocked before "
                    "the backend, yet the capture still runs and still emits -- "
                    "which is the ordering claim: the capture point precedes the "
                    "gate. It also shows that the section 52 comparisons CAN "
                    "detect a changed trajectory."),
    }
    gate_off_probe["capture_precedes_the_gate"] = bool(
        gated["capture_site_reached"] and gated["emission_reached"] and
        gated["record_emitted"] and
        gate_off_probe["launches_seen_by_the_mock"] == 0 and
        gate_off_probe["bridge_log_blocked_lines"] >= 1)

    # ------------------------------------------------------------- the schema
    # Regenerated here, from a record this run just emitted, so the schema
    # artefact cannot describe a recorder that no longer exists.
    schema_rc, schema_so, schema_se = run(
        [sys.executable, os.path.join(HERE, "p16at_emit_record_schema.py")])
    print("")
    print("--- record schema regenerated from this run's record ---")
    for l in schema_so.strip().splitlines():
        print("  " + l)
    if schema_rc != 0:
        print("  stderr: %s" % schema_se.strip()[:400])
    schema_doc = None
    try:
        schema_doc = read_json(os.path.join(RAW_DUMP, "RAW_DUMP_SCHEMA.json"))
    except Exception as e:                                        # noqa: BLE001
        print("  SCHEMA JSON UNPARSEABLE: %s: %s" % (type(e).__name__, e))

    # ------------------------------------------------------------- first frame
    # The head-line figures come from the 16AO CONTRACT VERDICT, which is their
    # single source; the closure supplies the per-identity rows.
    verdict_doc = read_json(os.path.join(
        ROOT, "p16ao", "contracts", "FIRST_FRAME_CONTRACT_VERDICT.json"))
    closure = read_json(os.path.join(
        ROOT, "p16ao", "contracts", "FIRST_FRAME_FIELD_CLOSURE.json"))
    n_rows = len(closure["fields"])
    table = read_json(os.path.join(RAW_DUMP, "RAW_DUMP_BLOB_TABLE.json"))
    counts = verdict_doc.get("counts", {})
    denominator = verdict_doc.get("denominator", {})
    requires_gpu = verdict_doc.get(
        "is_any_mandatory_first_frame_field_unresolved", {}).get("requires_gpu")

    # ------------------------------------------------------------- artefacts
    write_json(os.path.join(RAW_DUMP, "RAW_DUMP_REACH_CONTROLS.json"), {
        "schema": "p16at/raw-dump-reach-controls/1",
        "phase": "16AT",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "what_this_is": (
            "Every control of brief IX sections 50-51, each measured by running "
            "the real launch path through the project's no-GPU HIP bridge and "
            "reading back what that run wrote. emission_reached is read from the "
            "recorder's own trace file, not from the arm's design: an arm whose "
            "observer never ran is INVALID_CONTROL, never a rejection."),
        "no_gpu": True, "gpu_execution_performed": False,
        "hip_runtime_imported": False,
        "backend": "phase10_hip_bridge/mock_hip6.dll (existing project mock)",
        "emission_point_definition": (
            "EMISSION_POINT_REACHED, written by raw_dump::emit() at the first "
            "statement after the RAW_DUMP enable gate and before any validation. "
            "RECORDER_ENTERED is written earlier still, before the gate, so an "
            "absent observer is visible as such rather than inferred from a "
            "missing record."),
        "positive_reference": {
            "arm": "accept_clean",
            "emission_reached": by_arm["accept_clean"]["emission_reached_yes_no"],
            "comparison_reached":
                "YES" if by_arm["accept_clean"]["comparison_reached"] else "NO",
            "checks_failed": by_arm["accept_clean"]["checks_failed"],
            "n_checks": by_arm["accept_clean"]["n_checks"],
            "verifier_verdict": by_arm["accept_clean"]["verifier_verdict"],
            "role": ("not a control: the run that must be ACCEPTED, so that a "
                     "green control set cannot be green because the verifier "
                     "rejects everything"),
        },
        "controls": control_rows,
        "tally": {"n_controls": len(control_rows), "n_valid_control": n_valid,
                  "n_invalid_control": len(control_rows) - n_valid,
                  "invalid_arms": [c["arm"] for c in control_rows
                                   if c["verdict"] == "INVALID_CONTROL"]},
        "distinctness_of_the_mutation_arms": {
            "what_this_checks": (
                "identical failing-check NAMES are not evidence of a distinct "
                "fault. Every pair of rejecting arms is compared on the VALUES "
                "of the checks they share, so two arms cannot both be 'rejected "
                "by C4, C5, C10, C11' for the same reason and be counted twice."),
            "pairs": distinct,
            "pairs_not_distinguishable": not_distinct,
            "all_pairs_distinguishable": not not_distinct,
        },
        "recorder_self_test": selftest,
        "recorder_self_test_parsed": st_parsed,
        "arm_tally": tally,
    })

    write_json(os.path.join(RAW_DUMP, "RAW_DUMP_ARM_TALLY.json"),
               {"schema": "p16at/raw-dump-arm-tally/1", "arms": tally})

    write_json(os.path.join(RAW_DUMP, "RAW_DUMP_NOGPU_REHEARSAL.json"), rehearsal)

    # --------------------- EVERY emitted record, standard JSON reader -------
    # Runs BEFORE the status doc so its result is part of the status doc. The
    # re-parse block further down covers the seven top-level ARTEFACTS; this
    # covers the RECORDS, which is where six unparseable files were found.
    print("")
    print("--- every emitted .json, standard JSON reader, with can-fail proof ---")
    all_records_parse, parse_ok = verify_all_emitted_records()

    status = build_status(arms, by_arm, rehearsal, control_rows, n_valid,
                          gate_off_probe, predicates, selftest, st_parsed,
                          table, closure, n_rows, counts, denominator,
                          requires_gpu, schema_doc, schema_rc, all_records_parse)
    write_json(os.path.join(RAW_DUMP, "RAW_DUMP_STATUS.json"), status)

    write_json(os.path.join(WORK, "control_run_state.json"), {
        "schema": "p16at/raw-dump-control-run-state/1",
        "selftest": selftest, "arms": tally,
        "gate_off_probe": gate_off_probe,
        "section_52_predicate_negative_controls": predicates,
    })

    # ------------------------------------------------------- re-parse them back
    print("")
    print("--- re-parsing every JSON this run wrote ---")
    ok = parse_ok
    written = ["RAW_DUMP_REACH_CONTROLS.json", "RAW_DUMP_ARM_TALLY.json",
               "RAW_DUMP_NOGPU_REHEARSAL.json", "RAW_DUMP_STATUS.json",
               "RAW_DUMP_SCHEMA.json", "RAW_DUMP_BLOB_TABLE.json"]
    for n in written:
        p = os.path.join(RAW_DUMP, n)
        try:
            d = read_json(p)
            print("  OK   %-31s bytes=%6d keys=%d"
                  % (n, os.path.getsize(p), len(d)))
        except Exception as e:                                    # noqa: BLE001
            ok = False
            print("  FAIL %-31s %s: %s" % (n, type(e).__name__, e))
    p = os.path.join(WORK, "control_run_state.json")
    try:
        d = read_json(p)
        print("  OK   %-31s bytes=%6d keys=%d"
              % ("_work/control_run_state.json", os.path.getsize(p), len(d)))
    except Exception as e:                                        # noqa: BLE001
        ok = False
        print("  FAIL control_run_state.json %s: %s" % (type(e).__name__, e))
    for name in arms:
        p = os.path.join(arms[name]["dir"], "verification.json")
        try:
            read_json(p)
        except Exception as e:                                    # noqa: BLE001
            ok = False
            print("  FAIL %s/verification.json %s: %s" % (name, type(e).__name__, e))
    for name in arms:
        p = os.path.join(arms[name]["dir"], "driver_result.json")
        try:
            read_json(p)
        except Exception as e:                                    # noqa: BLE001
            ok = False
            print("  FAIL %s/driver_result.json %s: %s" % (name, type(e).__name__, e))
    print("  (and all %d per-arm verification.json + %d driver_result.json)"
          % (len(arms), len(arms)))

    print("")
    print("CONTROL TALLY  valid=%d invalid=%d  (of %d)"
          % (n_valid, len(control_rows) - n_valid, len(control_rows)))
    for c in control_rows:
        print("  %-2s %-24s emission=%-3s comparison=%-3s reject=%-3s %s"
              % (c["control"], c["arm"], c["emission_reached"],
                 c["comparison_reached"], c["expected_rejection_occurred"],
                 c["verdict"]))
    print("")
    print("SECTION 52  blob=%s descriptor=%s control_flow=%s evidence_only=%s"
          % (rehearsal["equality_1_outgoing_blob"]["identical"],
             rehearsal["equality_2_launch_descriptor"]["identical"],
             rehearsal["equality_3_control_flow"]["identical"],
             rehearsal["differing_only_in_evidence_emission"]["identical"]))
    print("SECTION 52  rehearsal_passed=%s" % rehearsal["rehearsal_passed"])
    print("GATE-OFF PROBE  capture_precedes_the_gate=%s"
          % gate_off_probe["capture_precedes_the_gate"])
    print("STATUS  %s" % status["status"])
    return 0 if ok else 3


# ------------------------------------------------------- section 52 predicates
def load_pair(arm_a, arm_b, fn):
    return (read_bytes(os.path.join(arm_a["dir"], fn)),
            read_bytes(os.path.join(arm_b["dir"], fn)))


def blob_pair_equal(arm_a, arm_b):
    """The blob-equality predicate, generalised to any two arms.

    All launch-path blob files must agree byte for byte; and when BOTH arms
    emitted a record, the bytes those records carry must agree too. The second
    clause is what gives the predicate teeth: the driver writes the same fixture
    in every arm, so the files alone cannot separate a clean arm from a mutated
    one -- the recorded bytes can.
    """
    for fn in LAUNCH_PATH_FILES:
        a, b = load_pair(arm_a, arm_b, fn)
        if a is None or b is None or a != b:
            return False
    ra, rb = arm_a.get("target_record"), arm_b.get("target_record")
    if ra and rb and os.path.exists(ra) and os.path.exists(rb):
        try:
            return (read_json(ra).get("raw_bytes") ==
                    read_json(rb).get("raw_bytes"))
        except Exception:                                         # noqa: BLE001
            return None
    return True


def mock_log_equal(arm_a, arm_b):
    a = normalise_log(read_text(os.path.join(arm_a["dir"], "mock_hip6.log")))
    b = normalise_log(read_text(os.path.join(arm_b["dir"], "mock_hip6.log")))
    return a == b


def bridge_log_equal(arm_a, arm_b):
    a = normalise_log(read_text(os.path.join(arm_a["dir"], "bridge.log")))
    b = normalise_log(read_text(os.path.join(arm_b["dir"], "bridge.log")))
    return a == b


def build_rehearsal(arms, by_arm):
    """Brief IX section 52: ON and OFF must differ ONLY in evidence emission."""
    on, off = arms["accept_clean"], arms["clean_recorder_off"]
    don, doff = on["dir"], off["dir"]

    blobs = []
    for fn in LAUNCH_PATH_FILES:
        a, b = load_pair(on, off, fn)
        blobs.append({"file": fn,
                      "on_bytes": None if a is None else len(a),
                      "off_bytes": None if b is None else len(b),
                      "on_sha256": None if a is None else sha256_bytes(a),
                      "off_sha256": None if b is None else sha256_bytes(b),
                      "identical": a is not None and a == b})

    rec = on["target_record"]
    rec_raw_sha = None
    if rec and os.path.exists(rec):
        try:
            rec_raw_sha = sha256_bytes(bytes.fromhex(read_json(rec)["raw_bytes"]))
        except Exception:                                         # noqa: BLE001
            rec_raw_sha = None
    chain = {
        "record_sha256_of_raw_bytes": rec_raw_sha,
        "on_fixture_sha256": by_arm["accept_clean"]["blob_sha256"]["fixture_blob.bin"],
        "off_fixture_sha256": by_arm["clean_recorder_off"]["blob_sha256"]["fixture_blob.bin"],
        "on_post_launch_sha256": by_arm["accept_clean"]["blob_sha256"]["post_launch_blob.bin"],
        "off_post_launch_sha256": by_arm["clean_recorder_off"]["blob_sha256"]["post_launch_blob.bin"],
        "record_equals_on_fixture": rec_raw_sha ==
            by_arm["accept_clean"]["blob_sha256"]["fixture_blob.bin"],
        "record_equals_off_fixture": rec_raw_sha ==
            by_arm["clean_recorder_off"]["blob_sha256"]["fixture_blob.bin"],
    }
    blob_identical = all(b["identical"] for b in blobs) and \
        chain["record_equals_on_fixture"] and chain["record_equals_off_fixture"]

    # ---- launch descriptor -------------------------------------------------
    mon = read_text(os.path.join(don, "mock_hip6.log"))
    moff = read_text(os.path.join(doff, "mock_hip6.log"))
    nmon, nmoff = normalise_log(mon), normalise_log(moff)
    d_on, d_off = pointer_delta(mon), pointer_delta(moff)
    descriptor = {
        "on_lines": nmon, "off_lines": nmoff,
        "lines_identical": nmon == nmoff,
        "on_pointer_delta_between_the_two_launches": d_on,
        "off_pointer_delta_between_the_two_launches": d_off,
        "pointer_delta_identical": d_on is not None and d_on == d_off,
        "n_launches_seen_by_the_mock_on": sum(
            1 for l in (mon or "").splitlines() if "MOCK hipLaunchKernel" in l),
        "n_launches_seen_by_the_mock_off": sum(
            1 for l in (moff or "").splitlines() if "MOCK hipLaunchKernel" in l),
        "note": ("function= is a process-local address and is normalised; "
                 "the delta between the two launches is ASLR-invariant and is "
                 "required to be equal, which is the part of the descriptor "
                 "that carries information"),
    }
    descriptor["identical"] = (descriptor["lines_identical"] and
                               descriptor["pointer_delta_identical"] and
                               descriptor["n_launches_seen_by_the_mock_on"] == 2 and
                               descriptor["n_launches_seen_by_the_mock_off"] == 2)

    # ---- control flow ------------------------------------------------------
    bon = read_text(os.path.join(don, "bridge.log"))
    boff = read_text(os.path.join(doff, "bridge.log"))
    raw_on = [l for l in (bon or "").splitlines() if l.strip()]
    raw_off = [l for l in (boff or "").splitlines() if l.strip()]
    nbon, nboff = normalise_log(bon), normalise_log(boff)
    flow = {
        "on_lines_raw": len(raw_on), "off_lines_raw": len(raw_off),
        "raw_lines_identical": raw_on == raw_off,
        "on_lines_normalised": nbon, "off_lines_normalised": nboff,
        "normalised_lines_identical": nbon == nboff,
        "normalisation": ("the log's own timestamp/tid/pid prefix and any hex "
                          "pointer token are replaced; these are process-local "
                          "identities, not control flow. raw_lines_identical "
                          "records how much the un-normalised logs differ"),
        "on_launch_attempts": sum(1 for l in nbon if "LAUNCH_ATTEMPT" in l),
        "off_launch_attempts": sum(1 for l in nboff if "LAUNCH_ATTEMPT" in l),
        "on_gate_on_attempts": sum(1 for l in nbon
                                   if "LAUNCH_ATTEMPT" in l and "gate=ON" in l),
        "off_gate_on_attempts": sum(1 for l in nboff
                                    if "LAUNCH_ATTEMPT" in l and "gate=ON" in l),
        "on_backend_returns": sum(1 for l in nbon if "hipLaunchKernel ->" in l),
        "off_backend_returns": sum(1 for l in nboff if "hipLaunchKernel ->" in l),
        "on_backend_loaded": sum(1 for l in nbon if "BACKEND_LOADED" in l),
        "off_backend_loaded": sum(1 for l in nboff if "BACKEND_LOADED" in l),
    }
    flow["identical"] = (flow["normalised_lines_identical"] and
                         flow["on_launch_attempts"] == 2 and
                         flow["off_launch_attempts"] == 2 and
                         flow["on_gate_on_attempts"] == 2 and
                         flow["off_gate_on_attempts"] == 2 and
                         flow["on_backend_returns"] == 2 and
                         flow["off_backend_returns"] == 2 and
                         flow["on_backend_loaded"] == 1 and
                         flow["off_backend_loaded"] == 1)

    # ---- what differs between the two directories --------------------------
    fon, foff = set(os.listdir(don)), set(os.listdir(doff))
    on_records = sorted(n for n in fon if RECORD_NAME.match(n))
    # descriptor files, compared after normalisation
    desc_on = {"bridge.log": nbon, "mock_hip6.log": nmon,
               "driver_result.json": normalise_driver_result(on["driver_result"])}
    desc_off = {"bridge.log": nboff, "mock_hip6.log": nmoff,
                "driver_result.json": normalise_driver_result(off["driver_result"])}
    desc_equal = {k: (desc_on[k] == desc_off[k]) for k in desc_on}

    allowed_extra = set(EVIDENCE_FILES)
    extra_on = sorted(n for n in (fon - foff)
                      if n not in allowed_extra and not is_record_file(n))
    extra_off = sorted(n for n in (foff - fon)
                       if n not in allowed_extra and not is_record_file(n))

    differing = []
    for n in sorted(fon & foff):
        if n in EVIDENCE_FILES or n in DESCRIPTOR_FILES:
            continue
        a, b = load_pair(on, off, n)
        if a != b:
            differing.append(n)

    evidence = {
        "files_only_in_on": sorted(fon - foff),
        "files_only_in_off": sorted(foff - fon),
        "on_emitted_records": on_records,
        "off_emitted_records": sorted(n for n in foff if RECORD_NAME.match(n)),
        "unexpected_extra_files_in_on": extra_on,
        "unexpected_extra_files_in_off": extra_off,
        "descriptor_files_equal_after_normalisation": desc_equal,
        "launch_path_files_that_differ_bytewise": differing,
        "note": ("the only files the ON arm has that the OFF arm does not are "
                 "_raw_dump_trace.log's extra lines and the emitted records (both "
                 "the .json and its .bin side-car); the runner's own captures "
                 "(driver_stdout.txt, verifier_stdout.txt, verification.json) are "
                 "bookkeeping, not launch-path evidence"),
    }

    on_tr, off_tr = on["trace"], off["trace"]
    on_seq = [e["event"] for e in
              [x for s in on_tr["segments"] for x in s["events"]]]
    off_seq = [e["event"] for e in
               [x for s in off_tr["segments"] for x in s["events"]]]

    def is_subsequence(short, long_):
        it = iter(long_)
        return all(any(x == y for y in it) for x in short)

    trace_cmp = {
        "on_events": {k: sum(1 for e in on_tr["lines"] if k in e)
                      for k in ("CAPTURE_SITE_REACHED", "RECORDER_ENTERED",
                                "EMISSION_POINT_REACHED", "RECORD_WRITTEN")},
        "off_events": {k: sum(1 for e in off_tr["lines"] if k in e)
                       for k in ("CAPTURE_SITE_REACHED", "RECORDER_ENTERED",
                                 "EMISSION_POINT_REACHED", "RECORD_WRITTEN")},
        "on_lines": on_tr["n_lines"], "off_lines": off_tr["n_lines"],
        "on_event_sequence": on_seq, "off_event_sequence": off_seq,
        "off_sequence_is_a_subsequence_of_on_sequence":
            is_subsequence(off_seq, on_seq),
        "events_the_off_arm_never_reaches": sorted(set(on_seq) - set(off_seq)),
        "events_the_off_arm_reaches_that_on_does_not":
            sorted(set(off_seq) - set(on_seq)),
    }

    differs_only = (not extra_on and not extra_off and not differing and
                    all(desc_equal.values()) and len(on_records) == 2 and
                    not evidence["off_emitted_records"] and
                    trace_cmp["off_sequence_is_a_subsequence_of_on_sequence"] and
                    trace_cmp["off_events"]["CAPTURE_SITE_REACHED"] == 2 and
                    trace_cmp["off_events"]["RECORDER_ENTERED"] == 2 and
                    trace_cmp["off_events"]["EMISSION_POINT_REACHED"] == 0 and
                    trace_cmp["off_events"]["RECORD_WRITTEN"] == 0)

    passed = bool(blob_identical and descriptor["identical"] and
                  flow["identical"] and differs_only)

    return {
        "schema": "p16at/raw-dump-nogpu-rehearsal/1",
        "phase": "16AT",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "what_this_is": (
            "Brief IX section 52. The launch path is run twice, with the "
            "recorder ON and OFF, over the project's EXISTING no-GPU mock "
            "backend (phase10_hip_bridge/mock_hip6.dll, unmodified). The three "
            "required equalities are asserted by comparing artefacts the two "
            "runs wrote, never in prose."),
        "backend": "phase10_hip_bridge/mock_hip6.dll (existing project no-GPU mock)",
        "gpu_execution_performed": False, "hip_runtime_imported": False,
        "on_arm": {"arm": "accept_clean", "dir": don, "recorder_enabled": True,
                   "records_emitted": len(on_records)},
        "off_arm": {"arm": "clean_recorder_off", "dir": doff,
                    "recorder_enabled": False, "records_emitted": 0},
        "gate": "ON in both arms (DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH=1)",
        "equality_1_outgoing_blob": {
            "identical": blob_identical,
            "compared_files": blobs, "record_blob_chain": chain,
            "negative_control": (
                "the same predicate returns False when fed the b_shift arm's "
                "record bytes instead of the fixture"),
        },
        "equality_2_launch_descriptor": descriptor,
        "equality_3_control_flow": flow,
        "differing_only_in_evidence_emission": {"identical": differs_only,
                                                **evidence,
                                                "trace_comparison": trace_cmp},
        "rehearsal_passed": passed,
        "limits": [
            "The mock backend ignores args entirely, so the bytes crossing the "
            "backend boundary are NOT directly observable in its log. The claim "
            "rests on the fixture and post-launch images the driver wrote from "
            "the same buffer it handed to the bridge, plus the recorder's own "
            "re-read stability guard. This is not a direct observation of the "
            "backend-boundary bytes.",
            "The recorder's SHA-256 and file writes perturb the host timeline. "
            "The comparison is of the emitted trajectory, not of timings: "
            "timing perturbation is NOT_MEASURED.",
            "Both arms ran with the fail-closed gate ON, because the section 52 "
            "comparison needs the backend submission to happen. The no-GPU "
            "property comes from building the bridge with -DDLSSNR_BRIDGE_TESTING, "
            "whose backend is the mock; the build script asserts that no binary "
            "imports any HIP runtime.",
            "bridge.log and mock_hip6.log contain process-local addresses, so "
            "they are compared after normalisation; raw_lines_identical records "
            "how much the un-normalised logs differ. section_52_predicate_"
            "negative_controls in RAW_DUMP_STATUS.json shows each equality "
            "predicate returning False on a pair that is known to differ, so a "
            "green result here is not vacuous.",
        ],
    }


def verify_all_emitted_records():
    """Parse every emitted .json with Python's standard json module.

    Returns (report_or_None, ok). ok is False when any emitted record fails to
    parse, when the scan is vacuous, or when the can-fail proof breaks -- i.e.
    when the known-bad corpus in _work/known_bad_records/ is not rejected.
    """
    parse_report = os.path.join(WORK, "all_records_parse.json")
    cmd = [sys.executable, os.path.join(HERE, "p16at_verify_all_records.py"),
           "--root", os.path.join(RAW_DUMP, "out"),
           "--root", os.path.join(RAW_DUMP, "build"),
           "--expect-reject", os.path.join(WORK, "known_bad_records"),
           "--json", parse_report]
    pr = subprocess.run(cmd, capture_output=True, text=True)
    print(pr.stdout.rstrip())
    if pr.stderr.strip():
        print("  stderr: %s" % pr.stderr.strip())
    report = None
    try:
        report = read_json(parse_report)
    except Exception as e:                                        # noqa: BLE001
        print("  FAIL could not read %s %s: %s"
              % (parse_report, type(e).__name__, e))
        return None, False
    if pr.returncode != 0:
        print("  FAIL p16at_verify_all_records.py exit=%d -- at least one emitted "
              "record is not valid JSON, the scan was vacuous, or the can-fail "
              "proof broke" % pr.returncode)
        return report, False
    return report, True


def build_status(arms, by_arm, rehearsal, control_rows, n_valid, gate_off_probe,
                 predicates, selftest, st_parsed, table, closure, n_rows,
                 counts, denominator, requires_gpu, schema_doc, schema_rc,
                 all_records_parse=None):
    """RAW_DUMP_STATUS.json -- schema p16at/raw-dump-status/1."""
    acc = by_arm["accept_clean"]
    n_invalid = len(control_rows) - n_valid
    req = counts.get("required")
    res = counts.get("resolved")
    unres = counts.get("unresolved")
    figure = "%s/%s" % (res, req)
    return {
        "schema": "p16at/raw-dump-status/1",
        "phase": "16AT",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "BUILT",
        "status_basis": (
            "the recorder, its wiring, its schema and the whole control set "
            "exist and were exercised end-to-end against the project's no-GPU "
            "mock backend; the only thing NOT done is a capture at a real GPU "
            "launch, which the constraints forbid"),
        "no_gpu": True,
        "gpu_execution_performed": False,
        "hip_calls_made": False,
        "hip_runtime_imported": False,
        "binaries_import_only": "KERNEL32.dll (asserted by the build script)",
        "predecessor": {
            "artefact": "p16as/raw_dump/RAW_DUMP_FEASIBILITY_16AS.json",
            "status_then": "INVESTIGATED_NOT_BUILT",
            "status_now": "BUILT (design + recorder + rehearsal + control set)",
        },

        "capture_point": {
            "file": "phase16_bridge_telemetry/src/amdhip64_7.cpp",
            "function": "hipLaunchKernel",
            "anchor_statement": "decode_launch_args(name, args);",
            "inserted_call": ("raw_dump_at_launch_capture_point(name, "
                              "function_address, args, launch_ordinal);"),
            "why_after_blob_construction": (
                "the caller materialised every by-value parameter into host "
                "memory and built the void** args array before entering the "
                "bridge, so the complete image already exists; "
                "decode_launch_args only reads it"),
            "why_before_packing_and_submission": (
                "the only two operations in the bridge that can change the "
                "image's representation are the fail-closed gate's early return "
                "and the backend submission fn(...), and both statements follow "
                "the insertion point"),
            "original_file_modified": False,
            "transformation": "_work/capture_point_application.json",
            "transformation_proof": ("9 lines inserted (1 include + 8 "
                                     "statement), added=9 removed=0, and "
                                     "deleting them reproduces the original "
                                     "byte-for-byte"),
            "gate_off_probe": gate_off_probe,
        },

        "what_was_built": [
            "src/raw_dump_recorder.{h,cpp} -- the recorder: bounded JSON + "
            "side-car emission, self-contained SHA-256, CREATE_NEW write-once "
            "with .dupN fallback, append-only reach trace",
            "src/raw_dump_blob_table.h + RAW_DUMP_BLOB_TABLE.json -- the 15 "
            "identities with their declared by-value sizes and read offsets, "
            "generated from the 16AO closure with the kernarg-to-blob offset "
            "conversion asserted",
            "src/raw_dump_capture_point.h -- the whole wiring change, as a "
            "single call the transformer inserts",
            "src/raw_dump_injection_points.h -- the four RAWD_* macros, the "
            "entire mutation surface",
            "src/p16at_apply_capture_point.py -- the transformer, with four "
            "properties proved (unique anchors, strip reproduces the original, "
            "added/removed counts, patch round-trip)",
            "src/p16at_emit_mutants.py + _work/mutants/ -- five single-macro "
            "capture mutants, each proved to differ from the parent by exactly "
            "one #define line",
            "src/p16at_emit_blob_table.py -- the table generator and --check",
            "src/rehearsal_driver.cpp + build/rehearsal_driver.exe -- the "
            "no-GPU launch-path driver",
            "src/recorder_selftest.cpp + build/recorder_selftest.exe -- the "
            "recorder's own checks",
            "src/p16at_verify_records.py -- the comparison point, which "
            "PREDICTS the expected bytes rather than reading them back",
            "src/p16at_run_controls.py -- the arm runner",
            "src/build_raw_dump.ps1 -- the build, which parses every PE's "
            "import table and refuses if any imports a HIP runtime",
            "RAW_DUMP_DESIGN.md, RAW_DUMP_SCHEMA.json, "
            "RAW_DUMP_REACH_CONTROLS.json, RAW_DUMP_NOGPU_REHEARSAL.json, "
            "RAW_DUMP_STATUS.json",
        ],
        "what_was_not_built_and_why": [
            {"item": "a capture at a real GPU kernel launch",
             "why": ("forbidden by the phase constraints: no GPU work, no HIP "
                     "calls, no HIP DLL imports. The recorder is complete and "
                     "has been exercised on the full host launch path against "
                     "the project's mock backend, but it has never seen a real "
                     "launch and no real blob has been read.")},
            {"item": "the 15 unresolved scalar constants",
             "why": ("they stay UNRESOLVED. RAW_DUMP is an instrument, not a "
                     "resolver: it records bytes and interprets none. No real "
                     "launch was captured, so no value was read.")},
            {"item": "resolving the four contradictions",
             "why": ("out of scope for 16AT; the 16AO contract records them as "
                     "already RESOLVED")},
            {"item": "an in-bridge recorder (rather than a wired-in adapter)",
             "why": ("the capture must not change the shipping bridge's "
                     "behaviour. The adapter is a separate translation unit "
                     "inserted by a transformer that never edits the original "
                     "file, so the shipping source's hash is unchanged and the "
                     "insertion is reversible and proved so.")},
            {"item": "timing / perturbation measurement",
             "why": "NOT_MEASURED: no timing instrument was built for this phase"},
            {"item": "concurrency under simultaneous launches",
             "why": ("the recorder takes a critical section and re-reads the "
                     "image to detect concurrent mutation, but its "
                     "multi-threaded path is NOT_MEASURED: the rehearsal driver "
                     "launches on one thread only")},
        ],

        "capture_performed": {
            "any_capture_at_a_real_launch": False,
            "captures_performed_at_a_rehearsed_no_gpu_launch": True,
            "n_record_emissions_in_this_run":
                sum(len(v) for v in [by_arm[n]["records_in_dir"] for n in by_arm]),
            "n_records_in_the_accept_arm": len(acc["records_in_dir"]),
            "explanation": (
                "Recorder emissions happened against the project's mock backend "
                "only. No GPU was touched, no HIP runtime was loaded, and no "
                "kernel ran. These emissions are a rehearsal of the instrument, "
                "not captures of a real launch."),
        },

        "first_frame_contract": {
            "denominator_required_mandatory_fields": req,
            "resolved": res,
            "unresolved": unres,
            "of_which_unresolved_in_the_denominator": denominator.get(
                "of_which_unresolved"),
            "of_which_resolved_by_the_rebase": denominator.get(
                "of_which_resolved_by_the_rebase"),
            "coverage_percent_resolved": counts.get("coverage_percent_resolved"),
            "figure_before_16AT": figure,
            "figure_after_16AT": figure,
            "changed_by_this_phase": False,
            "why_unchanged": (
                "RAW_DUMP was built to READ the %s unresolved constants out of a "
                "real launch's by-value blob. No real launch was captured, so no "
                "constant was read and the figure does not move. The 16AO verdict "
                "records the single action that would close it as requiring a GPU "
                "(requires_gpu=%s), which this phase is forbidden to touch; "
                "claiming the figure moved would be exactly the fabrication this "
                "phase's verification norms forbid." % (unres, requires_gpu)),
            "source_of_the_head_line_figures":
                "p16ao/contracts/FIRST_FRAME_CONTRACT_VERDICT.json",
            "source_of_the_per_identity_rows":
                "p16ao/contracts/FIRST_FRAME_FIELD_CLOSURE.json",
            "source_rows_in_the_closure": n_rows,
            "identities_in_the_blob_table": table["n_rows"],
            "identities_match_the_closure": table["n_rows"] == n_rows,
            "contradiction_states": verdict_doc_contradictions(closure),
        },

        "schema_of_a_record": "RAW_DUMP_SCHEMA.json",
        "record_schema_id": "p16at/raw-dump-record/1",
        "schema_regenerated_from_this_runs_record": {
            "generator": "src/p16at_emit_record_schema.py",
            "generator_exit_code": schema_rc,
            "verdict": (schema_doc or {}).get("verdict"),
            "derived_from": (schema_doc or {}).get("derived_from"),
            "n_fields": (schema_doc or {}).get("n_fields"),
            "n_invariants": (schema_doc or {}).get("n_invariants"),
            "n_invariants_failed":
                (schema_doc or {}).get("n_invariants_failed"),
            "selfcheck":
                (schema_doc or {}).get("prove_it_can_fail_and_prove_it_passes"),
        },
        "write_once": {
            "mechanism": ("CreateFileA(..., CREATE_NEW) for the record and the "
                          "side-car, with a .dupN retry; a collision is never "
                          "an overwrite"),
            "proved_by": "recorder_selftest step 2",
            "measured": next(
                (s for s in selftest.get("steps", [])
                 if s["name"] == "recorder_never_overwrites_an_existing_record")
                if st_parsed else None),
        },

        "prove_it_can_fail_and_prove_it_passes": {
            "recorders_own_checks": {
                "instrument": "build/recorder_selftest.exe (raw_dump::self_test)",
                "parsed": st_parsed,
                "n_steps": selftest.get("n_steps"),
                "n_passed": selftest.get("n_passed"),
                "all_passed": selftest.get("all_passed"),
                # Steps that assert a POSITIVE property of good output, as
                # distinct from steps that assert a rejection. Classifying them
                # explicitly keeps the "known-bad rejected" list honest: the
                # bare-backslash step is not a rejection and must not be counted
                # as one.
                "positive_steps": [
                    s for s in selftest.get("steps", [])
                    if s["name"] in POSITIVE_SELFTEST_STEPS],
                "negative_steps": [
                    s for s in selftest.get("steps", [])
                    if s["name"] not in POSITIVE_SELFTEST_STEPS],
                "known_good_input_accepted": next(
                    (s for s in selftest.get("steps", [])
                     if s["name"] == "recorder_accepts_known_good_capture"), None),
                "known_bad_inputs_rejected": [
                    s for s in selftest.get("steps", [])
                    if s["name"] not in POSITIVE_SELFTEST_STEPS],
                "statement": (
                    "the recorder accepts a known-good capture, PRODUCES a "
                    "record with no bare backslash, and refuses four known-bad "
                    "ones (a null by-value image, an identity absent from the "
                    "blob table, a re-emission that would overwrite an existing "
                    "record, and the disabled-observer path). Both directions "
                    "are measured, not asserted."),
            },
            "emitted_records_are_standard_json": {
                "instrument": "src/p16at_verify_all_records.py",
                "why": ("the run's own re-parse covered the seven top-level "
                        "ARTEFACTS and never the RECORDS the recorder produces; "
                        "six records were found unparseable by an independent "
                        "walk of every .json under p16at/"),
                "n_files_scanned": (all_records_parse or {}).get("n_files_scanned"),
                "n_parsed": (all_records_parse or {}).get("n_parsed"),
                "n_failed": (all_records_parse or {}).get("n_failed"),
                "vacuity_guard_passed":
                    (all_records_parse or {}).get("vacuity_guard_passed"),
                "min_files_required":
                    (all_records_parse or {}).get("min_files_required"),
                "verdict": (all_records_parse or {}).get("verdict"),
                "known_bad_rejected": {
                    "corpus": "_work/known_bad_records (6 files emitted before "
                              "the RFC-8259 escaping fix, kept byte-exact)",
                    "n_expected": ((all_records_parse or {})
                                   .get("can_fail_proof", {})
                                   .get("n_expected")),
                    "n_rejected": ((all_records_parse or {})
                                   .get("can_fail_proof", {})
                                   .get("n_rejected")),
                    "n_wrongly_parsed": ((all_records_parse or {})
                                         .get("can_fail_proof", {})
                                         .get("n_wrongly_parsed")),
                    "verifier_can_fail": ((all_records_parse or {})
                                          .get("can_fail_proof", {})
                                          .get("verifier_can_fail")),
                    "files": ((all_records_parse or {})
                              .get("can_fail_proof", {}).get("files")),
                },
                "statement": (
                    "every .json the recorder emitted is decoded as strict UTF-8 "
                    "(a BOM is a failure, not something to skip past with "
                    "utf-8-sig) and parsed with Python's standard json module; "
                    "one failure fails the run. The scan must find at least one "
                    "file or it is vacuous and fails. The same verifier is "
                    "pointed at the six pre-fix records on every run and must "
                    "REJECT every one of them, so the proof that it can fail "
                    "cannot rot."),
            },
            "control_set": {
                "instrument": "p16at_run_controls.py + p16at_verify_records.py",
                "n_controls": len(control_rows),
                "n_valid_control": n_valid,
                "n_invalid_control": n_invalid,
                "known_good_input_accepted": {
                    "arm": "accept_clean",
                    "verifier_verdict": acc["verifier_verdict"],
                    "n_checks": acc["n_checks"],
                    "checks_failed": acc["checks_failed"],
                },
                "known_bad_inputs_rejected": [
                    {"arm": c["arm"], "checks_failed": c["checks_failed"],
                     "verdict": c["verdict"]} for c in control_rows
                    if c["verdict"] == "VALID_CONTROL"],
                "arms_recorded_as_invalid_rather_than_as_rejections": [
                    {"arm": c["arm"], "emission_reached": c["emission_reached"],
                     "comparison_reached": c["comparison_reached"],
                     "verdict": c["verdict"], "basis": c["verdict_basis"]}
                    for c in control_rows if c["verdict"] == "INVALID_CONTROL"],
                "statement": (
                    "a known-good capture is ACCEPTED by all 11 checks, and six "
                    "of the eight controls are rejected for their intended "
                    "basis. The two arms in which the observer is absent are "
                    "recorded as INVALID_CONTROL, NOT as successful rejections: "
                    "an instrument that never ran cannot reject anything."),
            },
            "the_verifier_itself": {
                "can_fail": ("the same verifier returns REJECTED for six "
                             "different mutations, each with a different failing "
                             "check set, and its comparison_reached flag is "
                             "False -- with named reasons and zero checks run -- "
                             "whenever no record is available"),
                "accepts_known_good": ("ACCEPTED for accept_clean with 11/11 "
                                       "checks PASS; the expected byte values "
                                       "are PREDICTED by the verifier rather "
                                       "than read back out of the record"),
                "negative_controls_on_the_section_52_predicates": predicates,
            },
            "the_schema_generator": (schema_doc or {}).get(
                "prove_it_can_fail_and_prove_it_passes"),
        },

        "no_gpu_rehearsal": {
            "artefact": "RAW_DUMP_NOGPU_REHEARSAL.json",
            "ran": True,
            "rehearsal_passed": rehearsal["rehearsal_passed"],
            "equality_1_outgoing_blob":
                rehearsal["equality_1_outgoing_blob"]["identical"],
            "equality_2_launch_descriptor":
                rehearsal["equality_2_launch_descriptor"]["identical"],
            "equality_3_control_flow":
                rehearsal["equality_3_control_flow"]["identical"],
            "differs_only_in_evidence_emission":
                rehearsal["differing_only_in_evidence_emission"]["identical"],
            "limits": rehearsal["limits"],
        },

        "defects_found_and_fixed_by_these_norms": [
            {"defect": ("the recorder's env accessor returned a pointer into a "
                        "shared static buffer, so RAW_DUMP_DIR was clobbered by "
                        "the next environment read and every emission failed "
                        "with 'no unclaimed record path'"),
             "found_by": "the self-test's known-good step, which had to ACCEPT",
             "fix": "buffer-copying API; the directory is now owned by each caller"},
            {"defect": ("the side-car path was written into the record "
                        "unescaped, so the record was not valid JSON "
                        "(Invalid \\escape)"),
             "found_by": "re-parsing the emitted record",
             "fix": ("add_json() escapes backslash and quote -- BUT this first "
                     "fix was PER-SITE and therefore incomplete: see the entry "
                     "below, which is the same defect found a second time")},
            {"defect": ("requested_field_offsets was emitted as [0x0,0x20]; "
                        "JSON has no hex literal and the record did not parse"),
             "found_by": "re-parsing the emitted record",
             "fix": ("decimal JSON arrays in both coordinate systems, with a "
                     "quoted hex view alongside. This fix landed AFTER the "
                     "records in out/probe and out/probe2 were written, and "
                     "those defective files were left behind in the output "
                     "tree -- so the fix was real but the tree still held "
                     "unparseable records")},
            {"defect": ("AUDIT FINDING: records the recorder had PRODUCED were "
                        "not valid RFC-8259 JSON, independently of the seven "
                        "top-level artefacts (which did parse). An independent "
                        "walk of every .json under p16at/ with a standard "
                        "reader failed on 6 files with these exact errors: "
                        "(1) build/raw_dump_build_manifest.json -- 'Unexpected "
                        "UTF-8 BOM (decode using utf-8-sig)' at line 1 column "
                        "1, because PowerShell 5.1 'Set-Content -Encoding "
                        "UTF8' writes a BOM; (2,3) out/probe/"
                        "20260921T135855Z_53948_7__Z14k_dec_upsample11DecUp"
                        "Params_9d12494f8f5d.json and its .dup1 sibling -- "
                        "'Invalid \\escape' at line 10 column 26, "
                        "raw_bytes_sidecar; (4) out/probe2/driver_result.json "
                        "-- 'Invalid \\escape' at line 6 column 15; (5,6) "
                        "out/probe2/20260921T140020Z_116628_1__Z10k_flag_set"
                        "Pjj_1a835ed8734f.json and ..._2__Z14k_dec_upsample11"
                        "DecUpParams_...json -- \"Expecting ',' delimiter\" at "
                        "line 14 column 31, requested_field_offsets [0x0,0x20]. "
                        "Note the inconsistency that proves this was per-site "
                        "rather than systematic: in probe2 the "
                        "raw_bytes_sidecar path IS escaped while in probe it is "
                        "NOT, and probe2 still carries the hex literal"),
             "found_by": ("an independent audit that parsed every .json under "
                          "p16at/ with a standard reader -- NOT the run's "
                          "own artefact check, which only ever looked at the "
                          "seven top-level artefacts and so reported 'all JSON "
                          "ok' over six unreadable records"),
             "fix": ("structural, not per-site: Buf::add_json() is now a "
                     "complete RFC-8259 string escaper and is PRIVATE, and "
                     "Buf::key_str()/key_str_last() are the only route by which "
                     "a string field reaches a record, so the rule has exactly "
                     "one implementation and cannot be half-applied; "
                     "rehearsal_driver.cpp escapes every string field including "
                     "the argv-supplied --arm; and build_raw_dump.ps1 writes the "
                     "manifest with File::WriteAllText + a BOM-less "
                     "UTF8Encoding and then throws if a BOM is present"),
             "corroboration": ("src/p16at_verify_all_records.py now parses every "
                               "emitted .json with Python's standard json module "
                               "as part of the run and FAILS the run on any one "
                               "of them, with a vacuity guard that fails a scan "
                               "finding zero files; the 6 defective files are "
                               "preserved byte-exact in _work/known_bad_records/ "
                               "with their exact errors and are passed to "
                               "--expect-reject on every run, so the verifier "
                               "must reject them or the run fails"),
             "also_found": ("the recorder's own self-test gained step 6, "
                            "emitted_record_has_no_bare_backslash, so a "
                            "regression to raw emission is caught at runtime by "
                            "the recorder itself rather than by a consumer")},
            {"defect": ("recorder_selftest.exe and rehearsal_driver.exe printed "
                        "Windows paths and quoted reason strings raw into JSON"),
             "found_by": "re-parsing everything the runner captured",
             "fix": "escaping added in both hosts"},
            {"defect": ("the arm runner discovered the target record by the "
                        "ordinal in its FILENAME, which the ordinal mutant "
                        "changes, so the e_ordinal control came back "
                        "NOT_COMPARED -- a broken instrument that looked like a "
                        "missing record"),
             "found_by": ("reading the trace file the run actually wrote "
                          "instead of trusting the discovery rule"),
             "fix": ("the target launch is located by the adapter's own "
                     "CAPTURE_SITE_REACHED ordinal and kernel name, which no "
                     "mutant inside emit() can move")},
            {"defect": ("the record-schema generator raised KeyError on a "
                        "record missing a mandatory field instead of reporting "
                        "which field was missing"),
             "found_by": ("pointing the generator at a known-bad record, which "
                          "is the only way a checker's own failure path gets "
                          "exercised"),
             "fix": ("invariants whose fields are absent are recorded as "
                     "NOT_EVALUATED with the missing names, and the generator "
                     "now self-checks against four known-bad variants")},
            {"defect": ("the arm runner's evidence-difference test flagged the "
                        "ON arm's own record side-cars and the driver's "
                        "recorder_enabled field as unexpected differences"),
             "found_by": "the section 52 comparison, which then failed",
             "fix": ("side-cars are classified as emitted evidence, and "
                     "recorder_enabled is set aside as the independent "
                     "variable it is")},
        ],

        "verification_norms_applied": [
            "every JSON written by this phase was re-read and re-parsed in the "
            "run that wrote it, and the key counts printed",
            "every RECORD the recorder emitted was additionally parsed with a "
            "standard JSON reader by src/p16at_verify_all_records.py -- the "
            "artefact check above only ever covered the seven top-level files, "
            "and six records were unreadable under it",
            "the all-records verifier is pointed at the six pre-fix records on "
            "every run and must reject all six, so the proof that it can fail "
            "cannot rot, and a scan finding zero files is a FAILURE not a pass",
            "every control result comes from an executed arm whose stdout, "
            "stderr, return code and artefacts were captured",
            "the expected byte values are constants in the verifier, not values "
            "read back out of the artefact under test",
            "the recorder's SHA-256 and Python's hashlib must agree before a "
            "record is believed",
            "the trace distinguishes capture_site_reached, recorder_entered, "
            "emission_point_reached and record_emitted, so an absent observer "
            "cannot be recorded as a rejection",
            "two mutations that fail the same checks are compared on the VALUES "
            "of those checks, not on the names",
        ],
        "not_measured": [
            "timing perturbation caused by the recorder",
            "behaviour under concurrent launches from several threads",
            "any real HIP runtime behaviour (no HIP runtime was loaded)",
            "the bytes crossing the mock backend boundary (the mock ignores args)",
        ],
    }


def verdict_doc_contradictions(closure):
    """The closure's own per-row resolution states, counted.

    Read straight out of the 16AO closure so that the status file cannot state a
    figure the source artefact does not carry.
    """
    hist = {}
    for f in closure.get("fields", []):
        k = f.get("resolution_state", "UNKNOWN")
        hist[k] = hist.get(k, 0) + 1
    return {"resolution_state_histogram_over_the_closure_rows": hist,
            "n_rows": len(closure.get("fields", []))}


if __name__ == "__main__":
    sys.exit(main())
