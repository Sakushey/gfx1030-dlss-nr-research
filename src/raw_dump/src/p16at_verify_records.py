#!/usr/bin/env python3
"""Phase 16AT RAW_DUMP -- the comparison point.

Reads ONE record emitted by the recorder during a rehearsal arm, plus the
ground truth that arm's driver wrote, and decides ACCEPT or REJECT with a named
basis for every check. It never writes the record it verifies.

Every check is independent and is reported individually, because "rejected" and
"rejected for the reason I intended" are different facts and this project has
already counted a broken instrument as a rejection.

The expected values come from two INDEPENDENT sources, neither of which is the
recorder's own table:
  * p16ao/contracts/FIRST_FRAME_FIELD_CLOSURE.json -- the declared by-value
    size and the ISA-derived read offsets, read straight from that artefact.
  * the arm's own fixture: the driver-written bytes, and the byte patterns this
    verifier PREDICTS at the requested offsets rather than reading back out of
    the record.

Usage:
  python p16at_verify_records.py --record <path|-> --run-dir <dir>
                                 --target-identity <id> --expected-ordinal <n>
                                 [--json <out>]
`--record -` means "no record was emitted"; every check then reports NOT_REACHED
and comparison_reached is false.
"""

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DUMP = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(RAW_DUMP))
CLOSURE = os.path.join(ROOT, "p16ao", "contracts",
                       "FIRST_FRAME_FIELD_CLOSURE.json")

# The nine fields brief IX section 49 requires of every capture.
REQUIRED_FIELDS = ["frame_id", "launch_ordinal", "kernel_identity",
                   "raw_blob_length", "raw_bytes", "sha256", "timestamp_utc",
                   "source_callsite", "requested_field_offsets"]

# Values this verifier PREDICTS, baked into the fixture by the rehearsal driver.
# They are constants here on purpose: reading them back out of the artefact
# under test would make the check circular.
PREDICTED = {
    "_Z14k_dec_upsample11DecUpParams": {0x00: "0000000040000002",
                                        0x20: "dec0de01"},
    "_Z10k_flag_setPjj": {0x00: "11223344"},
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def closure_row(identity):
    with open(CLOSURE, "rb") as f:
        d = json.loads(f.read().decode("utf-8"))
    for fld in d["fields"]:
        if fld["identity"] == identity:
            lo = int(fld["declared_by_value_blob_range_bytes"][0], 16)
            return {
                "identity": identity,
                "blob_bytes": int(fld["declared_by_value_blob_bytes"]),
                "kernarg_range_lo": lo,
                "blob_offsets": sorted(
                    int(x, 16) - lo
                    for x in fld["part_a_static_read_structure"]
                                 ["what_was_derived"]["blob_offsets_read"]),
            }
    return None


def bridge_log_ordinal(run_dir, identity):
    """The ordinal the BRIDGE printed for this kernel's LAUNCH_ATTEMPT."""
    p = os.path.join(run_dir, "bridge.log")
    if not os.path.exists(p):
        return None
    seen = []
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "LAUNCH_ATTEMPT" not in line:
                continue
            if ('kernel="%s"' % identity) not in line:
                continue
            for tok in line.split():
                if tok.startswith("ordinal="):
                    seen.append(int(tok.split("=", 1)[1]))
    return seen[-1] if seen else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", required=True)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--target-identity", required=True)
    ap.add_argument("--expected-ordinal", type=int, required=True)
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    checks = []

    def chk(name, ok, detail):
        checks.append({"check": name, "result": "PASS" if ok else "FAIL",
                       "detail": detail})
        return ok

    # ---- preconditions for a comparison to exist at all -------------------
    record_path = None if a.record == "-" else a.record
    rec = None
    parse_err = ""
    if record_path and os.path.exists(record_path):
        try:
            with open(record_path, "rb") as f:
                rec = json.loads(f.read().decode("utf-8"))
        except Exception as e:                                   # noqa: BLE001
            parse_err = "%s: %s" % (type(e).__name__, e)

    fixture_path = os.path.join(a.run_dir, "fixture_blob.bin")
    post_path = os.path.join(a.run_dir, "post_launch_blob.bin")
    fixture = open(fixture_path, "rb").read() if os.path.exists(fixture_path) else None
    post = open(post_path, "rb").read() if os.path.exists(post_path) else None
    row = closure_row(a.target_identity)
    log_ord = bridge_log_ordinal(a.run_dir, a.target_identity)

    comparison_reached = bool(rec is not None and fixture is not None and
                              row is not None and log_ord is not None)
    if not comparison_reached:
        reasons = []
        if rec is None:
            reasons.append("no record to compare (path=%r, parse_error=%r)"
                           % (record_path, parse_err))
        if fixture is None:
            reasons.append("fixture_blob.bin absent")
        if row is None:
            reasons.append("target identity absent from the 16AO closure")
        if log_ord is None:
            reasons.append("no LAUNCH_ATTEMPT line for the target in bridge.log")
        out = {
            "schema": "p16at/raw-dump-verification/1",
            "record_loaded": None,
            "comparison_reached": False,
            "comparison_not_reached_because": reasons,
            "checks": [],
            "n_checks": 0,
            "n_failed": 0,
            "verdict": "NOT_COMPARED",
            "accepted": None,
            "rejection_basis": [],
        }
        emit(out, a.json)
        return 0

    # ---- C1: the record parses and carries every field section 49 names ---
    missing = [f for f in REQUIRED_FIELDS if f not in rec]
    chk("C1_record_carries_every_section_49_field", not missing,
        "missing=%s n_fields=%d" % (missing, len(rec)))

    raw = bytes.fromhex(rec["raw_bytes"]) if isinstance(rec.get("raw_bytes"), str) else b""
    rec_sha = rec.get("sha256")

    chk("C2_sha256_of_the_raw_bytes_field_equals_the_record_sha256",
        sha(raw) == rec_sha,
        "sha256(raw_bytes)=%s record.sha256=%s len=%d" % (sha(raw), rec_sha, len(raw)))

    sidecar = rec.get("raw_bytes_sidecar")
    sc_ok = False
    sc_detail = "no raw_bytes_sidecar field"
    if isinstance(sidecar, str) and os.path.exists(sidecar):
        sb = open(sidecar, "rb").read()
        sc_ok = (sha(sb) == rec_sha and sb == raw)
        sc_detail = "sidecar=%s bytes=%d sha=%s" % (sidecar, len(sb), sha(sb))
    elif isinstance(sidecar, str):
        sc_detail = "sidecar path does not exist: %s" % sidecar
    chk("C3_side_car_bytes_equal_the_inline_hex_and_carry_the_same_digest",
        sc_ok, sc_detail)

    chk("C4_recorded_bytes_equal_the_fixture_image",
        raw == fixture,
        "record=%s fixture=%s" % (raw.hex(), fixture.hex()))

    chk("C5_raw_blob_length_equals_the_16ao_declared_size",
        int(rec.get("raw_blob_length", -1)) == row["blob_bytes"] == len(raw),
        "record.raw_blob_length=%s 16ao=%d len(raw_bytes)=%d"
        % (rec.get("raw_blob_length"), row["blob_bytes"], len(raw)))

    chk("C6_kernel_identity_equals_the_expected_identity",
        rec.get("kernel_identity") == a.target_identity,
        "record=%r expected=%r" % (rec.get("kernel_identity"), a.target_identity))

    chk("C7_launch_ordinal_equals_the_bridge_log_ordinal",
        int(rec.get("launch_ordinal", -1)) == log_ord == a.expected_ordinal,
        "record=%s bridge_log=%s driver_expected=%s"
        % (rec.get("launch_ordinal"), log_ord, a.expected_ordinal))

    chk("C8_requested_field_offsets_equal_the_16ao_derived_offsets",
        list(rec.get("requested_field_offsets", [])) == row["blob_offsets"],
        "record=%s 16ao=%s" % (rec.get("requested_field_offsets"),
                               row["blob_offsets"]))

    # ---- C9: the values at the requested offsets, PREDICTED not read back --
    pred = PREDICTED.get(a.target_identity, {})
    bad = []
    for off, want in sorted(pred.items()):
        if off + len(want) // 2 > len(raw):
            bad.append("offset 0x%x beyond the recorded bytes" % off)
            continue
        got = raw[off:off + len(want) // 2].hex()
        if got != want:
            bad.append("0x%x got %s want %s" % (off, got, want))
    chk("C9_bytes_at_the_requested_offsets_equal_the_predicted_values",
        not bad and bool(pred),
        "predicted=%s mismatches=%s" % (
            {hex(k): v for k, v in pred.items()}, bad))

    chk("C10_record_digest_equals_the_digest_of_the_post_launch_image",
        post is not None and sha(post) == rec_sha,
        "post_launch=%s record.sha256=%s post_mutated=%s"
        % (sha(post) if post is not None else None, rec_sha,
           (post != fixture) if post is not None else None))

    chk("C11_declared_by_value_blob_bytes_equals_raw_blob_length",
        int(rec.get("declared_by_value_blob_bytes", -1)) ==
        int(rec.get("raw_blob_length", -2)),
        "declared=%s raw_blob_length=%s"
        % (rec.get("declared_by_value_blob_bytes"), rec.get("raw_blob_length")))

    failed = [c["check"] for c in checks if c["result"] == "FAIL"]
    out = {
        "schema": "p16at/raw-dump-verification/1",
        "record_loaded": record_path,
        "record_sha256": rec_sha,
        "comparison_reached": True,
        "target_identity": a.target_identity,
        "expected_ordinal": a.expected_ordinal,
        "bridge_log_ordinal": log_ord,
        "checks": checks,
        "n_checks": len(checks),
        "n_failed": len(failed),
        "verdict": "REJECTED" if failed else "ACCEPTED",
        "accepted": not failed,
        "rejection_basis": failed,
    }
    emit(out, a.json)
    return 0


def emit(out, path):
    txt = json.dumps(out, indent=1)
    if path:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    sys.exit(main())
