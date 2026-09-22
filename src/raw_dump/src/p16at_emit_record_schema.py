#!/usr/bin/env python3
"""Phase 16AT RAW_DUMP -- generate RAW_DUMP_SCHEMA.json from a REAL record.

The schema is not written from memory. It is derived from one record the
recorder actually emitted during the no-GPU rehearsal, and it FAILS if the
record and the declared field table disagree in either direction: a field the
table declares but the record lacks, or a field the record carries but the table
does not describe.

That is deliberate. A schema document that cannot disagree with an artefact is
prose, and this project has already shipped one of those.

Usage:
  python p16at_emit_record_schema.py [--record <path>] [--json <out>]
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DUMP = os.path.dirname(HERE)
DEFAULT_RECORD_DIR = os.path.join(RAW_DUMP, "out", "accept_clean")

# The nine fields brief IX section 49 makes mandatory for EVERY capture. This
# list is the brief's, and the run refuses if the record does not carry all of
# them.
SECTION_49 = ["frame_id", "launch_ordinal", "kernel_identity",
              "raw_blob_length", "raw_bytes", "sha256", "timestamp_utc",
              "source_callsite", "requested_field_offsets"]

# field -> (json type, origin, meaning, constraint)
FIELDS = {
    "schema": ("string", "16AT", "the record schema id",
               'always "p16at/raw-dump-record/1"'),
    "frame_id": ("integer|null", "section 49",
                 "the first-frame ordinal this launch belongs to; null until a "
                 "frame-start marker has been seen",
                 "null XOR an integer >= 1; never 0, because 'no marker yet' "
                 "and 'frame 0' are different facts"),
    "frame_id_source": ("string", "16AT",
                        "where frame_id came from, so a derived value is never "
                        "mistaken for a measured one",
                        '"MARKER_K_FLAG_SET" | "ENV_OVERRIDE_RAW_DUMP_FRAME_ID" '
                        '| "NO_MARKER_SEEN_YET"'),
    "launch_ordinal": ("integer", "section 49",
                       "the bridge's per-process launch counter for this launch",
                       "matches the LAUNCH_ATTEMPT ordinal in the same run's "
                       "bridge.log (subject to the identity of the record's "
                       "kernel)"),
    "kernel_identity": ("string", "section 49",
                        "the registered device (mangled) name of the kernel",
                        "one of the 15 identities in RAW_DUMP_BLOB_TABLE.json"),
    "raw_blob_length": ("integer", "section 49",
                        "how many bytes of the by-value image were read",
                        "> 0 and <= 4096 (the hard cap); equals the length of "
                        "raw_bytes/2 and of the side-car file"),
    "raw_bytes": ("string", "section 49",
                  "the captured by-value image, hex, lowercase, no separators",
                  "2 * raw_blob_length hex characters; sha256 over its decoded "
                  "bytes equals this record's sha256"),
    "raw_bytes_encoding": ("string", "16AT", "how raw_bytes is spelled",
                           'always "HEX_LOWERCASE"'),
    "raw_bytes_sidecar": ("string", "16AT",
                          "absolute path of the side-car holding the same bytes "
                          "as raw_bytes",
                          "the file exists and its bytes are identical to the "
                          "decoded raw_bytes"),
    "sha256": ("string", "section 49",
               "SHA-256 of the captured bytes",
               "64 lowercase hex characters; recomputed independently by the "
               "verifier with a second implementation"),
    "timestamp_utc": ("string", "section 49",
                      "UTC instant of emission, ISO-8601 with milliseconds",
                      "YYYY-MM-DDTHH:MM:SS.mmmZ"),
    "source_callsite": ("string", "section 49",
                        "the exact point in the shipping bridge the capture was "
                        "taken from",
                        "identifies amdhip64_7.cpp:hipLaunchKernel, after "
                        "decode_launch_args and before the gate and the backend"),
    "requested_field_offsets": ("array<integer>", "section 49",
                                "the byte offsets in the captured image whose "
                                "values the 15 unresolved fields live at, "
                                "BLOB-relative. DECIMAL JSON INTEGERS (0, 32) "
                                "-- not hex literals: an earlier generation "
                                "emitted [0x0,0x20], which no standard reader "
                                "accepts. The hex spelling is carried "
                                "separately, as a quoted string, in "
                                "requested_field_offsets_hex",
                                "each 0 <= off < raw_blob_length; equal to the "
                                "16AO closure's derived offsets for this "
                                "identity"),
    "requested_field_offsets_basis": ("string", "16AT",
                                      "the coordinate system of the array above",
                                      'always "BLOB_RELATIVE"'),
    "requested_field_offsets_hex": ("string", "16AT",
                                    "the same offsets in 16AO's hex spelling",
                                    "comma-separated 0x-prefixed values, in the "
                                    "same order as requested_field_offsets"),
    "requested_field_offsets_kernarg_relative": ("array<integer>", "16AT",
                                                 "the same offsets in the "
                                                 "kernarg's own coordinates",
                                                 "each equals the blob-relative "
                                                 "offset plus kernarg_range_lo"),
    "declared_by_value_blob_bytes": ("integer", "16AT",
                                     "the by-value size the code object's own "
                                     "metadata declares for this identity",
                                     "comes from the shipping table row for "
                                     "kernel_identity, never from the caller"),
    "kernarg_range_lo": ("integer", "16AT",
                         "the low end of this identity's by-value range, as "
                         "16AO recorded it",
                         "declared_by_value_blob_bytes equals the range width"),
    "kernarg_read_offsets_hex": ("string", "16AT",
                                 "the kernarg-relative offsets in hex",
                                 "same order as the two arrays above"),
    "blob_stable_during_capture": ("boolean", "16AT",
                                   "the image was read twice and the two reads "
                                   "agreed; a mismatch is refused rather than "
                                   "recorded",
                                   "always true in a written record: a false "
                                   "value causes a refusal, not a record"),
    "process_id": ("integer", "16AT", "the emitting process id",
                   "matches the pid in the run's logs"),
    "thread_id": ("integer", "16AT", "the emitting thread id",
                  "recorded because the recorder is reachable from more than "
                  "one thread"),
    "blob_table_source": ("string", "16AT",
                          "the artefact the declared sizes and offsets came from",
                          "p16ao/contracts/FIRST_FRAME_FIELD_CLOSURE.json"),
    "capture_point": ("string", "16AT",
                      "which side of the gate and the submission the capture "
                      "was taken on",
                      "always "
                      '"BEFORE_LAUNCH_GATE_AND_BEFORE_BACKEND_SUBMISSION"'),
}


def jtype(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array<%s>" % (jtype(v[0]) if v else "any")
    return "object"


def find_record(d):
    """The richest record in the directory: the one with the most requested
    offsets win, then the longest blob. A schema derived from the simplest
    record would leave the offset-list fields undescribed by example."""
    if not os.path.isdir(d):
        return None
    best, best_key = None, (-1, -1)
    for n in sorted(os.listdir(d)):
        if not (n.endswith(".json") and "__Z" in n):
            continue
        try:
            with open(os.path.join(d, n), "rb") as f:
                r = json.loads(f.read().decode("utf-8"))
            key = (len(r.get("requested_field_offsets", [])),
                   int(r.get("raw_blob_length", 0)))
        except Exception:                                         # noqa: BLE001
            continue
        if key > best_key:
            best, best_key = os.path.join(d, n), key
    return best


def validate(rec):
    """Every check this generator makes about one record.

    Returns (problems, invariants, not_evaluated, type_mismatch). Extracted from
    main() so the same checks can be pointed at known-bad records -- a checker
    that has never rejected anything is not evidence.
    """
    problems = []
    missing_49 = [k for k in SECTION_49 if k not in rec]
    if missing_49:
        problems.append("record lacks mandatory section 49 fields: %s"
                        % missing_49)
    declared = list(FIELDS)
    undeclared = [k for k in rec if k not in FIELDS]
    undescribed = [k for k in declared if k not in rec]
    if undeclared:
        problems.append("record carries fields the schema does not describe: %s"
                        % undeclared)
    if undescribed:
        problems.append("schema declares fields the record does not carry: %s"
                        % undescribed)

    # observed types must agree with the declared ones
    type_mismatch = []
    for k, v in rec.items():
        if k not in FIELDS:
            continue
        want = FIELDS[k][0]
        got = jtype(v)
        ok = (want == got) or (want == "integer|null" and got in
                               ("integer", "null"))
        if not ok:
            type_mismatch.append({"field": k, "declared": want, "observed": got})
    if type_mismatch:
        problems.append("observed types disagree with the schema: %s"
                        % type_mismatch)

    # cross-field invariants, measured rather than asserted. An invariant whose
    # fields are absent is recorded as NOT_EVALUATED with the missing names --
    # a crash is not a verdict, and a checker that dies on a malformed record
    # cannot tell you what was wrong with it.
    import hashlib
    not_evaluated = []

    def inv(name, needs, fn):
        absent = [k for k in needs if k not in rec]
        if absent:
            not_evaluated.append({"invariant": name, "missing_fields": absent})
            return None
        try:
            return bool(fn())
        except Exception as e:                                    # noqa: BLE001
            not_evaluated.append({"invariant": name,
                                  "error": "%s: %s" % (type(e).__name__, e)})
            return None

    invariants = {
        "raw_bytes_decodes_to_raw_blob_length_bytes": inv(
            "raw_bytes_decodes_to_raw_blob_length_bytes",
            ["raw_bytes", "raw_blob_length"],
            lambda: len(bytes.fromhex(rec["raw_bytes"])) ==
            rec["raw_blob_length"]),
        "sha256_over_the_decoded_bytes_equals_the_record_digest": inv(
            "sha256_over_the_decoded_bytes_equals_the_record_digest",
            ["raw_bytes", "sha256"],
            lambda: hashlib.sha256(bytes.fromhex(rec["raw_bytes"])).hexdigest()
            == rec["sha256"]),
        "side_car_exists_and_holds_the_same_bytes": inv(
            "side_car_exists_and_holds_the_same_bytes",
            ["raw_bytes", "raw_bytes_sidecar"],
            lambda: os.path.exists(rec["raw_bytes_sidecar"]) and
            open(rec["raw_bytes_sidecar"], "rb").read() ==
            bytes.fromhex(rec["raw_bytes"])),
        "requested_field_offsets_are_inside_the_blob": inv(
            "requested_field_offsets_are_inside_the_blob",
            ["requested_field_offsets", "raw_blob_length"],
            lambda: all(0 <= o < rec["raw_blob_length"]
                        for o in rec["requested_field_offsets"])),
        "kernarg_relative_offsets_equal_blob_relative_plus_lo": inv(
            "kernarg_relative_offsets_equal_blob_relative_plus_lo",
            ["requested_field_offsets", "kernarg_range_lo",
             "requested_field_offsets_kernarg_relative"],
            lambda: [o + rec["kernarg_range_lo"]
                     for o in rec["requested_field_offsets"]] ==
            rec["requested_field_offsets_kernarg_relative"]),
        "declared_by_value_blob_bytes_equals_raw_blob_length": inv(
            "declared_by_value_blob_bytes_equals_raw_blob_length",
            ["declared_by_value_blob_bytes", "raw_blob_length"],
            lambda: rec["declared_by_value_blob_bytes"] ==
            rec["raw_blob_length"]),
        "blob_stable_during_capture_is_true": inv(
            "blob_stable_during_capture_is_true", ["blob_stable_during_capture"],
            lambda: rec["blob_stable_during_capture"] is True),
        "frame_id_and_its_source_agree": inv(
            "frame_id_and_its_source_agree", ["frame_id", "frame_id_source"],
            lambda: (rec["frame_id"] is None) ==
            (rec["frame_id_source"] == "NO_MARKER_SEEN_YET")),
        "schema_id_is_the_declared_one": inv(
            "schema_id_is_the_declared_one", ["schema"],
            lambda: rec["schema"] == "p16at/raw-dump-record/1"),
        "capture_point_is_the_declared_one": inv(
            "capture_point_is_the_declared_one", ["capture_point"],
            lambda: rec["capture_point"] ==
            "BEFORE_LAUNCH_GATE_AND_BEFORE_BACKEND_SUBMISSION"),
    }
    failed = [k for k, v in invariants.items() if v is False]
    if failed:
        problems.append("cross-field invariants failed: %s" % failed)
    if not_evaluated:
        problems.append("cross-field invariants not evaluated: %s"
                        % [e["invariant"] for e in not_evaluated])
    return problems, invariants, not_evaluated, type_mismatch


def build_variant(rec, kind):
    """A known-bad record. Each one breaks exactly one thing."""
    import copy
    v = copy.deepcopy(rec)
    if kind == "mandatory_field_removed":
        v.pop("requested_field_offsets", None)
        return v, "a mandatory section 49 field is missing"
    if kind == "digest_does_not_match_the_bytes":
        v["sha256"] = "0" * 64
        return v, "sha256 does not hash the recorded bytes"
    if kind == "undeclared_extra_field":
        v["surprise"] = 1
        return v, "the record carries a field the schema does not describe"
    if kind == "kernarg_offsets_disagree":
        v["requested_field_offsets_kernarg_relative"] = [
            o + v["kernarg_range_lo"] + 4
            for o in v["requested_field_offsets"]]
        return v, "the two offset coordinate systems disagree"
    raise ValueError(kind)


def selfcheck(rec):
    """Point the same checks at one known-good and four known-bad records."""
    good_problems, _, _, _ = validate(rec)
    cases = []
    for kind in ("mandatory_field_removed", "digest_does_not_match_the_bytes",
                 "undeclared_extra_field", "kernarg_offsets_disagree"):
        bad, why = build_variant(rec, kind)
        p, _, _, _ = validate(bad)
        cases.append({"case": kind, "breaks": why,
                      "n_problems": len(p), "problems": p,
                      "rejected": bool(p)})
    return {
        "what_this_is": (
            "The generator's own checks, pointed at one known-good record and "
            "four known-bad variants of it. Both directions are measured: a "
            "checker that has never rejected anything is not evidence."),
        "known_good_accepted": not good_problems,
        "known_good_problems": good_problems,
        "known_bad_cases": cases,
        "n_known_bad": len(cases),
        "n_known_bad_rejected": sum(1 for c in cases if c["rejected"]),
        "all_known_bad_rejected": all(c["rejected"] for c in cases),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", default=None)
    ap.add_argument("--json", default=os.path.join(RAW_DUMP,
                                                   "RAW_DUMP_SCHEMA.json"))
    a = ap.parse_args()

    rec_path = a.record or find_record(DEFAULT_RECORD_DIR)
    if not rec_path or not os.path.exists(rec_path):
        print("no record to derive the schema from (%r)" % rec_path)
        return 2

    with open(rec_path, "rb") as f:
        import hashlib
        body = f.read()
        rec = json.loads(body.decode("utf-8"))
        rec_file_sha = hashlib.sha256(body).hexdigest()

    problems, invariants, not_evaluated, type_mismatch = validate(rec)
    failed = [k for k, v in invariants.items() if v is False]
    declared = list(FIELDS)
    checks = selfcheck(rec)

    out = {
        "schema": "p16at/raw-dump-schema/1",
        "phase": "16AT",
        "record_schema_id": "p16at/raw-dump-record/1",
        "what_this_is": (
            "The record schema for a RAW_DUMP capture, DERIVED from a record the "
            "recorder actually emitted during the no-GPU rehearsal. It is not "
            "written from memory: the generator fails if the record and this "
            "table disagree in either direction, and it evaluates the "
            "cross-field invariants against the record's own values."),
        "derived_from": {
            "record_path": rec_path,
            "record_file_sha256": rec_file_sha,
            "record_sha256_of_raw_bytes": rec["sha256"],
            "kernel_identity": rec["kernel_identity"],
            "raw_blob_length": rec["raw_blob_length"],
            "arm": "accept_clean (the no-GPU rehearsal's positive reference)",
        },
        "no_gpu": True,
        "gpu_execution_performed": False,
        "capture_point": {
            "file": "phase16_bridge_telemetry/src/amdhip64_7.cpp",
            "function": "hipLaunchKernel",
            "anchor_statement_and_line_in_the_original":
                "    decode_launch_args(name, args);  (line 584 of 607)",
            "inserted_call":
                "raw_dump_at_launch_capture_point(name, function_address, "
                "args, launch_ordinal);",
            "inserted_call_line_in_the_transformed_copy": 586,
            "why_after_construction_and_before_packing":
                "the caller has already materialised every by-value parameter "
                "and built the void** args array before entering the bridge, so "
                "the complete image exists at this statement; decode_launch_args "
                "only reads it. The only two operations in the bridge that could "
                "change its representation -- the fail-closed gate's early return "
                "and the backend submission fn(...) -- both come after it.",
            "original_file_modified": False,
        },
        "ordering_guarantees": [
            "the capture is taken after the complete host by-value image exists "
            "and before any packing or submission",
            "the capture is taken BEFORE the fail-closed launch gate: with the "
            "gate OFF the capture still runs and still emits, which the "
            "probe_gate_off arm measures",
            "the recorder traces CAPTURE_SITE_REACHED (adapter), "
            "RECORDER_ENTERED (before the enable gate), EMISSION_POINT_REACHED "
            "(after the enable gate, before any validation) and RECORD_WRITTEN "
            "(after the bytes reach the disk), so reach is measurable at four "
            "distinct points and an absent observer cannot be confused with a "
            "rejection",
            "the record and its side-car are created with CREATE_NEW: an "
            "existing file is never overwritten, a collision retries as .dupN",
            "the trace log is append-only, because losing a line to "
            "'already exists' would hide reach",
        ],
        "write_once": {
            "applies_to": ["the record .json", "the .bin side-car"],
            "mechanism": "CreateFileA(..., CREATE_NEW) with a .dupN retry",
            "path_uniqueness": ("<UTCstamp>_<pid>_<ordinal>_<identity stem>_"
                                "<sha256 first 12>"),
            "refuses_to_clobber": True,
            "proved_by": "recorder_selftest step "
                         "recorder_never_overwrites_an_existing_record",
        },
        "section_49_mandatory_fields": SECTION_49,
        "n_fields": len(declared),
        "fields": [
            {"name": k,
             "type": FIELDS[k][0],
             "origin": FIELDS[k][1],
             "mandatory_by_section_49": k in SECTION_49,
             "meaning": FIELDS[k][2],
             "constraint": FIELDS[k][3],
             "observed_type_in_the_derived_record": jtype(rec[k]),
             "observed_value_example": (rec[k] if isinstance(rec[k], (int, bool))
                                        or rec[k] is None else
                                        (rec[k] if len(str(rec[k])) <= 120
                                         else str(rec[k])[:117] + "..."))}
            for k in declared
        ],
        "invariants_evaluated_against_the_derived_record": invariants,
        "n_invariants": len(invariants),
        "n_invariants_failed": len(failed),
        "n_invariants_not_evaluated": len(not_evaluated),
        "invariants_not_evaluated": not_evaluated,
        "type_mismatches": type_mismatch,
        "prove_it_can_fail_and_prove_it_passes": checks,
        "problems": problems,
        "verdict": "SCHEMA_MATCHES_A_REAL_RECORD" if not problems
                   else "SCHEMA_DISAGREES_WITH_THE_RECORD",
    }

    with open(a.json, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print("record        %s" % rec_path)
    print("fields        %d declared, %d in the record, %d mandatory by section 49"
          % (len(declared), len(rec), len(SECTION_49)))
    print("invariants    %d evaluated, %d failed, %d not evaluated"
          % (len(invariants), len(failed), len(not_evaluated)))
    print("selfcheck     known_good_accepted=%s known_bad_rejected=%d/%d"
          % (checks["known_good_accepted"], checks["n_known_bad_rejected"],
             checks["n_known_bad"]))
    print("verdict       %s" % out["verdict"])
    for p in problems:
        print("  PROBLEM %s" % p)
    print("wrote         %s" % a.json)
    return 0 if (not problems and checks["all_known_bad_rejected"]
                 and checks["known_good_accepted"]) else 1


if __name__ == "__main__":
    sys.exit(main())
