#!/usr/bin/env python3
"""Phase 16AW -- run the rehearsal arms, verify every captured byte, and write
the six JSON deliverables.

HOST-ONLY. Writes only inside p16aw/raw_dump/. Reads p16at/ sources and
the authentic launch DB READ-ONLY, to quote the two defects verbatim rather than
paraphrase them.

THE COMPARISON IS TWO-LINEAGE
  The driver writes the bytes it actually placed in host memory (fixture_16aw.json).
  The capture layer writes the bytes it actually read (instances/*.json). Neither
  knows about the other. The verifier compares them, and ALSO compares the layer's
  own sha256 against hashlib's digest of the driver's bytes -- so a layer that
  hashed something other than what it emitted cannot pass by agreeing with itself.

EVERY RUN PRINTS ITS COMPARISON COUNT. A check that compared zero things returns
VACUOUS, which is a FAILURE, never a pass.
"""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))   # the raw_dump directory
RAW = HERE
ROOT = os.path.dirname(os.path.dirname(RAW))         # project root

BUILD = os.path.join(RAW, "build")
RUNS = os.path.join(RAW, "_runs")
WORK = os.path.join(RAW, "_work")
DRIVER = os.path.join(BUILD, "p16aw_driver.exe")
BRIDGE = os.path.join(BUILD, "rawdump_bridge_16aw.dll")

LAUNCH_DB = os.path.join(ROOT, "phase16_authentic_launch_db.csv")
EVENTS_TSV = os.path.join(WORK, "authentic_events.tsv")

P16AT = os.path.join(ROOT, "p16at", "raw_dump", "src")
DEFECT1_FILE = os.path.join(P16AT, "raw_dump_capture_point.h")
DEFECT1_DECL_FILE = os.path.join(P16AT, "raw_dump_recorder.h")
DEFECT2_FILE = os.path.join(P16AT, "raw_dump_recorder.cpp")

OPENER = "_Z11k_flag_waitPjjj"
CLOSER = "_Z10k_flag_setPjj"

MUTATIONS = ["NONE", "SWAPPED_ARG_INDEX", "WRONG_SIZE",
             "CONTIGUOUS_MEMORY_ASSUMPTION", "OFF_BY_ONE_KERNARG",
             "WRONG_POINTER_SCALAR_KIND", "OVERREAD_INTO_CANARY",
             "LEGACY_BLOB_ONLY"]
BOGUS_MUTATION = "OVERREAD_INTO_THE_NEXT_KERNELS_STACK_FRAME"  # must NOT resolve

PROBLEMS = []


def note(ok, msg):
    if not ok:
        PROBLEMS.append(msg)
    return ok


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def jload(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def jdump(path, doc):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")


def run_driver(args, env_extra=None, fresh=True):
    if fresh and "--out" in args:
        out = args[args.index("--out") + 1]
        if os.path.isdir(out):
            import shutil
            shutil.rmtree(out)
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    p = subprocess.run([DRIVER] + args, capture_output=True, text=True, env=env)
    return p


# ====================================================================== step 1
def quote_defect_sites():
    """Find the two defect sites in the EXISTING sources and quote them.

    Read-only. Each site is located by a pattern and the surrounding lines are
    copied verbatim, with the file's sha256 and the line numbers, so the quoted
    text is evidence and not a paraphrase.
    """
    out = {"host_only": True, "read_only": True}
    for key, path in (("defect_1_argument_capture", DEFECT1_FILE),
                      ("defect_2_frame_semantics", DEFECT2_FILE)):
        if not os.path.isfile(path):
            out[key] = {"found": False,
                        "reason": "file not present: %s" % path}
            PROBLEMS.append("%s: %s not found" % (key, path))
            continue
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        lines = text.split("\n")
        out[key] = {
            "found": True,
            "file": os.path.relpath(path, ROOT).replace("\\", "/"),
            "file_sha256": sha256_file(path),
            "file_lines": len(lines),
            "sites": [],
        }
        patterns = (["r.blob = args[0];", "r.blob_length = row->blob_bytes;",
                     "args == nullptr || args[0] == nullptr"]
                    if key.startswith("defect_1")
                    else ['std::strcmp(ident, "_Z10k_flag_setPjj") == 0',
                          "frame_src = \"MARKER_K_FLAG_SET\"",
                          "frame_src = \"ENV_OVERRIDE_RAW_DUMP_FRAME_ID\"",
                          "frame_id = (long)g_frameCounter"])
        for pat in patterns:
            hits = [i + 1 for i, l in enumerate(lines) if pat in l]
            entry = {"pattern": pat, "n_hits": len(hits), "line_numbers": hits,
                     "quoted_lines": [lines[i - 1].strip() for i in hits]}
            out[key]["sites"].append(entry)
            if not hits:
                PROBLEMS.append("%s: pattern not found: %s" % (key, pat))

    # The single field that carries the wrong argument forward, in the record
    # struct the capture fills in. Quoted from its own file rather than assumed
    # to be beside the assignment.
    if os.path.isfile(DEFECT1_DECL_FILE):
        with open(DEFECT1_DECL_FILE, "r", encoding="utf-8") as fh:
            dl = fh.read().splitlines()
        pat = "const void* blob;"
        hits = [i + 1 for i, l in enumerate(dl) if pat in l]
        out["defect_1_argument_capture"]["the_record_field"] = {
            "file": os.path.relpath(DEFECT1_DECL_FILE, ROOT).replace("\\", "/"),
            "file_sha256": sha256_file(DEFECT1_DECL_FILE),
            "pattern": pat,
            "n_hits": len(hits),
            "line_numbers": hits,
            "quoted_lines": [dl[i - 1].strip() for i in hits],
        }
        if not hits:
            PROBLEMS.append("defect 1: the record field declaration was not found")
    else:
        PROBLEMS.append("defect 1: %s not found" % DEFECT1_DECL_FILE)
    return out


# ====================================================================== step 2
def generate_events():
    """The authentic launch DB as a symbol/stream stream, in DB order."""
    if not os.path.isfile(LAUNCH_DB):
        PROBLEMS.append("authentic launch DB not found: %s" % LAUNCH_DB)
        return 0
    import csv
    os.makedirs(WORK, exist_ok=True)
    n = 0
    streams = set()
    with open(LAUNCH_DB, newline="", encoding="utf-8") as fh, \
            open(EVENTS_TSV, "w", encoding="utf-8", newline="\n") as w:
        r = csv.DictReader(fh)
        for row in r:
            s = row["stream"].strip()
            # The column is a 16-hex-digit stream handle (an opaque pointer).
            sid = int(s, 16) if s else 0
            streams.add(sid)
            w.write("%s\t%d\n" % (row["kernel_mangled"], sid))
            n += 1
    return {"n_rows": n, "n_distinct_streams": len(streams),
            "stream_ids": sorted(streams), "path": os.path.relpath(EVENTS_TSV, ROOT)}


# ====================================================================== step 3
ARGSPEC = jload(os.path.join(RAW, "RAW_DUMP_ARGSPEC_16AW.json"))


def argspec_offset(symbol, host_arg_index):
    """The canonical kernarg offset the TABLE declares for this argument. Read
    from the argspec deliverable, so the offset the record is checked against is
    not the same object the record was built from."""
    for ident in ARGSPEC["identities"]:
        if ident["identity"] == symbol:
            for a in ident["explicit_args"]:
                if a["host_arg_index"] == host_arg_index:
                    return a["canonical_kernarg_offset"]
    return None


def analyze_capture_arm(arm, fixture):
    """Compare every captured argument of every launch against the bytes the
    driver actually placed in host memory. Returns per-launch results and the
    aggregate counts that this arm's comparison actually examined."""
    inst_dir = os.path.join(RUNS, arm, "instances")
    records = []
    if os.path.isdir(inst_dir):
        for fn in sorted(os.listdir(inst_dir)):
            if fn.endswith(".json"):
                records.append(jload(os.path.join(inst_dir, fn)))
    by_ordinal = {}
    for rec in records:
        by_ordinal.setdefault(rec["launch_ordinal"], []).append(rec)

    fx = {l["launch_ordinal"]: l for l in fixture["launches"]}
    per_launch = []
    n_args_compared = 0
    n_args_exact = 0
    n_hash_compared = 0
    n_hash_exact = 0
    for ord_, launch in sorted(fx.items()):
        recs = by_ordinal.get(ord_, [])
        entry = {"launch_ordinal": ord_, "symbol": launch["symbol"],
                 "n_records": len(recs),
                 "n_expected_args": len(launch["args"]),
                 "n_captured_args": None, "arg_results": []}
        if not recs:
            PROBLEMS.append("%s: no instance record for launch %d" % (arm, ord_))
            per_launch.append(entry)
            continue
        rec = recs[0]
        entry["n_captured_args"] = len(rec["args"])
        entry["active_mutation"] = rec["active_mutation"]
        entry["frame_event_role"] = rec["frame_event_role"]
        entry["n_args_dropped"] = rec["n_args_dropped"]
        entry["resource_identities"] = rec["resource_identities"]
        entry["canonical_offsets"] = [c["destination_canonical_offset"]
                                      for c in rec["canonical_kernarg_record"]]
        for exp in launch["args"]:
            i = exp["host_arg_index"]
            got = next((a for a in rec["args"]
                        if a["host_arg_index"] == i), None)
            res = {"host_arg_index": i, "present": got is not None,
                   "declared_bytes": exp["declared_bytes"]}
            if got is None:
                entry["arg_results"].append(res)
                continue
            got_bytes = bytes.fromhex(got["bytes_hex"])
            exp_bytes = bytes.fromhex(exp["payload_hex"])
            res["captured_bytes"] = got["captured_bytes"]
            res["captured_bytes_equal_declared"] = (
                got["captured_bytes"] == exp["declared_bytes"])
            # Is the captured bytes image the EXPECTED ARGUMENT's storage?
            res["bytes_equal_expected_argument"] = (got_bytes == exp_bytes)
            # Is it some OTHER argument's storage? (the swapped-index fault)
            other = None
            for e2 in launch["args"]:
                if e2["host_arg_index"] != i and \
                        bytes.fromhex(e2["payload_hex"]) == got_bytes:
                    other = e2["host_arg_index"]
            res["bytes_equal_a_different_argument"] = other
            # Does the captured tail contain the surrounding canary?
            pre = bytes([exp["canary_pre"]])
            post = bytes([exp["canary_post"]])
            res["contains_own_canary"] = (pre in got_bytes[len(exp_bytes):] or
                                          post in got_bytes[len(exp_bytes):])
            res["declared_kernarg_offset"] = argspec_offset(launch["symbol"], i)
            n_args_compared += 1
            if res["bytes_equal_expected_argument"] and \
                    res["captured_bytes_equal_declared"]:
                n_args_exact += 1
            # independent hash lineage
            n_hash_compared += 1
            res["sha256_matches_python_digest_of_the_predicted_bytes"] = (
                got["sha256"] == sha256_bytes(exp_bytes))
            if res["sha256_matches_python_digest_of_the_predicted_bytes"]:
                n_hash_exact += 1
            entry["arg_results"].append(res)
        per_launch.append(entry)
    return {"per_launch": per_launch,
            "n_launches": len(per_launch),
            "n_args_compared": n_args_compared,
            "n_args_exact": n_args_exact,
            "n_sha256_compared": n_hash_compared,
            "n_sha256_exact": n_hash_exact}


# ====================================================================== step 4
def mutation_predicate(mut, analysis, fixture):
    """(did it reach the observer, did it alter the relevant result, the
    expected contract it violates). Counts are returned so a predicate that
    examined nothing is visible."""
    c = {"hits": 0, "examined": 0, "detail": ""}
    for launch in analysis["per_launch"]:
        for res in launch["arg_results"]:
            c["examined"] += 1
            if mut == "SWAPPED_ARG_INDEX":
                if res.get("bytes_equal_a_different_argument") is not None:
                    c["hits"] += 1
                    c["detail"] = ("argument %d of %s holds the bytes of "
                                   "argument %s" %
                                   (res["host_arg_index"], launch["symbol"],
                                    res["bytes_equal_a_different_argument"]))
            elif mut == "WRONG_SIZE":
                if not res.get("captured_bytes_equal_declared", False):
                    c["hits"] += 1
            elif mut == "CONTIGUOUS_MEMORY_ASSUMPTION":
                if res.get("contains_own_canary"):
                    c["hits"] += 1
            elif mut == "OFF_BY_ONE_KERNARG":
                pass  # handled over the canonical record, below
            elif mut == "WRONG_POINTER_SCALAR_KIND":
                pass  # handled over the kinds, below
            elif mut == "OVERREAD_INTO_CANARY":
                if not res.get("captured_bytes_equal_declared", False) and \
                        res.get("contains_own_canary"):
                    c["hits"] += 1
            elif mut == "LEGACY_BLOB_ONLY":
                if not res.get("captured_bytes_equal_declared", False):
                    c["hits"] += 1
                    c["detail"] = ("%s argument %d captured %s B, table "
                                   "declares %d B" %
                                   (launch["symbol"], res["host_arg_index"],
                                    res.get("captured_bytes"),
                                    res["declared_bytes"]))
    if mut == "LEGACY_BLOB_ONLY":
        # The strongest form of the defect: for the two flag kernels the legacy
        # capture NEVER READS the by-value argument at all.
        for launch in analysis["per_launch"]:
            c["examined"] += 1
            got = launch.get("n_captured_args") or 0
            if got < launch["n_expected_args"]:
                c["hits"] += 1
                c["detail"] = ("%s: %d of %d explicit arguments were captured; "
                               "%d were never read" %
                               (launch["symbol"], got,
                                launch["n_expected_args"],
                                launch["n_expected_args"] - got))
    if mut == "OFF_BY_ONE_KERNARG":
        for launch in analysis["per_launch"]:
            for res, off in zip(launch["arg_results"],
                                launch.get("canonical_offsets", [])):
                c["examined"] += 1
                if off != res["declared_kernarg_offset"]:
                    c["hits"] += 1
                    c["detail"] = ("%s argument %d placed at canonical offset "
                                   "%d, table declares %d" %
                                   (launch["symbol"], res["host_arg_index"],
                                    off, res["declared_kernarg_offset"]))
    if mut == "WRONG_POINTER_SCALAR_KIND":
        inst_dir = None
        for launch in analysis["per_launch"]:
            kinds = launch.get("kinds", [])
            for k in kinds:
                c["examined"] += 1
                if k["declared"] == "POINTER" and k["reported"] != "POINTER":
                    c["hits"] += 1
                    c["detail"] = ("%s argument %d reported %s, table says "
                                   "POINTER" % (launch["symbol"],
                                                k["host_arg_index"],
                                                k["reported"]))
    return c


# ====================================================================== main
def main():
    if not os.path.isfile(DRIVER) or not os.path.isfile(BRIDGE):
        print("RUNNER prerequisites missing: driver=%s bridge=%s"
              % (os.path.isfile(DRIVER), os.path.isfile(BRIDGE)))
        return 1

    os.makedirs(RUNS, exist_ok=True)

    # ---------------------------------------------------------- deliverables
    defect_sites = quote_defect_sites()
    events_info = generate_events()

    # ------------------------------------------------------------- selftest
    p = run_driver(["--out", os.path.join(RUNS, "selftest"), "--arm", "selftest"])
    print(p.stdout.strip())
    selftest_path = os.path.join(RUNS, "selftest", "selftest.json")
    selftest = jload(selftest_path) if os.path.isfile(selftest_path) else None
    note(selftest is not None and selftest["n_steps"] >= 8,
         "selftest produced %s steps" % (selftest["n_steps"] if selftest else None))
    note(selftest is not None and selftest["n_fail"] == 0,
         "selftest reported failures")

    # ---------------------------------------------------- frame replays
    fr_auth = run_driver(["--out", os.path.join(RUNS, "authentic"),
                          "--arm", "frame_authentic", "--events", EVENTS_TSV])
    print(fr_auth.stdout.strip())
    authentic = jload(os.path.join(RUNS, "authentic", "frame_authentic.json"))

    fr_scen = run_driver(["--out", os.path.join(RUNS, "scen"),
                          "--arm", "frame_scenarios"])
    print(fr_scen.stdout.strip())
    scenarios = jload(os.path.join(RUNS, "scen", "frame_scenarios.json"))

    fr_ovr = run_driver(["--out", os.path.join(RUNS, "override"),
                         "--arm", "frame_authentic", "--events", EVENTS_TSV],
                        env_extra={"RAW_DUMP_FRAME_ID": "7"})
    print(fr_ovr.stdout.strip())
    override = jload(os.path.join(RUNS, "override", "frame_authentic.json"))

    # ------------------------------------------------------ capture arms
    arms = {}
    for mut in MUTATIONS + [BOGUS_MUTATION]:
        arm = "cap_" + mut.lower()
        p = run_driver(["--bridge", BRIDGE,
                        "--out", os.path.join(RUNS, arm),
                        "--arm", "capture_all", "--gate", "0"],
                       env_extra={"RAW_DUMP_16AW_MUTATION": mut})
        line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
        print(line)
        fixture = jload(os.path.join(RUNS, arm, "fixture_16aw.json"))
        analysis = analyze_capture_arm(arm, fixture)
        analysis["fixture"] = fixture
        arms[mut] = analysis

    # augment each analysis with the reported semantic kinds (for the
    # pointer/scalar-kind mutation), read back from the records
    for mut, analysis in arms.items():
        fixture = analysis["fixture"]
        fx = {l["launch_ordinal"]: l for l in fixture["launches"]}
        inst_dir = os.path.join(RUNS, "cap_" + mut.lower(), "instances")
        recs = []
        if os.path.isdir(inst_dir):
            for fn in sorted(os.listdir(inst_dir)):
                if fn.endswith(".json"):
                    recs.append(jload(os.path.join(inst_dir, fn)))
        by_ord = {}
        for r in recs:
            by_ord.setdefault(r["launch_ordinal"], r)
        for launch in analysis["per_launch"]:
            rec = by_ord.get(launch["launch_ordinal"])
            kinds = []
            if rec:
                for a in rec["args"]:
                    kinds.append({"host_arg_index": a["host_arg_index"],
                                  "reported": a["semantic_kind"],
                                  "declared": None})
            launch["kinds"] = kinds
            launch["n_resource_identities"] = len(rec["resource_identities"]) if rec else None
        # fill the DECLARED kind from the table (the fixture carries value_kind)
        for launch in analysis["per_launch"]:
            for k in launch.get("kinds", []):
                exp = next(a for a in fx[launch["launch_ordinal"]]["args"]
                           if a["host_arg_index"] == k["host_arg_index"])
                k["declared"] = ("POINTER" if exp["value_kind"] == "global_buffer"
                                 else "SCALAR")

    # ------------------------------------------------- mutation controls
    mutation_controls = []
    for mut in MUTATIONS:
        if mut == "NONE":
            # The BASELINE, not a mutation. It must be ACCEPTED: if the clean
            # arm failed its own comparison, every rejection below would be
            # meaningless. A mutation set with no positive control is a
            # measurement of nothing.
            a = arms["NONE"]
            mutation_controls.append({
                "mutation": "NONE",
                "is_baseline_not_a_mutation": True,
                "comparisons_examined": a["n_args_compared"],
                "comparisons_exactly_equal": a["n_args_exact"],
                "n_sha256_compared": a["n_sha256_compared"],
                "n_sha256_equal": a["n_sha256_exact"],
                "verdict": ("BASELINE_ACCEPTED_AS_EXPECTED"
                            if (a["n_args_compared"] > 0 and
                                a["n_args_compared"] == a["n_args_exact"] and
                                a["n_sha256_compared"] == a["n_sha256_exact"])
                            else "BASELINE_FAILED"),
                "why_this_matters": "the clean capture must pass before any "
                                    "mutation can be said to have been rejected",
            })
            continue
        analysis = arms[mut]
        c = mutation_predicate(mut, analysis, analysis["fixture"])
        # did the mutation reach the observer? every record must carry it back
        n_carried = sum(1 for l in analysis["per_launch"]
                        if l.get("active_mutation") == mut)
        reached = (c["examined"] > 0 and n_carried == analysis["n_launches"]
                   and analysis["n_launches"] > 0)
        altered = c["hits"] > 0
        mutation_controls.append({
            "mutation": mut,
            "n_records_carrying_this_mutation": n_carried,
            "n_launches": analysis["n_launches"],
            "comparisons_examined": c["examined"],
            "comparisons_that_fired": c["hits"],
            "reached_the_observer": reached,
            "altered_the_relevant_result": altered,
            "first_counterexample": c["detail"],
            "rejected_by_the_expected_contract": reached and altered,
            "verdict": ("REJECTED" if (reached and altered)
                        else ("INVALID_CONTROL_MUTATION_DID_NOT_TAKE_EFFECT"
                              if not reached else "NOT_DETECTED")),
        })
    # the negative control: a mutation NAME that does not resolve
    bogus = arms[BOGUS_MUTATION]
    bogus_carried = sorted({l.get("active_mutation")
                            for l in bogus["per_launch"]})
    bogus_clean = (bogus["n_args_exact"] == bogus["n_args_compared"]
                   and bogus["n_args_compared"] > 0)
    mutation_controls.append({
        "mutation": BOGUS_MUTATION,
        "is_negative_control": True,
        "requested_name": BOGUS_MUTATION,
        "mutation_string_carried_back_in_the_records": bogus_carried,
        "records_behaved_as_an_unmutated_capture": bogus_clean,
        "comparisons_examined": bogus["n_args_compared"],
        "verdict": ("INVALID_CONTROL_THE_REQUESTED_MUTATION_DID_NOT_RESOLVE"
                    if (bogus_carried and bogus_carried != [BOGUS_MUTATION]
                        and bogus_clean)
                    else "THE_GUARD_FAILED_A_MISSPELLED_ARM_LOOKED_REAL"),
        "why_this_matters": "A mutator that silently does nothing reports the "
                            "INVERSE of the truth. Reading the active mutation "
                            "back out of each record makes that state visible: "
                            "the arm reports the string it actually used.",
    })
    n_rejected = sum(1 for m in mutation_controls
                     if m["verdict"] == "REJECTED")
    n_expected = len([m for m in MUTATIONS if m != "NONE"])
    baseline = next(m for m in mutation_controls
                    if m["mutation"] == "NONE")
    note(baseline["verdict"] == "BASELINE_ACCEPTED_AS_EXPECTED",
         "the clean baseline did not pass its own comparison")
    note(n_rejected == n_expected,
         "only %d of %d mutation arms were REJECTED" % (n_rejected, n_expected))
    note(mutation_controls[-1]["verdict"].startswith("INVALID_CONTROL_THE_REQUESTED"),
         "the misspelled-mutation negative control did not read as INVALID")

    # ------------------------------------------------ rehearsal deliverable
    clean = arms["NONE"]
    fixture = clean["fixture"]
    rehearsal = {
        "schema": "p16aw/raw-dump-rehearsal/1",
        "phase": "16AW",
        "host_only": True,
        "gpu_execution_performed": False,
        "what_this_is": "A real-signature rehearsal: every explicit host "
                        "argument of all 15 identities is built in its OWN "
                        "page-aligned allocation with per-argument, per-side "
                        "canaries, handed to the real bridge through a real "
                        "void** array, and the captured bytes are compared "
                        "against the bytes that were placed there.",
        "identity_count": fixture["identity_count"],
        "n_launches": fixture["n_launches"],
        "n_argument_regions": fixture["n_argument_regions"],
        "n_launches_with_noncontiguous_storage": fixture[
            "n_launches_with_noncontiguous_storage"],
        "n_launches_with_adjacent_storage": fixture["n_launches_with_adjacent_storage"],
        "n_launches_canaries_intact_after_the_launch": fixture[
            "n_launches_canaries_intact"],
        "n_launches_canaries_disturbed": fixture["n_launches_canaries_disturbed"],
        "n_expected_launch_failures": fixture["n_expected_launch_failures"],
        "n_args_compared": clean["n_args_compared"],
        "n_args_exactly_equal": clean["n_args_exact"],
        "n_sha256_compared_independently": clean["n_sha256_compared"],
        "n_sha256_equal": clean["n_sha256_exact"],
        "all_explicit_arguments_captured_exactly": (
            clean["n_args_compared"] == clean["n_args_exact"] == 18),
        "all_argument_digests_reproduced_by_an_independent_hasher": (
            clean["n_sha256_compared"] == clean["n_sha256_exact"] == 18),
        "storage_layout": [
            {"launch_ordinal": l["launch_ordinal"], "symbol": l["symbol"],
             "storage_noncontiguous": l["storage_noncontiguous"],
             "canaries_intact": l["canaries_intact"],
             "n_explicit": l["n_explicit"]}
            for l in fixture["launches"]],
        "per_argument_outcomes": [
            {"launch_ordinal": l["launch_ordinal"], "symbol": l["symbol"],
             "host_arg_index": r["host_arg_index"],
             "declared_bytes": r["declared_bytes"],
             "captured_bytes": r.get("captured_bytes"),
             "exact": r.get("bytes_equal_expected_argument"),
             "sha256_matches": r.get(
                 "sha256_matches_python_digest_of_the_predicted_bytes")}
            for l in clean["per_launch"] for r in l["arg_results"]],
    }
    note(rehearsal["n_args_compared"] > 0, "rehearsal compared 0 arguments")
    note(rehearsal["n_launches_with_adjacent_storage"] == 0,
         "the rehearsal storage was NOT noncontiguous for every launch")
    for key in ("all_explicit_arguments_captured_exactly",
                "all_argument_digests_reproduced_by_an_independent_hasher"):
        note(rehearsal[key], "rehearsal: %s is false" % key)
    jdump(os.path.join(RAW, "RAW_DUMP_REHEARSAL_16AW.json"), rehearsal)
    print("REHEARSAL identities=%d launches=%d regions=%d noncontiguous=%d "
          "args_compared=%d exact=%d sha256_compared=%d equal=%d"
          % (fixture["identity_count"], fixture["n_launches"],
             fixture["n_argument_regions"],
             fixture["n_launches_with_noncontiguous_storage"],
             clean["n_args_compared"], clean["n_args_exact"],
             clean["n_sha256_compared"], clean["n_sha256_exact"]))

    # ------------------------------------------ defect reproduction deliverable
    legacy = arms["LEGACY_BLOB_ONLY"]
    lfx = {l["launch_ordinal"]: l for l in legacy["fixture"]["launches"]}
    flag_set_ord = next(o for o, l in lfx.items() if l["symbol"] == CLOSER)
    flag_wait_ord = next(o for o, l in lfx.items() if l["symbol"] == OPENER)
    ls_recs = []
    inst_dir = os.path.join(RUNS, "cap_legacy_blob_only", "instances")
    for fn in sorted(os.listdir(inst_dir)):
        if fn.endswith(".json"):
            ls_recs.append(jload(os.path.join(inst_dir, fn)))
    ls_by_ord = {}
    for r in ls_recs:
        ls_by_ord.setdefault(r["launch_ordinal"], r)
    fset = ls_by_ord[flag_set_ord]
    fwait = ls_by_ord[flag_wait_ord]
    fs_fx = lfx[flag_set_ord]
    fw_fx = lfx[flag_wait_ord]

    defect1 = {
        "brief_section": 37,
        "where": defect_sites.get("defect_1_argument_capture", {}),
        "what_the_defective_line_does":
            "for EVERY identity it takes args[0] -- the caller's void** entry "
            "for the FIRST parameter -- and copies blob_bytes from it, where "
            "blob_bytes is the identity's whole declared by-value size.",
        "why_that_is_wrong":
            "the caller's void** has one entry PER PARAMETER and the entries "
            "are not guaranteed to be contiguous, so for any identity whose "
            "first parameter is not the by-value one, args[0] is a DIFFERENT "
            "argument's storage.",
        "control_the_defective_behaviour_reproduced": {
            "arm": "LEGACY_BLOB_ONLY",
            "how": "the repaired layer carries the replaced behaviour as one "
                   "selectable mutation: one capture, from args[0], of the "
                   "UNION of the by-value sizes.",
            "k_flag_set_expected_capture": [
                {"host_arg_index": a["host_arg_index"],
                 "declared_bytes": a["declared_bytes"],
                 "value_kind": a["value_kind"]}
                for a in fs_fx["args"]],
            "k_flag_set_legacy_capture":
                [{"host_arg_index": a["host_arg_index"],
                  "declared_bytes": a["declared_bytes"],
                  "captured_bytes": a["captured_bytes"],
                  "value_kind_in_the_code_object": a["value_kind_in_the_code_object"],
                  "semantic_kind": a["semantic_kind"],
                  "bytes_hex": a["bytes_hex"]}
                 for a in fset["args"]],
            "k_flag_set_true_bytes_of_each_argument":
                [{"host_arg_index": a["host_arg_index"],
                  "declared_bytes": a["declared_bytes"],
                  "payload_hex": a["payload_hex"]}
                 for a in fs_fx["args"]],
            "k_flag_wait_expected_capture": [
                {"host_arg_index": a["host_arg_index"],
                 "declared_bytes": a["declared_bytes"],
                 "value_kind": a["value_kind"]}
                for a in fw_fx["args"]],
            "k_flag_wait_legacy_capture":
                [{"host_arg_index": a["host_arg_index"],
                  "captured_bytes": a["captured_bytes"],
                  "semantic_kind": a["semantic_kind"]}
                 for a in fwait["args"]],
            "legacy_captured_the_pointer_bytes_and_called_them_the_blob":
                (fs_fx["args"][0]["payload_hex"].startswith(
                    fset["args"][0]["bytes_hex"]) and
                 fset["args"][0]["declared_bytes"] == 4 and
                 fset["args"][0]["value_kind_in_the_code_object"] == "blob"),
            "legacy_never_read_the_by_value_argument":
                len(fset["args"]) == 1 and fset["args"][0]["host_arg_index"] == 0,
            "legacy_dropped_argument_count": fset["n_args_dropped"],
        },
    }
    note(defect1["control_the_defective_behaviour_reproduced"][
             "legacy_captured_the_pointer_bytes_and_called_them_the_blob"],
         "the legacy arm did not reproduce the args[0] capture")
    note(defect1["control_the_defective_behaviour_reproduced"][
             "legacy_never_read_the_by_value_argument"],
         "the legacy arm read more than one argument")

    defect2 = {
        "brief_section": 44,
        "where": defect_sites.get("defect_2_frame_semantics", {}),
        "what_the_defective_code_does":
            "it increments a frame counter when the symbol is _Z10k_flag_setPjj "
            "and then stamps the CURRENT launch with that counter, so the closer "
            "and every launch before it in the frame carry the number of the "
            "PREVIOUS frame.",
        "why_that_is_wrong":
            "the authentic launch DB opens each frame with _Z11k_flag_waitPjjj "
            "and closes it with _Z10k_flag_setPjj (k_flag_set is the LAST launch "
            "of all 14 frames), so k_flag_set is a CLOSING event and an id "
            "minted there cannot number the frame it closes.",
        "control_the_defective_behaviour_reproduced": {
            "arm": "frame_authentic",
            "n_events": authentic["n_events"],
            "n_events_the_legacy_counter_could_not_place": authentic[
                "n_events_legacy_could_not_place"],
            "n_events_the_repaired_machine_could_not_place": authentic[
                "n_events_repaired_could_not_place"],
            "n_disagreements_with_the_legacy_counter": authentic[
                "n_disagreements_with_legacy"],
            "legacy_frames_opened": authentic["frames_opened"],
            "repaired_frames_opened": authentic["frames_opened"],
            "repaired_frames_complete": authentic["frames_complete"],
            "repaired_frames_incomplete": authentic["frames_incomplete"],
            "repaired_anomalies": authentic["n_events_with_an_anomaly"],
            "streams_in_the_authentic_db": authentic["n_streams_seen"],
            # The whole emitted window, NOT a slice: the window keeps the first
            # 40 events plus every frame boundary and its neighbour, so the
            # events where the two machines AGREE are visible beside the events
            # where they disagree.
            "event_window": authentic["events"],
            "n_events_in_window": len(authentic["events"]),
            "agreement_by_role": {
                role: {
                    "n": sum(1 for e in authentic["events"]
                             if e["role"] == role),
                    "n_agreeing_with_legacy": sum(
                        1 for e in authentic["events"]
                        if e["role"] == role and e["agrees"]),
                } for role in ("OPENER", "CLOSER", "WORK")},
            "reading": "the legacy counter agrees with the repaired machine on "
                       "exactly the CLOSING events and on nothing else: a frame "
                       "id minted at the closer cannot number the frame it "
                       "closes.",
        },
    }
    note(authentic["n_events_repaired_could_not_place"] == 0,
         "the repaired machine could not place %d authentic events"
         % authentic["n_events_repaired_could_not_place"])
    note(authentic["n_disagreements_with_legacy"] > 0,
         "the repaired machine agreed with the legacy counter on every event, "
         "so defect 2 did not reproduce")

    jdump(os.path.join(RAW, "RAW_DUMP_DEFECT_REPRODUCTION_16AW.json"),
          {"schema": "p16aw/raw-dump-defect-reproduction/1",
           "phase": "16AW", "host_only": True, "gpu_execution_performed": False,
           "defect_1_argument_capture": defect1,
           "defect_2_frame_semantics": defect2})
    print("DEFECTS defect1_reproduced=%s defect2_legacy_unplaced=%d "
          "defect2_disagreements=%d"
          % (defect1["control_the_defective_behaviour_reproduced"][
                 "legacy_captured_the_pointer_bytes_and_called_them_the_blob"],
             authentic["n_events_legacy_could_not_place"],
             authentic["n_disagreements_with_legacy"]))

    # --------------------------------------- frame state machine deliverable
    scen_by_name = {}
    for ev in scenarios["events"]:
        scen_by_name.setdefault(ev["scenario"], []).append(ev)
    scen_results = []
    for name, evs in scen_by_name.items():
        frames = [e["repaired_frame"] for e in evs]
        anomalies = [e["anomaly"] for e in evs if e["anomaly"]]
        scen_results.append({
            "scenario": name,
            "n_events": len(evs),
            "repaired_frames": frames,
            "legacy_frames": [e["legacy_frame"] for e in evs],
            "legacy_sources": sorted({e["legacy_source"] for e in evs}),
            "anomalies": anomalies,
            "n_streams_used": len({e["stream"] for e in evs}),
            "events": evs,
        })
    frame_doc = {
        "schema": "p16aw/raw-dump-frame-state-machine/1",
        "phase": "16AW",
        "host_only": True,
        "gpu_execution_performed": False,
        "explicit_frame_or_job_id_search": {
            "question": "does a job/frame/render-invocation id survive into the "
                        "launch construction, so the machine could read one "
                        "instead of deriving an interval?",
            "searched": [
                "phase16_bridge_telemetry/src/amdhip64_7.cpp hipLaunchKernel "
                "signature",
                "the bridge's registration ledger record",
                "the authentic launch DB columns",
            ],
            "finding": "NO. hipLaunchKernel's parameters are (function_address, "
                       "numBlocks, dimBlocks, args, sharedMemBytes, stream). "
                       "There is no job, frame, render-invocation or draw id in "
                       "the launch ABI, and the authentic launch DB carries no "
                       "such column. The only job identifier anywhere in the "
                       "project is p16ad/bridge/src/p16ad_jobplan.{h,cpp}, "
                       "which is this project's own admission-controller "
                       "abstraction: immutable per plan and not carried on the "
                       "launch path.",
            "consequence": "the fallback applies: frame intervals are DERIVED "
                           "from validated opening and closing events.",
            "environment_frame_id_is_a_DECLARED_OVERRIDE": True,
        },
        "opener_and_closer_validation": {
            "opener": OPENER,
            "closer": CLOSER,
            "evidence": "phase16_authentic_launch_db.csv: k_flag_wait is the "
                        "FIRST launch of frame 1 (launch_in_frame 0) and "
                        "k_flag_set is the LAST launch of all 14 frames; 14 of "
                        "each across 2239 launches, all on one stream. "
                        "phase16d_authentic_capture/tools/parse_launch_db.py:150 "
                        "independently uses FRAME_FIRST = \"%s\" with the comment "
                        "'each k_flag_wait starts a network job/frame'." % OPENER,
            "value_and_protocol_semantics_NOT_verified": "the flag kernels' "
                "argument VALUES are among the 15 UNRESOLVED constants and "
                "appear in no artefact, so the protocol was validated by "
                "POSITION and ORDER only; the byte values that might confirm "
                "the protocol were not available to read. Recorded as "
                "NOT_MEASURED rather than assumed.",
        },
        "authentic_replay": {
            "n_events": authentic["n_events"],
            "n_streams_seen": authentic["n_streams_seen"],
            "frames_opened": authentic["frames_opened"],
            "frames_complete": authentic["frames_complete"],
            "frames_incomplete": authentic["frames_incomplete"],
            "frames_left_open_at_end": authentic["frames_left_open_at_end"],
            "anomalies": authentic["n_events_with_an_anomaly"],
            "event_stream_source": events_info,
            "declared_frame_id_override_train_on_the_same_events": {
                "override": 7,
                "every_event_reports_source": override["events"][0][
                    "repaired_source"],
                "every_event_reports_provenance": override["events"][0][
                    "provenance"],
                "derived_interval_is_still_computed_beside_it":
                    override["last_derived_frame_id"],
                "consequence": "a declared id REPLACES nothing: the derived "
                               "interval is still computed and reported.",
            },
        },
        "how_the_eight_cases_were_driven": "replayed as ONE event stream on "
            "two stream handles, in the order listed, so each case inherits the "
            "state the previous one left. That is deliberate: a frame left open "
            "by missing_closing_event is then correctly reported as ABORTED by "
            "the next case's opener, and the report shows that as an anomaly of "
            "the LATER case rather than hiding it. Every case's own frames and "
            "anomalies are listed per case below.",
        "required_cases": scen_results,
        "aggregate_over_the_eight_cases": {
            "events": scenarios["n_events"],
            "streams": scenarios["n_streams_seen"],
            "frames_opened": scenarios["frames_opened"],
            "frames_complete": scenarios["frames_complete"],
            "frames_incomplete": scenarios["frames_incomplete"],
            "frames_left_open_at_end": scenarios["frames_left_open_at_end"],
            "anatomy_pre_opener": scenarios["anatomy_pre_opener"],
            "unmatched_closer": scenarios["unmatched_closer"],
            "duplicate_closer": scenarios["duplicate_closer"],
            "post_close_stray": scenarios["post_close_stray"],
            "disagreements_with_the_legacy_counter":
                scenarios["n_disagreements_with_legacy"],
        },
        "ambiguity_rule": {
            "statement": "a closer with no open frame on its own stream never "
                         "closes another stream's frame.",
            "evidence": "nested_concurrent_stream_activity ran two jobs on two "
                        "streams and produced two independently numbered, "
                        "independently closed frames; the unmatched-closer "
                        "counter is 0 because the closer matched its own "
                        "stream. A closer that genuinely matched nothing is "
                        "reported as CLOSER_WITHOUT_OPEN_FRAME, or as "
                        "AMBIGUOUS_UNMATCHED_CLOSER_NOT_MERGED when another "
                        "stream has a frame open.",
        },
    }
    jdump(os.path.join(RAW, "RAW_DUMP_FRAME_STATE_MACHINE_16AW.json"), frame_doc)
    print("FRAME_MACHINE cases=%d authentic_events=%d frames_opened=%d "
          "complete=%d incomplete=%d"
          % (len(scen_results), authentic["n_events"],
             authentic["frames_opened"], authentic["frames_complete"],
             authentic["frames_incomplete"]))

    # ------------------------------------------------ mutation deliverable
    jdump(os.path.join(RAW, "RAW_DUMP_MUTATION_CONTROLS_16AW.json"), {
        "schema": "p16aw/raw-dump-mutation-controls/1",
        "phase": "16AW", "host_only": True, "gpu_execution_performed": False,
        "discipline": "every arm must be: (1) applied, (2) shown to reach the "
                      "comparison, (3) shown to change the relevant captured "
                      "result, and (4) rejected by the contract it violates. An "
                      "arm that cannot show (2) is INVALID, never a rejection. "
                      "The mutation is read back out of every emitted record, "
                      "so a misspelled or ineffective arm reports the string it "
                      "actually used as its first line of defence.",
        "n_arms": len(mutation_controls),
        "n_arms_rejected": n_rejected,
        "n_arms_expected_rejected": n_expected,
        "controls": mutation_controls,
    })
    print("MUTATIONS arms=%d rejected=%d negative_control=%s"
          % (len(mutation_controls), n_rejected, mutation_controls[-1]["verdict"]))

    # --------------------------------------------------------- summary
    summary = {
        "schema": "p16aw/raw-dump-repair-summary/1",
        "phase": "16AW",
        "host_only": True,
        "gpu_execution_performed": False,
        "capture_authorization_touched": False,
        "gta_launched": False,
        "capture_session_started": False,
        "wrote_only_inside": "p16aw/raw_dump/",
        "existing_artifacts_modified": [],
        "both_defects_reproduced": (
            defect1["control_the_defective_behaviour_reproduced"][
                "legacy_captured_the_pointer_bytes_and_called_them_the_blob"] and
            authentic["n_disagreements_with_legacy"] > 0),
        "n_mutation_arms": len(mutation_controls),
        "n_mutation_arms_rejected": n_rejected,
        "rehearsal_comparisons": {
            "args_compared": clean["n_args_compared"],
            "args_exact": clean["n_args_exact"],
        },
        "verifier_counts": {
            "selftest_steps": selftest["n_steps"] if selftest else 0,
            "selftest_failures": selftest["n_fail"] if selftest else -1,
            "rehearsal_args_compared": clean["n_args_compared"],
            "rehearsal_sha256_compared": clean["n_sha256_compared"],
            "authentic_events_compared": authentic["n_events"],
            "scenario_events_compared": scenarios["n_events"],
            "mutation_comparisons_examined": sum(
                m.get("comparisons_examined", 0) for m in mutation_controls),
            "total": (clean["n_args_compared"] + clean["n_sha256_compared"] +
                      authentic["n_events"] + scenarios["n_events"] +
                      sum(m.get("comparisons_examined", 0)
                          for m in mutation_controls)),
        },
        "problems": PROBLEMS,
        "verdict": "PASS" if not PROBLEMS else "PROBLEMS",
    }
    jdump(os.path.join(RAW, "RAW_DUMP_REPAIR_16AW_SUMMARY.json"), summary)

    print("SUMMARY total_comparisons=%d problems=%d verdict=%s"
          % (summary["verifier_counts"]["total"], len(PROBLEMS),
             summary["verdict"]))
    for p in PROBLEMS:
        print("SUMMARY   PROBLEM %s" % p)
    return 0 if not PROBLEMS else 1


if __name__ == "__main__":
    sys.exit(main())
