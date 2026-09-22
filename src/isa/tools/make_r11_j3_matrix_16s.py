#!/usr/bin/env python3
"""Generate phase16s/isa/tools/r11_j3_matrix_16s.py from the 16R tool.

This generator is kept so the copy's provenance is reproducible: it reads the
16R tool with newline="" (byte-preserving), applies the replacements listed
below, and writes the copy with newline="" too.  Any anchor that does not match
exactly once aborts.

The 16R tool is NOT imported and NOT edited.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))
SRC = os.path.join(ROOT, "phase16r", "isa", "tools", "r11_j3_matrix.py")
DST = os.path.join(ROOT, "phase16s", "isa", "tools", "r11_j3_matrix_16s.py")
SECTION = os.path.join(ROOT, "phase16s", "isa", "tools", "s1_section.py")

BANNER = (
    "# ===========================================================================\n"
    "# PHASE 16S COPY of phase16r/isa/tools/r11_j3_matrix.py.\n"
    "#\n"
    "# Byte-for-byte the 16R tool except for:\n"
    "#   * OUT_REL / LOG_REL point at phase16s/isa, so this copy writes nothing\n"
    "#     into phase16r/isa (which is 16R evidence and is not touched);\n"
    "#   * one additive extension of the comparator (`_obs_diffs`) that only\n"
    "#     acts when the oracle side declares an `extra` read-back;\n"
    "#   * one optional argument to `measured_mutation` (the shapes to try),\n"
    "#     defaulting to the 16R tuple;\n"
    "#   * section 10 (added): the S1 independent ISA oracle suite, the additive\n"
    "#     harness widening it needs, and the shapes its mutation control uses;\n"
    "#   * the evidence join and the per-mnemonic mutation loop consume the S1\n"
    "#     suite when a mnemonic has no other oracle;\n"
    "#   * the artifact schema/phase fields, and the rule that a row resting on\n"
    "#     the S1 suite is demoted to BLOCKED when it carries no detecting\n"
    "#     mutation.\n"
    "#\n"
    "# Every other line is the 16R text, so the 16L / M2 / Q1 measurements this\n"
    "# tool performs are the same measurements.\n"
    "# ===========================================================================\n"
)


def main():
    src = open(SRC, encoding="utf-8", newline="").read()
    sec = open(SECTION, encoding="utf-8", newline="").read()
    S, n = src, 0

    def rep(old, new, count=1):
        nonlocal S, n
        got = S.count(old)
        if got != count:
            raise SystemExit("anchor matched %d time(s), wanted %d: %r"
                             % (got, count, old[:80]))
        S = S.replace(old, new)
        n += 1

    rep("#!/usr/bin/env python3\n", "#!/usr/bin/env python3\n" + BANNER)
    rep('OUT_REL = "phase16r/isa/J3_INSTRUCTION_CONFORMANCE.json"',
        'OUT_REL = "phase16s/isa/J3_INSTRUCTION_CONFORMANCE.json"')
    rep('LOG_REL = "phase16r/isa/logs/r11_matrix.txt"',
        'LOG_REL = "phase16s/isa/logs/r11_matrix_16s.txt"')

    rep('''    for k in ("scc", "exec", "value"):
        if orc.get(k) is None:
            continue
        if emu.get(k) != orc.get(k):
            d.append({"field": k, "emulator": emu.get(k), "oracle": orc.get(k)})
    return d''',
        '''    for k in ("scc", "exec", "value"):
        if orc.get(k) is None:
            continue
        if emu.get(k) != orc.get(k):
            d.append({"field": k, "emulator": emu.get(k), "oracle": orc.get(k)})
    # 16S additive: an oracle side that declares `extra` read-backs has those
    # compared as well.  Observations without an `extra` key are unaffected, so
    # every 16L / M2 / Q1 comparison is exactly what it was.
    for reg, want in (orc.get("extra") or {}).items():
        got = (emu.get("extra") or {}).get(reg)
        if got != want:
            d.append({"field": "extra." + reg, "emulator": got,
                      "oracle": want})
    return d''')

    rep("def measured_mutation(harness, core_cls, attr, vectors):",
        "def measured_mutation(harness, core_cls, attr, vectors, shapes=None):")
    rep('''    for shape_name, shape in MUTATION_SHAPES:''',
        '''    for shape_name, shape in (shapes or MUTATION_SHAPES):''')

    anchor = ("# ---------------------------------------------------------------------------\n"
              "# section 4b -- adjudicating an oracle the ISA document refutes\n"
              "# ---------------------------------------------------------------------------")
    rep(anchor, sec + anchor)

    rep('''            d["suites"].add(suite)
    covered = [m for m in union if evid.get(nm(m), {}).get("comparisons")]''',
        '''            d["suites"].add(suite)
    # 16S: the S1 independent ISA oracle suite, measured in THIS run through
    # the same `Harness.probe` path, the file supplying expectations only.
    s1_kit, s1_doc, s1_sha = load_s1_suite()
    evid_s1 = {}
    if s1_kit:
        evid_s1 = s1_evidence(s1_kit, harness_s1)
        for mnem, e in evid_s1.items():
            d = evid[mnem]
            d["vectors"].extend(e["vectors"])
            d["comparisons"] += e["comparisons"]
            d["mismatches"] += e["mismatches"]
            d["suites"].update(e["suites"])
            d["s1"] = True
        P("5b. S1 oracle suite joined: %d vectors over %d mnemonics, "
          "%d comparisons, %d disagreeing"
          % (sum(len(e["vectors"]) for e in evid_s1.values()), len(evid_s1),
             sum(e["comparisons"] for e in evid_s1.values()),
             sum(1 for e in evid_s1.values()
                 for v in e["vectors"] if not v["agree"])))
        for mnem in sorted(evid_s1):
            e = evid_s1[mnem]
            P("     %-24s %2d vectors %4d comparisons %2d disagreeing"
              % (mnem, len(e["vectors"]), e["comparisons"],
                 sum(1 for v in e["vectors"] if not v["agree"])))
        P("")
    covered = [m for m in union if evid.get(nm(m), {}).get("comparisons")]''')

    rep('''    harness = Harness(env, m2)
    core_cls = harness.BOTH''',
        '''    harness = Harness(env, m2)
    # 16S: the same harness with the two additive, values-only widenings the
    # S1 suite needs.  Every recorded suite keeps using `harness` unchanged.
    harness_s1 = HarnessS1(env, m2)
    core_cls = harness.BOTH''')

    rep('''        vectors = kit.get(nm(m))
        attr = (row["handler_live"] or {}).get("attr")
        if not vectors or not attr:
            row["mutation_effect_observed"] = False
            row["mutation_rejected"] = False
            row["mutation_source"] = "none available"
            continue
        rec = measured_mutation(harness, core_cls, attr, vectors)
        n_measured += 1
        row["mutation_source"] = "measured here on the MRO-resolved handler"''',
        '''        s1v = (s1_kit or {}).get(nm(m)) or []
        vectors = s1v if s1v else kit.get(nm(m))
        attr = (row["handler_live"] or {}).get("attr")
        if not vectors or not attr:
            row["mutation_effect_observed"] = False
            row["mutation_rejected"] = False
            row["mutation_source"] = "none available"
            continue
        rec = measured_mutation(harness_s1 if s1v else harness, core_cls,
                                attr, vectors,
                                S1_MUTATION_SHAPES if s1v else None)
        n_measured += 1
        row["mutation_source"] = ("measured here on the MRO-resolved handler"
                                  + (" (S1 suite)" if s1v else ""))''')

    rep('''    # rows whose status rests on an adjudicated oracle carry the measurement
    for row in rows:''',
        '''    # 16S rule: a row that rests on the S1 suite is VERIFIED only when the
    # oracle OBSERVED the mnemonic, the emulator AGREED on at least one vector,
    # AND a detecting mutation was measured.  Without the mutation the row is
    # demoted, with the reason recorded -- the bar is not lowered to reach 0.
    demoted = []
    for row in rows:
        e = evid.get(nm(row["mnemonic"])) or {}
        s1_hit = any(v["suite"] == "S1_ISA_ORACLE"
                     for v in e.get("vectors", []))
        row["s1_suite_observed"] = bool(s1_hit)
        row["s1_agreeing_vectors"] = sum(
            1 for v in e.get("vectors", [])
            if v["suite"] == "S1_ISA_ORACLE" and v.get("agree"))
        if (s1_hit and row["status"] == "VERIFIED_INDEPENDENTLY"
                and not row["mutation_rejected"]):
            row["status"] = "BLOCKED"
            row["blocked_reason"] = ("NO_DETECTING_MUTATION_FOR_THE_"
                                     "INDEPENDENT_ORACLE")
            row["verification_basis"] += (
                " ; DEMOTED from VERIFIED_INDEPENDENTLY: no mutation of the "
                "MRO-resolved handler changed any observation")
            demoted.append(row["mnemonic"])
    if demoted:
        P("   DEMOTED (no detecting mutation) : %s" % sorted(demoted))
    # rows whose status rests on an adjudicated oracle carry the measurement
    for row in rows:''')

    rep('P("write intents outside phase16r/isa: %d, state-changing: %d"',
        'P("write intents outside phase16s/isa: %d, state-changing: %d"')

    rep('P("PHASE 16R / R11 -- instruction-level J3 conformance matrix")',
        'P("PHASE 16S / R11-INTEGRATION -- instruction-level J3 conformance '
        'matrix")\n    P("   (copy of the 16R tool; adds the S1 oracle suite)")')

    rep('''    P("3. probe-able 16L vectors: %d over %d mnemonics"
      % (sum(len(x) for x in kit.values()), len(kit)))
    P("")''',
        '''    nc_e = s1_harness_equivalence(harness, harness_s1)
    P("2b. NC_E HarnessS1 widening is additive: %s" % nc_e["ok"])
    P("    int-valued-setup probes identical through both classes: %d of %d"
      % (sum(1 for x in nc_e["same"] if x["identical"]), len(nc_e["same"])))
    for x in nc_e["widening_needed"]:
        P("    list-valued setup: base class raised %s, S1 class value=%s"
          % (x["base_class_raised"], x["s1_class_value"]))
    P("")
    P("3. probe-able 16L vectors: %d over %d mnemonics"
      % (sum(len(x) for x in kit.values()), len(kit)))
    P("")''')

    rep('''            "oracle_16l_vector": v_rec,''',
        '''            "oracle_s1": {
                "path": S1_ORACLE_REL, "sha256": s1_sha,
                "loaded": bool(s1_doc),
                "supplied_by": "the S1 independent oracle (oracle16.py); it "
                               "supplies EXPECTED values only -- every "
                               "emulator-side observation of this suite is "
                               "Harness.probe's, measured in this run",
                "host_only": (s1_doc or {}).get("host_only"),
                "gpu_execution_performed":
                    (s1_doc or {}).get("gpu_execution_performed"),
                "tool": "phase16s/isa/tools/r11_j3_matrix_16s.py",
            },
            "oracle_16l_vector": v_rec,''')

    rep('''        "negative_controls": {"NC1_classifier": nc1, "NC3_pair_readback": nc3,
                              "NC4_refuted_oracle": adj},''',
        '''        "s1_integration": {
            "tool": ("phase16s/isa/tools/r11_j3_matrix_16s.py -- a copy of the "
                     "16R tool; the 16R tool is neither imported nor edited"),
            "suite": "S1_ISA_ORACLE",
            "oracle_path": S1_ORACLE_REL,
            "oracle_sha256": s1_sha,
            "n_vectors": sum(len(e["vectors"]) for e in evid_s1.values()),
            "n_comparisons": sum(e["comparisons"] for e in evid_s1.values()),
            "n_mnemonics": len(evid_s1),
            "harness": ("the tool's own Harness.probe, reached through "
                        "HarnessS1, whose two widenings are additive and whose "
                        "additivity NC_E measures"),
            "harness_equivalence": nc_e,
            "demoted_for_no_detecting_mutation": sorted(demoted),
            "per_mnemonic": {
                m: {
                    "oracle_vectors": len(e["vectors"]),
                    "comparisons": e["comparisons"],
                    "disagreements": sum(1 for v in e["vectors"]
                                         if not v["agree"]),
                    "agreeing_vectors": sum(1 for v in e["vectors"]
                                            if v["agree"]),
                    "status_in_the_matrix": next(
                        r["status"] for r in rows if nm(r["mnemonic"]) == m),
                    "blocked_reason": next(
                        r["blocked_reason"] for r in rows
                        if nm(r["mnemonic"]) == m),
                    "detecting_mutation": next(
                        r["detecting_mutation"] for r in rows
                        if nm(r["mnemonic"]) == m),
                    "mutation_rejected": next(
                        r["mutation_rejected"] for r in rows
                        if nm(r["mnemonic"]) == m),
                    "open_questions": (
                        ((s1_doc or {}).get("per_mnemonic", {}) or {}).get(
                            next(r["mnemonic"] for r in rows
                                 if nm(r["mnemonic"]) == m), {}) or {}
                    ).get("open_questions"),
                    "disagreeing_vectors": [
                        {"name": v["name"], "diffs": v["diffs"],
                         "expect": v["expect"], "measured": v["measured"],
                         "alt": v["alt"],
                         "matches_alternate_reading":
                             v["matches_alternate_reading"],
                         "note": v["note"], "source": v["source"]}
                        for v in e["vectors"] if not v["agree"]],
                } for m, e in sorted(evid_s1.items())},
        },
        "defect_findings": (s1_doc or {}).get("defect_findings") or [],
        "negative_controls": {"NC1_classifier": nc1, "NC3_pair_readback": nc3,
                              "NC4_refuted_oracle": adj,
                              "NC_E_harness_s1": nc_e},''')

    rep('''        "schema": "phase16r-j3-instruction-conformance/1",
        "phase": "16R",
        "requirement": "R11",''',
        '''        "schema": "phase16s-j3-instruction-conformance/1",
        "phase": "16S",
        "requirement": "S1 (R11 integration)",
        "copy_provenance": {
            "copy_of": "phase16r/isa/tools/r11_j3_matrix.py",
            "copy_of_sha256": sha256_file(os.path.join(
                ROOT, "phase16r/isa/tools/r11_j3_matrix.py")),
            "the_16r_artifact": "phase16r/isa/J3_INSTRUCTION_CONFORMANCE.json",
            "the_16r_tool_and_artifact_were_not_modified": True,
        },''')

    rep('''        "what": ("instruction-level J3 conformance matrix over the actual J3 "
                 "output-cone record: one row per mnemonic with the recorded "
                 "cone counts, the live MRO-resolved handler, every "
                 "independent oracle that observes it, and a measured "
                 "per-mnemonic negative control"),''',
        '''        "what": ("instruction-level J3 conformance matrix over the actual J3 "
                 "output-cone record: one row per mnemonic with the recorded "
                 "cone counts, the live MRO-resolved handler, every "
                 "independent oracle that observes it, and a measured "
                 "per-mnemonic negative control.  Phase 16S adds the S1 "
                 "instruction-level oracle suite for the sixteen mnemonics for "
                 "which 16R found no oracle at all."),''')

    with open(DST, "w", encoding="utf-8", newline="") as fh:
        fh.write(S)
    print("wrote %s (%d replacements)" % (DST, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
