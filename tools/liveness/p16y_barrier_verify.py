#!/usr/bin/env python3
"""Phase 16Y / PART II / INDEPENDENT BARRIER VERIFIER (brief S24, S25, S26).

WHY A SECOND FILE.  `p16y_barrier_trace.py` both PRODUCES the trace and
DECIDES what it means.  Brief S26 forbids that: a producer that grades its own
homework cannot be distinguished from one that is simply wrong.  This verifier

  * consumes ONLY the serialized JSON -- it never imports the tracer, never
    touches the emulator, and never sees a live core;
  * reaches its conclusion by different logic, from different inputs;
  * anchors that conclusion on an instrument the tracer does not own.

THE INDEPENDENT ANCHOR.  `barrier_epoch_list_from_model` is produced by the
WAVE SCHEDULER (`p14eh._run_wg_hw`): it appends the PC at which every live wave
converged, and it is computed from the `alive` set, not from any per-wave hook.
The per-wave `barrier_pc_sequence` comes from the instrument's subclass.  These
are two different subsystems answering the same question, so they can be
cross-checked:

    union of the per-wave barrier PCs  ==  set of the scheduler's epoch PCs

That cross-check is what brief S25 is really asking for.  A synthetic trace in
which every wave consistently omits 0xBBE20 is INTERNALLY CONSISTENT -- all
eight sequences still agree -- so a checker that only compares waves to each
other passes it.  But the scheduler's epoch list still contains 0xBBE20, the
two instruments disagree, and this verifier must FAIL it.  Internal
consistency is reported separately from agreement with observed ground truth
for exactly that reason.

Host-only.  No GPU, no HIP, no driver, no game, no harness executable.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
Y = os.path.dirname(HERE)
ROOT = os.path.dirname(Y)

TRACE = os.path.join(Y, "audit", "J3_DYNAMIC_BARRIER_LIVENESS_16Y.json")
FROZEN_16T = os.path.join(ROOT, "phase16t", "j3", "out", "j3_revision.json")
CONTROLS_OUT = os.path.join(Y, "audit",
                            "J3_DYNAMIC_BARRIER_INDEPENDENT_CONTROLS_16Y.json")

IN_LOOP = 0xBBE20
WAVES = 8
#: the ten barrier PCs 16X listed, as the sequence must appear in program order
EXPECTED_ORDER = [0xAD744, 0xB3A54, 0xB5B8C, 0xB780C, 0xB9384, 0xBA70C,
                  0xBBE20, 0xBBF24, 0xBDB5C, 0xC06F0]
ENDPGM = 0xC36D8


def verdict_of(doc, frozen):
    """The whole decision, from the serialized document and the frozen 16T
    artifact.  Pure: no I/O beyond what it is handed, so the controls below can
    feed it mutated documents."""
    checks = {}

    def ck(name, ok, evidence=""):
        checks[name] = {"pass": bool(ok), "evidence": evidence}

    pw = doc.get("per_wave") or []
    epochs = doc.get("barrier_epoch_list_from_model")
    epochs = epochs if epochs is not None else []

    ck("V1_eight_waves_present",
       len(pw) == WAVES and sorted(w.get("wave") for w in pw) == list(range(WAVES)),
       "waves=%s" % sorted(w.get("wave") for w in pw))

    seqs = [list(w.get("barrier_pc_sequence") or []) for w in pw]
    lens = [len(s) for s in seqs]
    ck("V2_no_wave_ends_while_a_peer_awaits_a_later_barrier",
       len(set(lens)) == 1 and (lens[0] if lens else 0) > 0,
       "lengths=%s" % lens)

    same = bool(seqs) and all(s == seqs[0] for s in seqs)
    ck("V3_all_waves_reach_the_same_barriers_in_the_same_order", same,
       "%d sequences compared" % len(seqs))

    # EVERY wave, not just wave 0: checking one wave would let a mutated peer
    # leave this axis reading True, and "the trace shows the J3 sequence" would
    # then be a claim about a single column dressed up as a claim about the run.
    ck("V4_every_wave_shows_the_expected_ten_barriers_in_program_order",
       bool(seqs) and all(s == EXPECTED_ORDER for s in seqs),
       "differing waves=%s"
       % [i for i, s in enumerate(seqs) if s != EXPECTED_ORDER])

    counts_bbe20 = [sum(1 for p in s if p == IN_LOOP) for s in seqs]
    ordinals = [(s.index(IN_LOOP) + 1) if IN_LOOP in s else None for s in seqs]
    reached_all = bool(seqs) and all(IN_LOOP in s for s in seqs)
    ck("V5_in_loop_barrier_reached_by_every_wave_exactly_once",
       reached_all and set(counts_bbe20) == {1},
       "counts=%s ordinals=%s" % (counts_bbe20, ordinals))
    ck("V6_every_wave_at_the_same_barrier_ordinal", len(set(ordinals)) == 1,
       "ordinals=%s" % ordinals)

    hdrs = [w.get("loop_header_entries") for w in pw]
    ck("V7_every_wave_iterates_the_header_the_same_number_of_times",
       len(set(hdrs)) == 1 and hdrs and hdrs[0] is not None, "hdrs=%s" % hdrs)

    # ---- THE INDEPENDENT ANCHOR (cross-instrument) -----------------------
    per_wave_union = set()
    for s in seqs:
        per_wave_union.update(s)
    epc = set(epochs)
    ck("V8_per_wave_instrument_agrees_with_the_scheduler_epoch_list",
       per_wave_union == epc and bool(epc),
       "instrument_only=%s scheduler_only=%s"
       % (sorted(hex(x) for x in per_wave_union - epc),
          sorted(hex(x) for x in epc - per_wave_union)))
    ck("V9_the_two_instruments_agree_on_the_ORDER",
       bool(seqs) and seqs[0] == list(epochs),
       "wave0=%s" % [hex(x) for x in (seqs[0] if seqs else [])])

    # ---- non-perturbation against the frozen 16T artifact ----------------
    npb = doc.get("nonperturbation_observables") or {}
    axes = {
        "ticks": "ticks",
        "outcome": "outcome",
        "natural_end": "natural_end",
        "control_flow_signature": "control_flow_signature",
        "store_digest": "store_digest",
        "store_addresses_sha256": "store_addresses_sha256",
        "by_pc_n": "by_pc_n",
        "gate": "gate",
    }
    mism = []
    for k, fk in axes.items():
        if json.dumps(npb.get(k), sort_keys=True) != json.dumps(frozen.get(fk),
                                                                sort_keys=True):
            mism.append(k)
    if json.dumps(npb.get("barrier_epochs") or epochs, sort_keys=True) != \
            json.dumps(frozen.get("barrier_epochs"), sort_keys=True):
        mism.append("barrier_epochs")
    ck("V10_the_run_reproduced_the_frozen_J3_on_every_named_axis",
       not mism, "mismatched axes=%s" % (mism or "none"))

    # ---- the trace must not be vacuous -----------------------------------
    steps = [w.get("instrument_steps") for w in pw]
    halts = [w.get("halting_steps") for w in pw]
    haltpcs = [w.get("halt_pcs") for w in pw]
    ck("V11_recording_is_not_vacuous",
       all((x or 0) > 0 for x in steps) and all(x == 1 for x in halts)
       and all(h == [hex(ENDPGM)] for h in haltpcs),
       "steps=%s halting=%s halt_pcs=%s" % (steps, halts, haltpcs))
    fs = [w.get("frozen_16t_steps") for w in pw]
    ck("V12_step_counts_agree_with_the_frozen_16t_artifact",
       all((s - h) == f for s, h, f in zip(steps, halts, fs)),
       "counted=%s frozen=%s" % ([s - h for s, h in zip(steps, halts)], fs))

    failed = sorted(k for k, v in checks.items() if not v["pass"])
    internal = all(checks[k]["pass"] for k in
                   ("V1_eight_waves_present",
                    "V2_no_wave_ends_while_a_peer_awaits_a_later_barrier",
                    "V3_all_waves_reach_the_same_barriers_in_the_same_order",
                    "V6_every_wave_at_the_same_barrier_ordinal",
                    "V7_every_wave_iterates_the_header_the_same_number_of_times"))
    ground_truth = all(checks[k]["pass"] for k in
                       ("V4_every_wave_shows_the_expected_ten_barriers_in_program_order",
                        "V5_in_loop_barrier_reached_by_every_wave_exactly_once",
                        "V8_per_wave_instrument_agrees_with_the_scheduler_epoch_list",
                        "V9_the_two_instruments_agree_on_the_ORDER",
                        "V10_the_run_reproduced_the_frozen_J3_on_every_named_axis",
                        "V11_recording_is_not_vacuous",
                        "V12_step_counts_agree_with_the_frozen_16t_artifact"))
    return {
        "checks": checks,
        "internal_consistency": internal,
        "agreement_with_observed_j3_ground_truth": ground_truth,
        "checks_failed": failed,
        "in_loop_barrier_reached": reached_all,
        "in_loop_barrier_counts_per_wave": counts_bbe20,
        "in_loop_barrier_ordinal_per_wave": ordinals,
        "loop_header_entries_per_wave": hdrs,
        "verdict": ("PASS" if (internal and ground_truth and not failed)
                    else "FAIL"),
    }


def controls(doc, frozen):
    """S25.  The HOST trace is mutated here; Candidate F is not.  A verifier
    that rejects nothing is not a verifier.

    Each case states the two axes SEPARATELY, because the whole point of S25 is
    that they can disagree: a trace can be perfectly self-consistent and still
    not be the J3 run we observed.
    """
    import copy as _copy
    cases = []

    def run(label, mutate, want_verdict, want_internal, want_truth):
        d = _copy.deepcopy(doc)
        mutate(d)
        r = verdict_of(d, frozen)
        ok = (r["verdict"] == want_verdict
              and r["internal_consistency"] == want_internal
              and r["agreement_with_observed_j3_ground_truth"] == want_truth)
        cases.append({
            "case": label,
            "expected": {"verdict": want_verdict, "internal": want_internal,
                         "ground_truth": want_truth},
            "actual": {"verdict": r["verdict"],
                       "internal": r["internal_consistency"],
                       "ground_truth":
                           r["agreement_with_observed_j3_ground_truth"],
                       "failed": r["checks_failed"]},
            "verdict": "PASS" if ok else "FAIL",
        })

    run("pristine serialized trace", lambda d: None, "PASS", True, True)

    def m_missing(d):
        s = d["per_wave"][7]["barrier_pc_sequence"]
        d["per_wave"][7]["barrier_pc_sequence"] = s[:-1]
    run("wave 7 is short one barrier event (exits before the last barrier)",
        m_missing, "FAIL", False, False)
    # (V4 is per-wave, so a mutated peer moves the ground-truth axis too)

    def m_extra(d):
        s = list(d["per_wave"][3]["barrier_pc_sequence"])
        s.insert(7, IN_LOOP)
        d["per_wave"][3]["barrier_pc_sequence"] = s
    run("wave 3 is given one extra in-loop barrier event",
        m_extra, "FAIL", False, False)

    def m_reorder(d):
        d["per_wave"][2]["barrier_pc_sequence"] = list(
            reversed(d["per_wave"][2]["barrier_pc_sequence"]))
    run("wave 2 reaches the same barriers in a different order",
        m_reorder, "FAIL", False, False)

    def m_iters(d):
        d["per_wave"][5]["loop_header_entries"] = \
            (d["per_wave"][5]["loop_header_entries"] or 1) + 1
    # This defect lives ONLY on the internal-consistency axis: the eight
    # barrier sequences and the run identity are untouched, so the trace still
    # shows the J3 barrier sequence correctly while contradicting itself about
    # how many times the header was entered.  Reported as such rather than
    # forced onto both axes.
    run("wave 5 iterates the loop header one more time",
        m_iters, "FAIL", False, True)

    def m_no_bbe20(d):
        for w in d["per_wave"]:
            w["barrier_pc_sequence"] = [p for p in w["barrier_pc_sequence"]
                                        if p != IN_LOOP]
            w["in_loop_barrier_executions"] = 0
    run("ALL EIGHT waves consistently omit 0xBBE20 -- internally consistent, "
        "but the scheduler epoch list still has it", m_no_bbe20,
        "FAIL", True, False)

    def m_epochs_scrubbed(d):
        # the harder version of the same lie: scrub the independent anchor too
        for w in d["per_wave"]:
            w["barrier_pc_sequence"] = [p for p in w["barrier_pc_sequence"]
                                        if p != IN_LOOP]
        d["barrier_epoch_list_from_model"] = [p for p
                                              in d["barrier_epoch_list_from_model"]
                                              if p != IN_LOOP]
    run("all waves omit 0xBBE20 AND the epoch list is scrubbed to match "
        "(the trace no longer matches the frozen J3 sequence)", m_epochs_scrubbed,
        "FAIL", True, False)

    def m_perturbed(d):
        d["nonperturbation_observables"]["ticks"] = 12345
    run("the instrumented run's tick count disagrees with the frozen J3",
        m_perturbed, "FAIL", True, False)

    def m_vacuous(d):
        for w in d["per_wave"]:
            w["barrier_pc_sequence"] = []
            w["instrument_steps"] = 0
            w["halting_steps"] = 0
    run("the instrument recorded nothing at all (vacuous trace)",
        m_vacuous, "FAIL", False, False)

    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", default=TRACE)
    ap.add_argument("--controls", action="store_true")
    a = ap.parse_args()
    doc = json.load(open(a.trace, encoding="utf-8"))
    frozen = json.load(open(FROZEN_16T, encoding="utf-8"))
    if a.controls:
        cs = controls(doc, frozen)
        print("independent verifier negative controls (S25):")
        for c in cs:
            print("  %-72s %s" % (c["case"][:72], c["verdict"]))
            if c["verdict"] != "PASS":
                print("        expected %s" % json.dumps(c["expected"]))
                print("        actual   %s" % json.dumps(c["actual"]))
        bad = [c for c in cs if c["verdict"] != "PASS"]
        print("cases=%d failed=%d" % (len(cs), len(bad)))
        with open(CONTROLS_OUT, "w", encoding="utf-8") as f:
            json.dump({
                "schema": "phase16y-barrier-independent-controls/1",
                "phase": "16Y",
                "note": "S25: the HOST trace is mutated here; Candidate F is "
                        "not.  internal_consistency and agreement_with_"
                        "observed_ground_truth are reported separately, so an "
                        "'all waves omit 0xBBE20' trace that agrees with "
                        "itself cannot masquerade as the observed J3 trace.",
                "verifier": "phase16y/liveness/p16y_barrier_verify.py",
                "cases": cs, "n_failed": len(bad),
                "verdict": "PASS" if not bad else "FAIL",
            }, f, indent=1)
            f.write("\n")
        print("INDEPENDENT CONTROL VERDICT: %s"
              % ("PASS" if not bad else "FAIL"))
        return 0 if not bad else 1
    r = verdict_of(doc, frozen)
    print("independent verifier over %s" % os.path.relpath(a.trace, ROOT))
    for k in sorted(r["checks"]):
        v = r["checks"][k]
        print("  %-64s %s" % (k, "PASS" if v["pass"] else "FAIL"))
        if not v["pass"]:
            print("        %s" % v["evidence"])
    print("internal consistency      : %s" % r["internal_consistency"])
    print("agrees with observed J3   : %s"
          % r["agreement_with_observed_j3_ground_truth"])
    print("VERDICT: %s" % r["verdict"])
    return 0 if r["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
