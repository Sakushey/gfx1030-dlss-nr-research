"""Host-only tests for the fail-closed qualification primitives.

Every test here exists because a real readiness generator got the corresponding
question wrong.  The tests are written so that the *known-good* case is checked
as well as the rejection: a checker that rejects everything reads as strict and
is just as broken as one that accepts everything.

    unittest, not pytest -- matches the rest of this suite and keeps the tests
    runnable on a host with no test dependencies installed.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hostpath  # noqa: F401  (puts src/* on sys.path)

from qualification import (                                    # noqa: E402
    ALLOWED_RESULTS, Coverage, Evidence, aggregate, gate,
    sha256_file, sha256_file_independent,
)
from qualification import evidence as ev_mod                   # noqa: E402
from qualification.attempt_ledger import AttemptLedger         # noqa: E402
from qualification import mutation as mut_mod                  # noqa: E402


def _good_predicate():
    return ("PASS", {"measured": True}, "everything checked", None)


class TestResultVocabulary(unittest.TestCase):
    def test_exactly_four_results(self):
        self.assertEqual(
            sorted(ALLOWED_RESULTS),
            ["FAIL", "NOT_APPLICABLE_PROVEN", "PASS", "UNKNOWN"])

    def test_there_is_no_pass_by_default(self):
        for forbidden in ("PASS_BY_DEFAULT", "OK", "TRUE", "SUCCESS"):
            self.assertNotIn(forbidden, ALLOWED_RESULTS)


class TestCoverage(unittest.TestCase):
    def test_a_complete_row_is_complete(self):
        c = Coverage("cats", total=10, analyzed=8, proven_na=2, unsupported=0,
                     skipped=0, checker="t", evidence="t")
        self.assertTrue(c.complete)
        self.assertEqual(c.status, "COMPLETE")

    def test_an_unaccounted_row_is_incomplete(self):
        c = Coverage("cats", 10, 8, 1, 0, 0, "t", "t")
        self.assertFalse(c.complete)
        self.assertEqual(c.status, "INCOMPLETE")

    def test_unsupported_blocks_even_when_the_arithmetic_adds_up(self):
        """analyzed + proven_na == total, and it is still not complete."""
        c = Coverage("cats", 10, 8, 2, unsupported=3, skipped=0,
                     checker="t", evidence="t")
        self.assertEqual(c.accounted, c.total)
        self.assertFalse(c.complete)

    def test_skipped_blocks(self):
        c = Coverage("cats", 10, 10, 0, 0, 1, "t", "t")
        self.assertFalse(c.complete)

    def test_a_zero_total_row_without_a_proof_is_NOT_complete(self):
        """The arithmetic form of all([]): 0 + 0 == 0 is not a pass."""
        c = Coverage("depctr", 0, 0, 0, 0, 0, "t", "t")
        self.assertTrue(c.is_vacuous)
        self.assertFalse(c.complete)
        self.assertEqual(c.status, "INCOMPLETE")

    def test_a_zero_total_row_with_a_written_proof_is_proven_not_applicable(self):
        c = Coverage("depctr", 0, 0, 0, 0, 0, "t", "t",
                     basis="PROOF OF EMPTINESS: zero such instructions execute in "
                           "the analysed prefix, so there is nothing to decode.")
        self.assertTrue(c.complete)
        self.assertEqual(c.status, "NOT_APPLICABLE_PROVEN")


class TestGateRefusals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.present = os.path.join(self.tmp, "present.json")
        with open(self.present, "w", encoding="utf-8") as fh:
            json.dump({"k": 1}, fh)
        self.absent = os.path.join(self.tmp, "absent.json")

    def test_the_known_good_case_is_ACCEPTED(self):
        g = gate("G", "r", [self.present], _good_predicate, ["nc"])
        self.assertEqual(g["result"], "PASS")

    def test_missing_mandatory_evidence_is_UNKNOWN_not_PASS(self):
        g = gate("G", "r", [self.absent], _good_predicate, ["nc"])
        self.assertEqual(g["result"], "UNKNOWN")
        self.assertIn("absent", g["reason"])

    def test_a_missing_artefact_cannot_be_promoted_by_a_good_predicate(self):
        """The predicate says PASS; the gate still refuses."""
        g = gate("G", "r", [self.absent], _good_predicate, ["nc"])
        self.assertNotEqual(g["result"], "PASS")

    def test_a_raising_predicate_is_FAIL_not_PASS(self):
        def boom():
            raise ValueError("checker bug")
        g = gate("G", "r", [self.present], boom, ["nc"])
        self.assertEqual(g["result"], "FAIL")
        self.assertIn("ValueError", json.dumps(g["recomputed_measurement"]))

    def test_an_out_of_vocabulary_status_is_FAIL(self):
        g = gate("G", "r", [self.present], lambda: ("PROBABLY_FINE", {}, "", None),
                 ["nc"])
        self.assertEqual(g["result"], "FAIL")

    def test_not_applicable_without_a_proof_is_FAIL(self):
        g = gate("G", "r", [self.present],
                 lambda: ("NOT_APPLICABLE_PROVEN", {}, "trust me", None), ["nc"])
        self.assertEqual(g["result"], "FAIL")

    def test_not_applicable_with_a_proof_is_accepted(self):
        g = gate("G", "r", [self.present],
                 lambda: ("NOT_APPLICABLE_PROVEN", {}, "why", "a real proof"),
                 ["nc"])
        self.assertEqual(g["result"], "NOT_APPLICABLE_PROVEN")


class TestAggregate(unittest.TestCase):
    def _g(self, gid, result, ncs=("nc",)):
        return {"gate_id": gid, "result": result, "negative_control_ids": list(ncs)}

    def test_all_pass_is_pass(self):
        self.assertEqual(aggregate([self._g("A", "PASS")])["verdict"], "PASS")

    def test_one_fail_blocks(self):
        agg = aggregate([self._g("A", "PASS"), self._g("B", "FAIL")])
        self.assertEqual(agg["verdict"], "FAIL")
        self.assertEqual(agg["blocking_gates"], ["B"])

    def test_one_unknown_blocks(self):
        agg = aggregate([self._g("A", "PASS"), self._g("B", "UNKNOWN")])
        self.assertEqual(agg["verdict"], "FAIL")

    def test_a_gate_with_no_negative_control_is_an_orphan_and_blocks(self):
        agg = aggregate([self._g("A", "PASS"), self._g("B", "PASS", ncs=())])
        self.assertEqual(agg["verdict"], "FAIL")
        self.assertEqual(agg["orphan_gates"], ["B"])

    def test_proven_not_applicable_does_not_block(self):
        agg = aggregate([self._g("A", "PASS"), self._g("B", "NOT_APPLICABLE_PROVEN")])
        self.assertEqual(agg["verdict"], "PASS")


class TestObservation(unittest.TestCase):
    def _fake(self, returncode, stdout, stderr=""):
        class P:
            pass
        p = P()
        p.returncode, p.stdout, p.stderr = returncode, stdout, stderr
        return p

    def test_a_successful_enumeration_observes(self):
        orig = ev_mod.subprocess.run
        ev_mod.subprocess.run = lambda *a, **k: self._fake(0, "a\nb\n")
        try:
            o = ev_mod.run_observation(["x"])
        finally:
            ev_mod.subprocess.run = orig
        self.assertTrue(o.observed)
        self.assertEqual(o.n_records, 2)

    def test_a_nonzero_return_code_is_an_OBSERVATION_FAILURE(self):
        orig = ev_mod.subprocess.run
        ev_mod.subprocess.run = lambda *a, **k: self._fake(1, "", "Access denied")
        try:
            o = ev_mod.run_observation(["x"])
        finally:
            ev_mod.subprocess.run = orig
        self.assertFalse(o.observed)
        self.assertIn("OBSERVATION FAILURE", o.why_not_observed)

    def test_empty_output_is_an_OBSERVATION_FAILURE_not_an_empty_result(self):
        orig = ev_mod.subprocess.run
        ev_mod.subprocess.run = lambda *a, **k: self._fake(0, "")
        try:
            o = ev_mod.run_observation(["x"])
        finally:
            ev_mod.subprocess.run = orig
        self.assertFalse(o.observed)
        self.assertIn("not evidence of absence", o.why_not_observed)

    def test_a_command_that_cannot_run_is_an_OBSERVATION_FAILURE(self):
        orig = ev_mod.subprocess.run

        def boom(*a, **k):
            raise OSError("no such binary")
        ev_mod.subprocess.run = boom
        try:
            o = ev_mod.run_observation(["definitely-not-a-real-binary-xyz"])
        finally:
            ev_mod.subprocess.run = orig
        self.assertFalse(o.observed)


class TestIdentity(unittest.TestCase):
    def test_two_independent_digest_paths_agree(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"hello world" * 5000)
            p = fh.name
        try:
            self.assertEqual(sha256_file(p), sha256_file_independent(p))
        finally:
            os.unlink(p)

    def test_a_missing_file_raises_rather_than_returning_a_digest(self):
        with self.assertRaises(FileNotFoundError):
            sha256_file(os.path.join(tempfile.mkdtemp(), "nope"))


class TestAttemptLedger(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "ATTEMPTS.jsonl")
        self.led = AttemptLedger(self.path)

    def test_an_empty_ledger_has_an_intact_chain(self):
        self.assertTrue(self.led.verify_chain()["intact"])

    def test_reserving_does_not_consume_budget(self):
        self.led.reserve(attempt_uuid="a1")
        b = self.led.derive_budget(1)
        self.assertEqual(b["derived_spent"], 0)
        self.assertEqual(b["derived_remaining"], 1)
        self.assertFalse(b["hardcoded"])
        self.assertEqual(len(b["reserved_but_never_launched"]), 1)

    def test_consuming_consumes_budget(self):
        self.led.reserve(attempt_uuid="a1")
        self.led.consume("a1")
        b = self.led.derive_budget(1)
        self.assertEqual(b["derived_spent"], 1)
        self.assertEqual(b["derived_remaining"], 0)

    def test_the_same_attempt_cannot_be_consumed_twice(self):
        self.led.reserve(attempt_uuid="a1")
        self.assertIsNotNone(self.led.consume("a1"))
        self.assertIsNone(self.led.consume("a1"))
        self.assertEqual(self.led.derive_budget(1)["derived_spent"], 1)

    def test_budget_is_derived_and_never_negative(self):
        self.led.consume("a1")
        self.led.consume("a2")
        self.assertEqual(self.led.derive_budget(1)["derived_remaining"], 0)

    def test_editing_a_middle_record_breaks_the_chain(self):
        self.led.append("RESERVED", attempt_uuid="a1")
        self.led.append("LAUNCH_STARTED", attempt_uuid="a1")
        self.led.append("FINAL_OUTCOME", attempt_uuid="a1", outcome="TDR")
        self.assertTrue(self.led.verify_chain()["intact"])

        with open(self.path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        rec = json.loads(lines[1])
        rec["note"] = "tampered"
        lines[1] = json.dumps(rec, sort_keys=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

        v = self.led.verify_chain()
        self.assertFalse(v["intact"])
        self.assertEqual(v["broken_at_sequence"], 1)

    def test_truncating_the_file_breaks_the_chain(self):
        self.led.append("RESERVED", attempt_uuid="a1")
        self.led.append("LAUNCH_STARTED", attempt_uuid="a1")
        self.led.append("FINAL_OUTCOME", attempt_uuid="a1")
        with open(self.path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(lines[1] + "\n")          # drop the genesis record
        self.assertFalse(self.led.verify_chain()["intact"])

    def test_an_unknown_event_is_refused(self):
        with self.assertRaises(ValueError):
            self.led.append("NOT_A_REAL_EVENT", attempt_uuid="a1")


class TestMutationHarness(unittest.TestCase):
    """The harness must be able to report a gate as unmutatable, and must carry
    a known-good control -- otherwise it measures itself."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.artifact = os.path.join(self.tmp, "artifact.json")
        with open(self.artifact, "w", encoding="utf-8") as fh:
            json.dump({"verdict": "CLEAN", "n": 3}, fh)

    def _build(self, ev):
        def p_reads_the_field():
            d = ev.json(self.artifact)
            ok = d.get("verdict") == "CLEAN" and d.get("n") == 3
            return ("PASS" if ok else "FAIL", {"verdict": d.get("verdict")}, "", None)

        # the second gate has NO effective mutant available in this fixture:
        # its decisive evidence is its own source, which no mutation here touches
        def p_cannot_be_mutated():
            return ("PASS", {"yes": True}, "", None)

        gates = [
            gate("G1-field", "reads a field", [self.artifact], p_reads_the_field,
                 ["field_wrong"]),
            gate("G2-unmutatable", "no mutant reaches it", [self.artifact],
                 p_cannot_be_mutated, ["nothing"]),
        ]
        return {"gate_results": gates, "aggregate": aggregate(gates)}

    def test_the_control_reproduces_the_baseline(self):
        rep = mut_mod.run_suite(self._build, [])
        self.assertEqual(rep["baseline_final_verdict"], "PASS")
        self.assertTrue(rep["known_good_control"]["reproduces_the_baseline"])

    def test_a_working_mutation_flips_the_verdict(self):
        m = mut_mod.set_fields("artifact.json", verdict="DIRTY")
        rep = mut_mod.run_suite(self._build, [("flip_verdict", m, "G1")])
        self.assertEqual(rep["n_effective"], 1)
        self.assertTrue(rep["results"][0]["final_verdict_changed"])

    def test_an_unmutatable_gate_is_reported_not_hidden(self):
        m = mut_mod.set_fields("artifact.json", verdict="DIRTY")
        rep = mut_mod.run_suite(self._build, [("flip_verdict", m, "G1")])
        self.assertFalse(rep["every_gate_has_an_effective_mutant"])
        self.assertEqual(rep["gates_without_effective_mutant"], ["G2-unmutatable"])

    def test_a_raw_mutation_does_not_silently_no_op_on_a_parsed_object(self):
        """The defect that made a sound system look fail-open: field mutations
        applied to raw bytes are no-ops.  The Evidence layer must offer both
        surfaces so a field mutation actually reaches the parsed object."""
        ev = Evidence(mutate=mut_mod.set_fields("artifact.json", verdict="DIRTY"))
        self.assertEqual(ev.json(self.artifact)["verdict"], "DIRTY")

    def test_a_raw_mutation_reaches_bytes(self):
        ev = Evidence(mutate=mut_mod.flip_bytes("artifact.json"))
        with open(self.artifact, "rb") as fh:
            on_disk = fh.read()
        self.assertNotEqual(ev.raw(self.artifact), on_disk)

    def test_malformed_json_is_reported_by_the_gate_not_swallowed(self):
        ev = Evidence(mutate=mut_mod.malformed_json("artifact.json"))
        with self.assertRaises(Exception):
            ev.json(self.artifact)


if __name__ == "__main__":
    unittest.main()
