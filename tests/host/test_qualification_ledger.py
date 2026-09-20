"""Host-only regression for the artifact-backed qualification ledger.

The defect
----------
`tools/k_readiness.py` decided the four flags that gated `J3_READY` from
string literals:

    ev["F_output_dependency_slice"] = "NOT_BUILT"
    ev["G_j3v2_input_expected_harness"] = "NOT_BUILT"
    ev["I_final_package"] = "PARTIAL (H track only)"
    ev["J_adversarial_release_tests"] = "NOT_BUILT"

Every other flag in that file is derived from an artifact on disk. These four
were typed in, which made them the only claims nothing could contradict --
and they were exactly the four gating the decision. A phase that built one of
them would have had to edit the literal by hand, and the resulting flag would
report the last editor's belief.

What is checked here
--------------------
`tools/qualification_ledger.py` replaces them with one ledger keyed by
(source profile, source object SHA, translated object SHA, device, runtime,
fixture, geometry, test version), with seven independent stages and five
statuses. The load-bearing checks are the negative controls:

  * `test_negative_control_a_pass_with_no_artifact_is_not_a_pass` -- the
    literal's replacement must not be able to claim a status nothing supports.
  * `test_negative_control_an_artifact_that_changed_makes_the_record_stale`
    -- STALE is computed from the bytes, so an artifact edited after the fact
    invalidates its record.
  * `test_negative_control_a_final_head_pass_does_not_advance_j3` -- the
    brief's rule, tested with every required stage recorded PASS under a
    final-head profile.
  * `test_negative_control_a_near_miss_key_is_not_counted` -- a single
    differing key field is enough, and the refusal names the field.
  * `test_negative_control_one_stage_does_not_stand_in_for_another` -- stages
    are independent, so a green ISOLATED_PHYSICAL does not decide
    AUTHENTIC_DISPATCH.
  * status and stage vocabularies are closed, and STALE cannot be stored.

Nothing here runs GPU work, opens a device, or writes outside a temporary
directory.
"""
from __future__ import annotations

import ast
import json
import os
import shutil
import tempfile
import unittest

import hostpath  # noqa: F401  (sets up the import namespace)

REPO = hostpath.REPO_ROOT
TOOLS = os.path.join(REPO, "tools")
READINESS = os.path.join(TOOLS, "k_readiness.py")
LEDGER_PY = os.path.join(TOOLS, "qualification_ledger.py")

import sys  # noqa: E402
sys.path.insert(0, TOOLS)

import qualification_ledger as ql  # noqa: E402


def a_key(**over) -> ql.Key:
    """The key under test, with individual fields overridable."""
    base = dict(
        source_profile=ql.J3_SOURCE_PROFILE,
        source_object_sha256="a" * 64,
        translated_object_sha256="b" * 64,
        device="gfx1030",
        runtime="rocm6.4",
        fixture="swin32f",
        geometry="one_workgroup",
        test_version="16o",
    )
    base.update(over)
    return ql.Key(**base)


ALL_PASS_STAGES = ql.J3_REQUIRED_STAGES


def passing_records(key, root, stage_list=ALL_PASS_STAGES, status="PASS",
                    artifact="evidence.json"):
    """Records that would advance J3, each citing a real hashed file."""
    path = os.path.join(root, artifact)
    with open(path, "wb") as f:
        f.write(b'{"evidence": "real bytes"}\n')
    digest = ql.sha256_file(path)
    recs = []
    for stage in stage_list:
        recs.append(ql.Record(key=key, stage=stage, status=status,
                              artifacts=[ql.Artifact(artifact, digest)],
                              observed_utc="2026-09-20T00:00:00Z"))
    return recs


class TestTheLedgerVocabularyIsClosed(unittest.TestCase):

    def test_the_seven_stages_are_exactly_the_required_set(self):
        self.assertEqual(list(ql.STAGES), [
            "HOST_STATIC", "HOST_NUMERIC", "ISOLATED_PHYSICAL",
            "AUTHENTIC_DISPATCH", "COMPLETE_JOB", "TRANSPORT", "PRESENTATION"])

    def test_the_five_statuses_are_exactly_the_required_set(self):
        self.assertEqual(list(ql.STATUSES),
                         ["NOT_RUN", "PASS", "FAIL", "UNSUPPORTED", "STALE"])

    def test_the_key_has_the_eight_required_fields(self):
        self.assertEqual(list(ql.KEY_FIELDS), [
            "source_profile", "source_object_sha256",
            "translated_object_sha256", "device", "runtime", "fixture",
            "geometry", "test_version"])

    def test_an_unknown_stage_is_refused(self):
        with self.assertRaises(ql.LedgerFormatError):
            ql.Record(key=a_key(), stage="MOSTLY_DONE", status="PASS")

    def test_an_unknown_status_is_refused(self):
        with self.assertRaises(ql.LedgerFormatError):
            ql.Record(key=a_key(), stage="HOST_STATIC", status="LGTM")

    def test_stale_cannot_be_stored(self):
        """STALE is a conclusion about artifacts, not an assertion."""
        with self.assertRaises(ql.LedgerFormatError):
            ql.Record(key=a_key(), stage="HOST_STATIC", status="STALE")

    def test_a_partial_key_is_refused(self):
        with self.assertRaises(ql.LedgerKeyError):
            ql.Key(source_profile="x", source_object_sha256="",
                    translated_object_sha256="b", device="d", runtime="r",
                    fixture="f", geometry="g", test_version="v")

    def test_a_key_missing_a_field_is_refused(self):
        d = {f: "x" for f in ql.KEY_FIELDS}
        d.pop("runtime")
        with self.assertRaises(ql.LedgerKeyError):
            ql.key_from_dict(d)

    def test_an_unrecognised_key_field_is_refused(self):
        d = {f: "x" for f in ql.KEY_FIELDS}
        d["confidence"] = "high"
        with self.assertRaises(ql.LedgerKeyError):
            ql.key_from_dict(d)


class TestReadingStatuses(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f7-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_an_empty_ledger_reports_every_stage_not_run(self):
        led = ql.Ledger([], self.tmp)
        self.assertEqual(led.statuses_for(a_key()),
                         {s: "NOT_RUN" for s in ql.STAGES})

    def test_a_missing_ledger_file_is_an_empty_ledger(self):
        led = ql.Ledger.load(os.path.join(self.tmp, "absent.json"))
        self.assertEqual(led.records, [])
        self.assertEqual(led.status(a_key(), "HOST_STATIC"), "NOT_RUN")

    def test_a_recorded_pass_reads_back_as_pass(self):
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        self.assertEqual(led.status(key, "HOST_STATIC"), "PASS")
        self.assertEqual(led.status(key, "PRESENTATION"), "NOT_RUN")

    def test_round_trips_through_json(self):
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        path = os.path.join(self.tmp, "ledger.json")
        led.save(path)
        back = ql.Ledger.load(path, root=self.tmp)
        self.assertEqual(len(back.records), len(led.records))
        self.assertEqual(back.status(key, "COMPLETE_JOB"), "PASS")

    def test_the_saved_file_names_its_own_stages_and_statuses(self):
        """The vocabulary travels with the artifact, not only with the code."""
        led = ql.Ledger(passing_records(a_key(), self.tmp), self.tmp)
        path = os.path.join(self.tmp, "ledger.json")
        led.save(path)
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["schema"], ql.SCHEMA)
        self.assertEqual(doc["stages"], list(ql.STAGES))
        self.assertEqual(doc["statuses"], list(ql.STATUSES))

    def test_untraceable_records_are_surfaced_not_discarded(self):
        other = a_key(fixture="swin64f")
        led = ql.Ledger(passing_records(other, self.tmp), self.tmp)
        self.assertEqual(led.untraceable(a_key(), "HOST_STATIC"),
                         led.records[:1])
        self.assertEqual(led.status(a_key(), "HOST_STATIC"), "NOT_RUN")


class TestNegativeControls(unittest.TestCase):
    """Each control constructs the broken behaviour and requires rejection."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f7neg-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_negative_control_a_pass_with_no_artifact_is_not_a_pass(self):
        """The literal's replacement must not assert what nothing supports.

        A PASS with no cited artifact is exactly the shape of a typed-in
        NOT_BUILT: a status with nothing behind it.
        """
        key = a_key()
        rec = ql.Record(key=key, stage="HOST_STATIC", status="PASS")
        led = ql.Ledger([rec], self.tmp)
        self.assertEqual(rec.own_health(self.tmp), "NO_ARTIFACT")
        self.assertEqual(led.status(key, "HOST_STATIC"), "STALE")
        self.assertEqual(led.stale_records()[0][1], "NO_ARTIFACT")

    def test_negative_control_an_artifact_that_changed_makes_the_record_stale(self):
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        self.assertEqual(led.status(key, "HOST_STATIC"), "PASS")
        # Someone rewrites the evidence after the record was made.
        with open(os.path.join(self.tmp, "evidence.json"), "ab") as f:
            f.write(b"and a change nobody recorded\n")
        self.assertEqual(led.status(key, "HOST_STATIC"), "STALE")
        self.assertEqual(led.stale_records()[0][1], "CHANGED")

    def test_negative_control_a_missing_artifact_makes_the_record_stale(self):
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        os.remove(os.path.join(self.tmp, "evidence.json"))
        self.assertEqual(led.status(key, "HOST_STATIC"), "STALE")
        self.assertEqual(led.stale_records()[0][1], "MISSING")

    def test_negative_control_a_final_head_pass_does_not_advance_j3(self):
        """The brief's rule, with every required stage recorded PASS.

        The contributor's artifact set is a different chain: a different
        source object, a different fixture. Its PASS is a real PASS about
        *that* set, so the refusal must come from the profile and not from a
        missing stage -- otherwise a future contributor could advance J3 by
        recording the stages it does own.
        """
        key = a_key(source_profile="astra-final-head")
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        self.assertEqual(
            [led.status(key, s) for s in ALL_PASS_STAGES],
            ["PASS"] * len(ALL_PASS_STAGES),
            "the control needs every stage to be PASS to prove the point")
        decision = ql.j3_decision(led, key)
        self.assertFalse(decision.advance)
        self.assertTrue(any("final-head" in r for r in decision.reasons))

    def test_negative_control_every_final_head_alias_is_refused(self):
        for profile in ql.FINAL_HEAD_PROFILES:
            key = a_key(source_profile=profile)
            led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
            self.assertFalse(ql.j3_decision(led, key).advance, profile)

    def test_negative_control_another_kernel_is_not_j3(self):
        key = a_key(source_profile="swin<64,false>")
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        decision = ql.j3_decision(led, key)
        self.assertFalse(decision.advance)
        self.assertTrue(any("not the kernel under qualification" in r
                            for r in decision.reasons))

    def test_negative_control_a_near_miss_key_is_not_counted(self):
        """One differing field is enough, and the refusal names the field."""
        recorded = a_key()
        queried = a_key(translated_object_sha256="c" * 64)
        led = ql.Ledger(passing_records(recorded, self.tmp), self.tmp)
        decision = ql.j3_decision(led, queried)
        self.assertFalse(decision.advance)
        self.assertTrue(any("translated_object_sha256" in nm
                            for nm in decision.near_misses),
                        decision.near_misses)

    def test_negative_control_one_stage_does_not_stand_in_for_another(self):
        """Stages are independent: a green device run decides nothing else.

        The literal vocabulary could not express this -- one word covered
        four different questions.
        """
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp,
                                        stage_list=("ISOLATED_PHYSICAL",)),
                        self.tmp)
        self.assertEqual(led.status(key, "ISOLATED_PHYSICAL"), "PASS")
        self.assertEqual(led.status(key, "AUTHENTIC_DISPATCH"), "NOT_RUN")
        self.assertEqual(led.status(key, "COMPLETE_JOB"), "NOT_RUN")
        decision = ql.j3_decision(led, key)
        self.assertFalse(decision.advance)
        self.assertIn("AUTHENTIC_DISPATCH=NOT_RUN", decision.reasons)

    def test_negative_control_a_fail_is_not_a_pass(self):
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp,
                                        stage_list=("COMPLETE_JOB",),
                                        status="FAIL"), self.tmp)
        self.assertEqual(ql.j3_decision(led, key).per_stage["COMPLETE_JOB"],
                         "FAIL")
        self.assertFalse(ql.j3_decision(led, key).advance)

    def test_negative_control_unsupported_is_not_stale_and_not_pass(self):
        """The distinction the vocabulary exists for.

        UNSUPPORTED says the stage cannot be evaluated for this key at all;
        STALE says it was evaluated and its evidence no longer holds. A
        single word for both would report a device that cannot run the
        geometry as if evidence had rotted.
        """
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp,
                                        stage_list=("TRANSPORT",),
                                        status="UNSUPPORTED"), self.tmp)
        self.assertEqual(led.status(key, "TRANSPORT"), "UNSUPPORTED")
        self.assertNotEqual(led.status(key, "TRANSPORT"), "STALE")
        self.assertNotIn(("TRANSPORT"), [r.stage for r, _ in led.stale_records()])


class TestThePositiveDirection(unittest.TestCase):
    """A full set of keyed PASSes must actually advance, or the controls
    above would be proved by a ledger that never advances anything."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f7pos-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_all_required_stages_pass_advances(self):
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        decision = ql.j3_decision(led, key)
        self.assertTrue(decision.advance, decision.reasons)
        self.assertEqual(decision.reasons, [])

    def test_transport_and_presentation_are_not_required(self):
        """They are reported, not gating: naming them would be a claim."""
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        self.assertEqual(led.status(key, "TRANSPORT"), "NOT_RUN")
        self.assertEqual(led.status(key, "PRESENTATION"), "NOT_RUN")
        self.assertTrue(ql.j3_decision(led, key).advance)

    def test_the_decision_lists_every_stage_it_read(self):
        key = a_key()
        led = ql.Ledger(passing_records(key, self.tmp), self.tmp)
        decision = ql.j3_decision(led, key)
        self.assertEqual(set(decision.per_stage), set(ql.J3_REQUIRED_STAGES))
        self.assertIn("ADVANCE", "\n".join(decision.lines()))


class TestReadinessUsesTheLedger(unittest.TestCase):
    """`k_readiness.py` must read the ledger, not a literal."""

    @classmethod
    def setUpClass(cls):
        with open(READINESS, encoding="utf-8") as f:
            cls.src = f.read()
        cls.tree = ast.parse(cls.src)

    def code_string_literals(self):
        """String constants in the module, excluding docstrings.

        The module docstring *quotes* the defect it replaces, so a plain
        substring search would flag the explanation as the offence -- the
        same trap as a placeholder check that fires on the rule that created
        it. Excluding docstrings is what makes the check about the code.
        """
        docstrings = set()
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                if (node.body and isinstance(node.body[0], ast.Expr)
                        and isinstance(node.body[0].value, ast.Constant)
                        and isinstance(node.body[0].value.value, str)):
                    docstrings.add(id(node.body[0].value))
        return [n.value for n in ast.walk(self.tree)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and id(n) not in docstrings]

    def test_no_hardcoded_not_built_remains_in_the_code(self):
        offenders = [s for s in self.code_string_literals()
                     if "NOT_BUILT" in s or s.startswith("PARTIAL (H track")]
        self.assertEqual(
            offenders, [],
            "k_readiness.py still decides a track flag from a literal; the "
            f"flags must come from the ledger. Offending strings: {offenders}")

    def test_the_docstring_does_quote_the_defect(self):
        """The check above is only meaningful if the defect is documented."""
        doc = ast.get_docstring(self.tree) or ""
        self.assertIn("NOT_BUILT", doc)

    def test_the_ledger_is_imported_and_read(self):
        self.assertIn("from qualification_ledger import", self.src)
        self.assertIn("Ledger.load", self.src)
        self.assertIn("QUALIFICATION_LEDGER.json", self.src)

    def test_every_track_flag_is_a_ledger_stage_read(self):
        for track in ("F_output_dependency_slice",
                      "G_j3v2_input_expected_harness",
                      "I_final_package",
                      "J_adversarial_release_tests"):
            self.assertIn(f'"{track}": "', self.src, track)
        self.assertIn("TRACK_STAGE", self.src)
        self.assertIn("ledger.status(j3_key, stage)", self.src)

    def test_the_track_mapping_names_only_real_stages(self):
        # Read the table out of the source text rather than off the AST: walk
        # order is not the source order, and pairing two independent walks by
        # position would silently pair the wrong strings.
        import re
        block = re.search(r"TRACK_STAGE = \{(.*?)\n    \}", self.src, re.S)
        self.assertIsNotNone(block, "TRACK_STAGE table not found")
        pairs = re.findall(r'"([^"]+)":\s*"([^"]+)"', block.group(1))
        self.assertEqual(len(pairs), 4, pairs)
        for track, stage in pairs:
            self.assertIn(stage, ql.STAGES,
                          f"{track} maps to unknown stage {stage}")

    def test_the_tool_still_runs_host_only(self):
        """It must not have grown a device call while being rewired."""
        for needle in ("hipInit", "hipMalloc", "amdhip64", "subprocess",
                       "os.system"):
            self.assertNotIn(needle, self.src, needle)


if __name__ == "__main__":
    unittest.main()
