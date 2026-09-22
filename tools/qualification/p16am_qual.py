#!/usr/bin/env python3
"""Phase 16AM -- the single qualification library (brief sections 62 and 63).

WHY THIS FILE EXISTS
--------------------
Astra audit #3 found that this project's per-phase outcome classifiers each
redefined what "completion", "reset", "guard success" and "UNKNOWN" mean, and
that at least one of those definitions was fail-open in three separate ways:
a clean guard report read as a violation, an absent guard report read as clean,
and a failed reset-monitor query read as "no reset occurred".

This module is the one place those meanings are defined.  Phase scripts may
orchestrate; they may not redefine.

THE THREE RULES THIS LIBRARY ENFORCES
-------------------------------------
1. AN UNAVAILABLE OBSERVATION IS NOT A NEGATIVE OBSERVATION.  Every observation
   is either OBSERVED (with a value) or UNKNOWN (with a reason).  There is no
   third, implicit "false".

2. A POSITIVE VERDICT REQUIRES EVERY MANDATORY OBSERVATION TO BE OBSERVED AND
   POSITIVE.  One UNKNOWN mandatory observation is enough to refuse a positive
   verdict.  Nothing is inferred to fill a gap.

3. THE RESULT DIMENSIONS ARE INDEPENDENT.  Dispatch completion, the
   diagnostic's own memory/guard contract, and numerical correctness are
   reported separately and never promote one another.  A prefix diagnostic is
   not numerically wrong for not producing an image it never promised.

Runtime identity: this library never reads an artefact's content to decide what
it is; the caller supplies parsed observations.  The parsers here are given for
the markers the project's own harness prints, and each records the producer
that emits the marker so a parser can be checked against its producer rather
than against a remembered string.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Optional

SCHEMA = "p16am-qualification/1"

# --------------------------------------------------------------------------
# observations
# --------------------------------------------------------------------------
OBSERVED = "OBSERVED"
UNKNOWN = "UNKNOWN"

#: why an observation is UNKNOWN.  These are distinct because the remedies
#: differ: ABSENT means the producer never ran, MALFORMED means it ran and the
#: contract changed, QUERY_FAILED means the instrument broke.
ABSENT = "ABSENT"
MALFORMED = "MALFORMED"
QUERY_FAILED = "QUERY_FAILED"
UNAVAILABLE = "UNAVAILABLE"
TRUNCATED = "TRUNCATED"


@dataclass
class Obs:
    """One typed observation.  `status` is OBSERVED or UNKNOWN -- never None."""
    name: str
    status: str
    value: Any = None
    reason: Optional[str] = None
    source: Optional[str] = None
    source_line: Optional[int] = None
    source_text: Optional[str] = None
    producer: Optional[str] = None
    detail: Any = None

    @property
    def known(self) -> bool:
        return self.status == OBSERVED

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def unknown(name, reason, **kw) -> "Obs":
        assert reason in (ABSENT, MALFORMED, QUERY_FAILED, UNAVAILABLE, TRUNCATED)
        return Obs(name=name, status=UNKNOWN, reason=reason, **kw)

    @staticmethod
    def observed(name, value, **kw) -> "Obs":
        return Obs(name=name, status=OBSERVED, value=value, **kw)


def payload_is_usable(blob: Optional[bytes]) -> Obs:
    """The output artefact, typed.  A missing or short artefact is UNKNOWN.

    An all-zero artefact is NOT "no output": after a confirmed reset it is
    reset aftermath (16AK section 37) and is never read as kernel output.  That
    rule lives here so no phase can reinterpret it.
    """
    if blob is None:
        return Obs.unknown("output_payload", ABSENT)
    if len(blob) == 0:
        return Obs.unknown("output_payload", TRUNCATED, detail={"size": 0})
    return Obs.observed("output_payload", blob, detail={"size": len(blob)})


# --------------------------------------------------------------------------
# parsers, each bound to the producer that emits the marker
# --------------------------------------------------------------------------
GUARD_PRODUCER = "phase16w/j3/harness/j3v2_harness_16w.cpp:772-776"
HASHES_PRODUCER = "phase16w/j3/harness/j3v2_harness_16w.cpp:799"
GUARD_RE = re.compile(
    r"GUARD SUMMARY:\s*(?P<examined>\d+)\s+guard bytes examined across\s+"
    r"(?P<regions>\d+)\s+regions;\s*(?P<modified>\d+)\s+modified;")


def parse_guard_summary(lines: Iterable[str]) -> Obs:
    """The guard contract observation, parsed NUMERICALLY.

    Astra finding A: the production classifier searched for the bare word
    `modified`, so a clean report containing `0 modified` set a violation.  The
    count is parsed here, and the failure to parse is UNKNOWN -- never "clean".

    The harness prints (j3v2_harness_16w.cpp:772):
        GUARD SUMMARY: <n> guard bytes examined across <r> regions;
                       <m> modified; first modified address <addr|NONE>
    so a clean run is `... 0 modified; first modified address NONE`.
    """
    for i, ln in enumerate(lines):
        if "GUARD SUMMARY:" not in ln:
            continue
        m = GUARD_RE.search(ln)
        if not m:
            return Obs.unknown("guard_contract", MALFORMED, source_line=i + 1,
                               source_text=ln.strip(), producer=GUARD_PRODUCER,
                               detail={"expected": "GUARD SUMMARY: <n> guard "
                                       "bytes examined across <r> regions; "
                                       "<m> modified; ..."})
        modified = int(m.group("modified"))
        return Obs.observed(
            "guard_contract", "SATISFIED" if modified == 0 else "VIOLATED",
            source_line=i + 1, source_text=ln.strip(), producer=GUARD_PRODUCER,
            detail={"guard_bytes_examined": int(m.group("examined")),
                    "regions": int(m.group("regions")),
                    "modified": modified})
    return Obs.unknown("guard_contract", ABSENT, producer=GUARD_PRODUCER)


def parse_hashes_equal(lines: Iterable[str]) -> Obs:
    for i, ln in enumerate(lines):
        if "HASHES_EQUAL" not in ln:
            continue
        m = re.search(r"HASHES_EQUAL\s*=\s*(YES|NO)\b", ln)
        if not m:
            return Obs.unknown("numerical_correctness", MALFORMED,
                               source_line=i + 1, source_text=ln.strip(),
                               producer=HASHES_PRODUCER)
        return Obs.observed("numerical_correctness",
                            "MATCH" if m.group(1) == "YES" else "MISMATCH",
                            source_line=i + 1, source_text=ln.strip(),
                            producer=HASHES_PRODUCER)
    return Obs.unknown("numerical_correctness", ABSENT, producer=HASHES_PRODUCER)


def parse_launch_api(lines: Iterable[str]) -> Obs:
    """The single hipModuleLaunchKernel call's return value."""
    for i, ln in enumerate(lines):
        if "launch returned " in ln:
            ok = "hipSuccess" in ln
            return Obs.observed("launch_api", ok, source_line=i + 1,
                                source_text=ln.strip(),
                                producer="the launch harness stdout")
    return Obs.unknown("launch_api", ABSENT)


def parse_synchronization(lines: Iterable[str]) -> Obs:
    for i, ln in enumerate(lines):
        if "hipDeviceSynchronize =" in ln:
            # NOTE, deliberately preserved: a watchdog reset UNBLOCKS
            # hipDeviceSynchronize, so this returning success is not evidence
            # that a kernel completed.  It is recorded as what it is.
            ok = "hipSuccess" in ln
            return Obs.observed("synchronization", ok, source_line=i + 1,
                                source_text=ln.strip(),
                                producer="the launch harness stdout",
                                detail={"success_is_not_completion": True})
    return Obs.unknown("synchronization", ABSENT)


def parse_completion_marker(lines: Iterable[str]) -> Obs:
    for i, ln in enumerate(lines):
        if "PHYSICAL_VERDICT_THIS_PROCESS" in ln:
            return Obs.observed("completion_contract", True, source_line=i + 1,
                                source_text=ln.strip(),
                                producer="the launch harness stdout")
    return Obs.observed("completion_contract", False,
                        producer="the launch harness stdout",
                        detail={"the_marker_is_absent": True})


# --------------------------------------------------------------------------
# reset monitoring, bound to the attempt's identity and interval
# --------------------------------------------------------------------------
EXCLUDED_STALE = "EXCLUDED_STALE"
EXCLUDED_OUTSIDE_INTERVAL = "EXCLUDED_OUTSIDE_INTERVAL"
EXCLUDED_OTHER_ATTEMPT = "EXCLUDED_OTHER_ATTEMPT"


def classify_reset_monitor(before, after, attempt_uuid=None,
                           attempt_start_utc=None, attempt_end_utc=None) -> Obs:
    """Whether a NEW watchdog reset is observed inside THIS attempt.

    `after is None` means the query failed or was unavailable.  Astra finding A:
    the production classifier turned that into `NO_NEW_TDR`; here it is UNKNOWN,
    because an unavailable observation is not evidence that no reset occurred.

    Events are bound to the attempt by record identity, timestamp window and
    attempt identity.  An excluded event is RECORDED as excluded, not dropped.
    """
    if after is None:
        return Obs.unknown("reset_monitor", QUERY_FAILED,
                           detail={"the_query_returned_nothing": True})
    if not isinstance(after, dict) or "wer_kernel" not in after:
        return Obs.unknown("reset_monitor", UNAVAILABLE,
                           detail={"shape": type(after).__name__})

    wk_before = (before or {}).get("wer_kernel") or {}
    base_id = wk_before.get("record_id") or 0
    recs = after.get("wer_kernel") or []
    if not isinstance(recs, list):
        return Obs.unknown("reset_monitor", MALFORMED,
                           detail={"wer_kernel_is_not_a_list": True})

    new, excluded = [], []
    for r in recs:
        rid = r.get("record_id")
        if rid is None:
            excluded.append({"record": r, "why": "NO_RECORD_IDENTITY"})
            continue
        if rid <= base_id:
            excluded.append({"record_id": rid, "why": EXCLUDED_STALE})
            continue
        ts = r.get("utc")
        if attempt_start_utc and attempt_end_utc and ts:
            if not (attempt_start_utc <= ts <= attempt_end_utc):
                excluded.append({"record_id": rid, "why": EXCLUDED_OUTSIDE_INTERVAL,
                                 "utc": ts,
                                 "window": [attempt_start_utc, attempt_end_utc]})
                continue
        if attempt_uuid and r.get("attempt_uuid") and \
                r.get("attempt_uuid") != attempt_uuid:
            excluded.append({"record_id": rid, "why": EXCLUDED_OTHER_ATTEMPT})
            continue
        new.append(r)

    watchdog = [r for r in new if "WATCHDOG" in (r.get("message") or "")]
    return Obs.observed("reset_monitor",
                        "NEW_RESET" if watchdog else "NO_NEW_RESET",
                        detail={"new_record_ids": [r.get("record_id") for r in new],
                                "new_watchdog_record_ids":
                                    [r.get("record_id") for r in watchdog],
                                "excluded": excluded,
                                "compared_by": "record identity, not by count",
                                "bound_to_attempt": {
                                    "attempt_uuid": attempt_uuid,
                                    "window": [attempt_start_utc, attempt_end_utc]}})


# --------------------------------------------------------------------------
# the diagnostic's own contract  (brief section 6)
# --------------------------------------------------------------------------
UNDEFINED = "UNDEFINED_NOT_YET_DERIVED"


@dataclass
class DiagnosticContract:
    """What a diagnostic PROMISES.  A prefix diagnostic does not promise an image.

    Astra finding B: the classifier required equality with the frozen FULL J3
    expected output to declare completion, which a correctly terminated prefix
    need never produce.  The three result dimensions are separated here so the
    requirement can only come from the contract.
    """
    name: str
    numerical_comparison_required: Any          # True / False / UNDEFINED
    expected_write_footprint: Any = UNDEFINED
    expected_untouched_footprint: Any = UNDEFINED
    sentinel_contract: Any = UNDEFINED
    completion_marker: Any = UNDEFINED
    output_artefact_required: bool = True
    notes: str = ""

    def missing_definitions(self) -> list:
        out = []
        for f in ("expected_write_footprint", "expected_untouched_footprint",
                  "sentinel_contract", "completion_marker"):
            if getattr(self, f) == UNDEFINED:
                out.append(f)
        if self.numerical_comparison_required == UNDEFINED:
            out.append("numerical_comparison_required")
        return out


def cut_prefix_contract(name: str) -> DiagnosticContract:
    """The CUT_* prefix diagnostics.

    `numerical_comparison_required = False` is NOT an assumption: the frozen
    record `p16ae/qualification/CUT_MID_RESULT_INTERPRETATION.json` states
    the observation contract in its own words -- "CUT_MID does NOT have 'must
    pass numerically' as its physical outcome.  Its result domain is liveness,
    not correctness."  The remaining contract fields are recorded as UNDEFINED
    rather than invented; see missing_definitions().
    """
    return DiagnosticContract(
        name=name,
        numerical_comparison_required=False,
        output_artefact_required=False,
        notes=("liveness-domain prefix diagnostic; numerical comparison is not "
               "part of its contract (CUT_MID_RESULT_INTERPRETATION.json). "
               "The footprint and sentinel fields are not yet derived -- a "
               "positive liveness verdict does not depend on them, but a "
               "CONTRACT_COMPLETE claim would."))


# --------------------------------------------------------------------------
# the verdict
# --------------------------------------------------------------------------
HARNESS_REFUSED = "HARNESS_REFUSED_AFTER_ATTEMPT_START"
LAUNCH_API_FAILED = "DEVICE_LAUNCH_API_FAILED"
SYNC_FAILED = "DEVICE_SYNCHRONIZATION_FAILED"
OBSERVATION_INCOMPLETE = "OBSERVATION_INCOMPLETE"
PHYSICAL_TDR = "PHYSICAL_TDR"
GUARD_VIOLATED = "GUARD_CONTRACT_VIOLATED"
DISPATCH_NOT_COMPLETED = "DISPATCH_NOT_COMPLETED"
NUMERICAL_MISMATCH = "NUMERICAL_MISMATCH"
PHYSICAL_COMPLETES = "PHYSICAL_COMPLETES"
AMBIGUOUS = "DEVICE_EXECUTION_AMBIGUOUS"

POSITIVE = (PHYSICAL_COMPLETES,)

#: every observation a positive verdict depends on.  The decision table sweeps
#: these one at a time;  each must be able to block a positive verdict alone.
MANDATORY = ("launch_api", "synchronization", "reset_monitor", "guard_contract",
             "completion_contract")


@dataclass
class Verdict:
    primary_outcome: str
    dispatch_completion: str
    diagnostic_contract: str
    numerical_correctness: str
    reset_monitor: str
    observations: dict = field(default_factory=dict)
    why: str = ""
    refused: bool = False
    contract_missing_definitions: list = field(default_factory=list)

    @property
    def is_positive(self) -> bool:
        return self.primary_outcome in POSITIVE

    def to_dict(self) -> dict:
        d = asdict(self)
        d["is_positive"] = self.is_positive
        return d


def classify(obs: dict, contract: DiagnosticContract,
             mutate: Optional[str] = None) -> Verdict:
    """Classify one attempt from typed observations.

    `mutate` injects a DELIBERATELY WRONG rule so the decision table can be
    shown to reject it.  It exists because a checker that cannot fail is not
    evidence, and because Astra's acceptance criterion for the sibling oracle is
    that an incorrect implementation must not pass.
    """
    def k(name):
        o = obs.get(name)
        return o if o is not None else Obs.unknown(name, ABSENT)

    launch, sync = k("launch_api"), k("synchronization")
    reset, guard = k("reset_monitor"), k("guard_contract")
    comp, payload = k("completion_contract"), k("output_payload")
    numeric = k("numerical_correctness")

    if mutate == "UNKNOWN_READS_AS_CLEAN":              # the historical defect
        # This is a faithful model of the 16AK behaviour, not a caricature:
        # an absent guard report produced guard_violation False (i.e. "clean"),
        # a failed WER query produced NO_NEW_TDR (i.e. "no reset"), and the
        # completion marker was collected but never consulted at all -- so an
        # absent marker was equally harmless.  Every missing observation is
        # therefore read here as the clean value it was read as.
        clean_value = {"launch_api": True, "synchronization": True,
                       "reset_monitor": "NO_NEW_RESET",
                       "guard_contract": "SATISFIED",
                       "completion_contract": True,
                       "numerical_correctness": "MATCH"}
        for name in list(obs):
            if obs[name].status == UNKNOWN:
                obs[name] = Obs.observed(name, clean_value.get(name, False),
                                         detail={"MUTATED_missing_reads_clean": True})
        launch, sync = k("launch_api"), k("synchronization")
        reset, guard = k("reset_monitor"), k("guard_contract")
        comp, payload = k("completion_contract"), k("output_payload")
        numeric = k("numerical_correctness")
    if mutate == "GUARD_WORD_MATCH":                    # the 16AK guard defect
        guard = Obs.observed("guard_contract",
                             "VIOLATED" if (guard.source_text or "").find(
                                 "modified") >= 0 else "SATISFIED",
                             source_text=guard.source_text)
    if mutate == "IGNORE_RESET_MONITOR":
        reset = Obs.observed("reset_monitor", "NO_NEW_RESET")

    dispatch = "UNKNOWN"
    diag = "UNKNOWN"
    num = "UNKNOWN" if contract.numerical_comparison_required is not False \
        else "NOT_REQUIRED"

    if reset.known:
        dispatch = "NOT_COMPLETED" if reset.value == "NEW_RESET" else "UNKNOWN"
    if guard.known:
        diag = guard.value

    # ---- the ordered rules ------------------------------------------------
    if obs.get("refused"):
        return Verdict(HARNESS_REFUSED, "NOT_STARTED", "NOT_APPLICABLE",
                       "NOT_APPLICABLE", "NOT_APPLICABLE",
                       _dump(obs), "the harness refused before its HIP section.")

    if launch.known and launch.value is False:
        return Verdict(LAUNCH_API_FAILED, "NOT_STARTED", "NOT_APPLICABLE",
                       "NOT_APPLICABLE",
                       reset.value if reset.known else "UNKNOWN",
                       _dump(obs), "the launch API returned a failure code.")

    missing = [n for n in MANDATORY if not k(n).known]
    if missing:
        return Verdict(
            OBSERVATION_INCOMPLETE, "UNKNOWN", diag, num,
            reset.value if reset.known else "UNKNOWN", _dump(obs),
            "no positive verdict is available: these mandatory observations "
            "are UNKNOWN -- " + ", ".join(
                "%s(%s)" % (n, k(n).reason) for n in missing),
            contract_missing_definitions=contract.missing_definitions())

    if reset.value == "NEW_RESET":
        return Verdict(
            PHYSICAL_TDR, "NOT_COMPLETED", diag, num, reset.value, _dump(obs),
            "a new watchdog reset was observed inside the attempt window; per "
            "16AK section 37 the payload and guards are reset aftermath and are "
            "not kernel output. This says nothing about reachability or causal "
            "origin -- see END_PGM_SEMANTICS_AUDIT.json.",
            contract_missing_definitions=contract.missing_definitions())

    if guard.value == "VIOLATED":
        return Verdict(GUARD_VIOLATED, "UNKNOWN", "VIOLATED", num, reset.value,
                       _dump(obs),
                       "guard bytes changed with no reset observed -- the "
                       "dispatch's memory contract is not satisfied.",
                       contract_missing_definitions=contract.missing_definitions())

    if sync.value is False:
        return Verdict(SYNC_FAILED, "UNKNOWN", diag, num, reset.value, _dump(obs),
                       "hipDeviceSynchronize returned an error.",
                       contract_missing_definitions=contract.missing_definitions())

    if contract.output_artefact_required and not payload.known:
        return Verdict(
            OBSERVATION_INCOMPLETE, "UNKNOWN", diag, num, reset.value, _dump(obs),
            "the diagnostic contract requires an output artefact and it is %s."
            % payload.reason,
            contract_missing_definitions=contract.missing_definitions())

    if comp.known and comp.value is False:
        return Verdict(
            DISPATCH_NOT_COMPLETED, "NOT_COMPLETED", diag, num, reset.value,
            _dump(obs),
            "the completion marker is absent and no reset was observed: the "
            "dispatch did not complete. This is the timeout/early-exit class; "
            "it is NOT a TDR and is NOT evidence about where execution stopped.",
            contract_missing_definitions=contract.missing_definitions())

    # ---- dispatch completion is established; now the numeric dimension ----
    if contract.numerical_comparison_required is True:
        if not numeric.known:
            return Verdict(OBSERVATION_INCOMPLETE, "COMPLETED", diag, num,
                           reset.value, _dump(obs),
                           "the contract requires numerical comparison and it "
                           "is UNKNOWN (%s)." % numeric.reason,
                           contract_missing_definitions=contract.missing_definitions())
        num = numeric.value
        if numeric.value == "MISMATCH":
            return Verdict(NUMERICAL_MISMATCH, "COMPLETED", diag, num,
                           reset.value, _dump(obs),
                           "the dispatch completed with a valid guard contract "
                           "but the output does not match the expected output.",
                           contract_missing_definitions=contract.missing_definitions())
        return Verdict(PHYSICAL_COMPLETES, "COMPLETED", diag, num, reset.value,
                       _dump(obs),
                       "every mandatory observation is present and positive, "
                       "and the required numerical comparison matched.",
                       contract_missing_definitions=contract.missing_definitions())

    if contract.numerical_comparison_required is UNDEFINED:
        return Verdict(
            OBSERVATION_INCOMPLETE, "COMPLETED", diag, "UNKNOWN", reset.value,
            _dump(obs),
            "the diagnostic contract does not define whether numerical "
            "comparison applies, so no completion claim can be made.",
            contract_missing_definitions=contract.missing_definitions())

    # numerical comparison not required (a liveness-domain diagnostic)
    num = "NOT_REQUIRED"
    if numeric.known:
        # recorded when present, but it does not gate the liveness verdict
        num = "NOT_REQUIRED_BUT_OBSERVED_" + str(numeric.value)
    return Verdict(
        PHYSICAL_COMPLETES, "COMPLETED", diag, num, reset.value, _dump(obs),
        "every mandatory observation is present and positive. The diagnostic "
        "contract does not require numerical comparison, so its established "
        "result is liveness: the dispatch completed. This is NOT a statement "
        "that the computation was numerically correct.",
        contract_missing_definitions=contract.missing_definitions())


def _dump(obs):
    return {k: v.to_dict() for k, v in sorted(obs.items())}
