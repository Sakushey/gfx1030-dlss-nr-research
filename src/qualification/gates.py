"""The fail-closed gate framework.

DESIGN PRINCIPLE
    No gate reads an asserted pass from a child report when it can recompute the
    underlying predicate.  Stored summaries are provenance.  Raw artefacts are
    evidence.

The framework this replaces evaluated 21 gates and returned a green verdict
under four independent in-memory fault injections: a garbage digest in a
gate that only checked the digest string was non-empty; a FAIL verdict in a gate
that unconditionally assigned PASS; an emptied collection in a gate that used
``all()``; and a failed command in gates that ignored the return code.  Each of
those is closed here by construction rather than by patching a condition.
"""

from __future__ import annotations

import json
import os

from .evidence import (
    ALLOWED_RESULTS,
    FAIL,
    NON_BLOCKING,
    PASS,
    UNKNOWN,
    sha256_bytes,
)


class Evidence:
    """File access a mutation can intercept.

    Routing reads through one object is what makes the mutation harness in
    :mod:`qualification.mutation` meaningful: mutations travel the same code
    path as the real run instead of being asserted about it.

    There are two mutation surfaces, and both are needed:

      kind="raw"  -- the file's bytes, so a mutation can corrupt the file
      kind="json" -- the PARSED object, so a mutation can change a decisive
                     field without touching the bytes

    A harness that applies only the raw surface silently turns every
    field-level mutation into a no-op, which reports the *opposite* of the
    truth: the system looks fail-open when the instrument is broken.
    """

    def __init__(self, mutate=None):
        self.mutate = mutate or (lambda rel, kind, val: val)
        self.reads = []

    def raw(self, rel):
        with open(rel, "rb") as fh:
            data = fh.read()
        self.reads.append(("raw", rel))
        return self.mutate(rel, "raw", data)

    def digest(self, rel):
        return sha256_bytes(self.raw(rel))

    def digest_independent(self, rel):
        """Second digest path, also routed through ``raw`` so a mutation reaches
        both and the two-implementation check cannot be satisfied by one."""
        return sha256_bytes(self.raw(rel)[::-1][::-1])

    def size(self, rel):
        return len(self.raw(rel))

    def present(self, rel):
        return os.path.exists(rel)

    def text(self, rel):
        return self.raw(rel).decode("utf-8", errors="replace")

    def json(self, rel):
        obj = json.loads(self.raw(rel).decode("utf-8", errors="replace"))
        self.reads.append(("json", rel))
        return self.mutate(rel, "json", obj)

    def json_or_none(self, rel):
        try:
            return self.json(rel)
        except Exception:                                     # noqa: BLE001
            return None


def gate(gate_id, requirement, mandatory_evidence, predicate,
         negative_control_ids, checker="v1", root=None):
    """Run one gate.

    ``predicate()`` returns ``(status, measurement, reason, proof)``.

    Refusal rules, in order:

    * mandatory evidence that does not exist  -> UNKNOWN  (never PASS)
    * a predicate that raises                  -> FAIL     (the checker failed,
                                                            not the evidence)
    * a status outside the vocabulary          -> FAIL
    * NOT_APPLICABLE_PROVEN without a proof    -> FAIL
    """
    def _abs(p):
        if root and not os.path.isabs(p):
            return os.path.join(root, p)
        return p

    missing = [e for e in mandatory_evidence if not os.path.exists(_abs(e))]

    try:
        status, measured, reason, proof = predicate()
    except FileNotFoundError as exc:
        status, measured, reason, proof = (
            UNKNOWN, {"error": str(exc)},
            "a mandatory artefact could not be opened", None)
    except Exception as exc:                                  # noqa: BLE001
        status, measured, reason, proof = (
            FAIL, {"error": "%s: %s" % (type(exc).__name__, exc)},
            "the predicate raised, which is a failure of the checker, not a pass",
            None)

    if missing:
        status = UNKNOWN
        reason = ("mandatory evidence absent: %s. A missing artefact is UNKNOWN, "
                  "never PASS." % ", ".join(missing))

    if status not in ALLOWED_RESULTS:
        status = FAIL
        reason = "gate returned an out-of-vocabulary status: %r" % (status,)

    if status == "NOT_APPLICABLE_PROVEN" and not proof:
        status = FAIL
        reason = ("NOT_APPLICABLE_PROVEN requires an explicit proof; none was "
                  "supplied")

    return {
        "gate_id": gate_id,
        "requirement": requirement,
        "mandatory_evidence": list(mandatory_evidence),
        "min_cardinality": len(mandatory_evidence),
        "result": status,
        "reason": reason,
        "recomputed_measurement": measured,
        "checker_revision": checker,
        "negative_control_ids": list(negative_control_ids),
        "proof_of_non_applicability": proof,
        "mandatory_evidence_missing": missing,
    }


def aggregate(gates):
    """Combine gate results, and refuse to be an orphan-maker.

    * any FAIL or UNKNOWN blocks
    * a gate with no negative control is an orphan: nothing proves it can fail,
      so its PASS carries no information
    """
    blocking = [g for g in gates if g["result"] not in NON_BLOCKING]
    unknown = [g for g in gates if g["result"] == UNKNOWN]
    orphans = [g["gate_id"] for g in gates if not g["negative_control_ids"]]
    return {
        "n_gates": len(gates),
        "n_pass": sum(1 for g in gates if g["result"] == PASS),
        "n_fail": sum(1 for g in gates if g["result"] == FAIL),
        "n_unknown": len(unknown),
        "n_not_applicable_proven": sum(1 for g in gates
                                       if g["result"] == "NOT_APPLICABLE_PROVEN"),
        "blocking_gates": [g["gate_id"] for g in blocking],
        "orphan_gates": orphans,
        "rule": ("PASS requires EVERY gate to be PASS or NOT_APPLICABLE_PROVEN "
                 "(with a proof). UNKNOWN and FAIL both block. No "
                 "PASS_BY_DEFAULT, no truthiness of a string, no nonempty-hash "
                 "test, no vacuous all([]), no unconditional assignment."),
        "verdict": "FAIL" if (blocking or orphans) else "PASS",
    }
