"""Typed results, coverage denominators and observations that can fail.

Nothing here knows about any particular experiment.  Everything is about making
the *shape* of a claim impossible to state dishonestly.
"""

from __future__ import annotations

import hashlib
import os
import subprocess

# --------------------------------------------------------------------------
# The result vocabulary.
#
# Four values, and deliberately no fifth.  The generator this package replaced
# had a fifth in practice -- "PASS" produced by a truthiness test, by a
# non-empty string, or by ``all()`` over an empty collection.  Each of those is
# a way of saying PASS without having measured anything.
# --------------------------------------------------------------------------
PASS = "PASS"
FAIL = "FAIL"
UNKNOWN = "UNKNOWN"
NOT_APPLICABLE_PROVEN = "NOT_APPLICABLE_PROVEN"

ALLOWED_RESULTS = (PASS, FAIL, UNKNOWN, NOT_APPLICABLE_PROVEN)

#: Results that do not block an aggregate.
#:
#: NOT_APPLICABLE_PROVEN is here because it *carries a proof*.  The proof is a
#: mandatory field, and :func:`qualification.gates.gate` refuses to issue the
#: status without one -- so the exemption is earned, not asserted.
NON_BLOCKING = (PASS, NOT_APPLICABLE_PROVEN)


# --------------------------------------------------------------------------
# Real, file-backed identity (Rule L)
# --------------------------------------------------------------------------
def sha256_bytes(b):
    """Digest of a bytes object."""
    return hashlib.sha256(b).hexdigest()


def sha256_file(path, chunk=1 << 20):
    """Digest of a file, re-read from disk.  Raises if it is absent.

    An absent mandatory artefact is the *caller's* problem to classify.  It must
    never silently become a digest, because a digest of nothing has the same
    shape as a digest of something.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def sha256_file_independent(path):
    """A second digest implementation, written differently on purpose.

    It streams a different block size and re-reverses each chunk, so it shares
    no code path with :func:`sha256_file` beyond hashlib itself.  Requiring the
    two to agree is a real cross-check of the read; requiring a function to
    agree with itself is not.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(65536 + 4096)
            if not block:
                break
            h.update(block[::-1][::-1])
    return h.hexdigest()


# --------------------------------------------------------------------------
# Rule K: observations that can fail to observe
# --------------------------------------------------------------------------
class Observation:
    """The result of an enumeration-style measurement.

    ``observed`` is False for every failure mode: a non-zero return code, an
    exception, or a successful command that produced no records.

    The caller MUST map ``observed=False`` to UNKNOWN.  The whole point of this
    type is that "the command failed" and "there was nothing there" are
    different facts, and the first must never be reported as the second.
    """

    __slots__ = ("argv", "observed", "returncode", "records", "stderr",
                 "why_not_observed")

    def __init__(self, argv, observed=False, returncode=None, records=None,
                 stderr="", why_not_observed=None):
        self.argv = list(argv)
        self.observed = observed
        self.returncode = returncode
        self.records = list(records or [])
        self.stderr = stderr
        self.why_not_observed = why_not_observed

    @property
    def n_records(self):
        return len(self.records)

    def as_dict(self):
        return {
            "argv": self.argv,
            "observed": self.observed,
            "returncode": self.returncode,
            "n_records": len(self.records),
            "records": self.records,
            "stderr": self.stderr[:400],
            "why_not_observed": self.why_not_observed,
        }

    def __repr__(self):
        return ("Observation(observed=%r, n_records=%d, why=%r)"
                % (self.observed, len(self.records), self.why_not_observed))


def run_observation(argv, timeout=60):
    """Run a command and say whether it OBSERVED anything.  Never raises."""
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True,
                              timeout=timeout)
    except Exception as exc:                                  # noqa: BLE001
        return Observation(argv, why_not_observed=
                           "the command could not be run: %s" % exc)

    stderr = (proc.stderr or "")
    if proc.returncode != 0:
        return Observation(
            argv, returncode=proc.returncode, stderr=stderr,
            why_not_observed=("non-zero return code %s -- this is an OBSERVATION "
                              "FAILURE, not an empty result" % proc.returncode))

    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if not lines:
        return Observation(
            argv, returncode=proc.returncode, stderr=stderr,
            why_not_observed=("the command succeeded but produced no records; "
                              "absence of output is not evidence of absence of "
                              "the thing"))

    return Observation(argv, observed=True, returncode=proc.returncode,
                       records=lines, stderr=stderr)


# --------------------------------------------------------------------------
# Rule M: coverage that cannot be stated without a denominator
# --------------------------------------------------------------------------
class Coverage:
    """A coverage statement that cannot exist without its denominator.

    Two guards, both earned from a real defect:

    * a zero-total row is **not** a row that passed.  ``analyzed + proven_na ==
      total`` is trivially true when ``total`` is 0, which is the arithmetic
      form of ``all([])``.  A zero-total row must carry a written proof of *why*
      the set is empty, or it is not complete.

    * ``unsupported`` and ``skipped`` are counted, not inferred.  A category
      with silently-dropped members reports complete coverage of a set it
      quietly shrank.
    """

    __slots__ = ("category", "total", "analyzed", "proven_na", "unsupported",
                 "skipped", "checker", "evidence", "basis", "min_basis_chars")

    def __init__(self, category, total, analyzed, proven_na, unsupported,
                 skipped, checker, evidence, basis=None, min_basis_chars=20):
        self.category = category
        self.total = int(total)
        self.analyzed = int(analyzed)
        self.proven_na = int(proven_na)
        self.unsupported = int(unsupported)
        self.skipped = int(skipped)
        self.checker = checker
        self.evidence = evidence
        self.basis = basis
        self.min_basis_chars = min_basis_chars

    @property
    def accounted(self):
        return self.analyzed + self.proven_na

    @property
    def unaccounted(self):
        return self.total - self.accounted

    @property
    def is_vacuous(self):
        return self.total == 0

    @property
    def has_a_proof_of_emptiness(self):
        return bool(self.basis) and len(str(self.basis).strip()) > self.min_basis_chars

    @property
    def complete(self):
        if self.unsupported or self.skipped:
            return False
        if self.is_vacuous:
            return self.has_a_proof_of_emptiness
        return self.accounted == self.total

    @property
    def status(self):
        if not self.complete:
            return "INCOMPLETE"
        return "NOT_APPLICABLE_PROVEN" if self.is_vacuous else "COMPLETE"

    def as_dict(self):
        return {
            "category": self.category,
            "dynamic_count_total": self.total,
            "analyzed": self.analyzed,
            "proven_not_applicable": self.proven_na,
            "unsupported": self.unsupported,
            "skipped": self.skipped,
            "accounted": self.accounted,
            "unaccounted": self.unaccounted,
            "checker": self.checker,
            "evidence": self.evidence,
            "isa_basis": self.basis,
            "vacuously_empty": self.is_vacuous,
            "status": self.status,
        }

    def __repr__(self):
        return ("Coverage(%r, total=%d, accounted=%d, unsupported=%d, skipped=%d,"
                " status=%s)" % (self.category, self.total, self.accounted,
                                 self.unsupported, self.skipped, self.status))


def write_json(path, obj, indent=1):
    """Write JSON, creating parent directories.  Returns the path written."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    import json
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=indent)
    return path
