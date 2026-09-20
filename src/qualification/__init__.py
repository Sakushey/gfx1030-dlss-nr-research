"""Fail-closed qualification primitives.

Extracted from a GPU binary-translation research project where a readiness
generator was found to be promoting *missing and explicitly failing* evidence
into a green result. Three ideas came out of that, and they are the reason this
package exists:

RULE K -- an observation that FAILED is not a negative observation.  A command
    that could not enumerate a system state did not prove that state was empty.

RULE L -- a summary is not evidence.  A stored digest is provenance; the raw
    artefact is evidence.  Where a predicate can be recomputed, it is.

RULE M -- coverage is a first-class output.  No verdict may be reported without
    its denominator, its unsupported count and its skipped count.

The result vocabulary is deliberately tiny -- PASS, FAIL, UNKNOWN,
NOT_APPLICABLE_PROVEN -- and there is no PASS_BY_DEFAULT, no truthiness test on
a string, no "non-empty hash" check and no vacuous ``all([])``.

See ``docs/fail-closed-qualification.md`` for the methodology, and
``qualification.mutation`` for the harness that proves a gate can actually fail.
"""

from __future__ import annotations

from .evidence import (                                          # noqa: F401
    ALLOWED_RESULTS,
    FAIL,
    NOT_APPLICABLE_PROVEN,
    NON_BLOCKING,
    PASS,
    UNKNOWN,
    Coverage,
    Observation,
    sha256_file,
    sha256_file_independent,
    sha256_bytes,
)
from .gates import (                                             # noqa: F401
    Evidence,
    aggregate,
    gate,
)

__all__ = [
    "ALLOWED_RESULTS", "FAIL", "NOT_APPLICABLE_PROVEN", "NON_BLOCKING",
    "PASS", "UNKNOWN", "Coverage", "Observation", "Evidence", "gate",
    "aggregate", "sha256_file", "sha256_file_independent", "sha256_bytes",
]
