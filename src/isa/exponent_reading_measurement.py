#!/usr/bin/env python3
"""Phase 16S / S2C -- quantify the `exponent()` ambiguity in V_DIV_SCALE_F32.

HOST ONLY.  No GPU, no HIP, no game, nothing armed.  Writes only under
`phase16s/isa/`.  Reads one file: `phase16r/isa/ref/rdna2_isa.txt`.

THE QUESTION
------------
`V_DIV_SCALE_F32`'s branch chain (section 12.12) ends with

    else if (exponent(S2.f) <= 23)
        // Numerator is tiny
        D.f = ldexp(S0.f, 64);
    end if.

and the document never says whether `exponent()` is the **encoded (biased)
exponent field** or the **mathematical (unbiased) exponent**.  The two readings
select different branches on the J3 fixture, so the ambiguity is load-bearing.

THE BRIEF'S INSTRUCTION (S2C, clue A)
-------------------------------------
    "The comment 'Numerator is tiny' combined with F32 exponent <= 23 and F64
     exponent <= 53 looks much more coherent if exponent refers to the encoded
     exponent field.  If it means unbiased exponent: enormous portions of
     ordinary finite input space would satisfy 'tiny.'  Quantify this."

So this tool QUANTIFIES, from the bit patterns, what fraction of the f32 input
space each reading calls "tiny", and what the boundary values actually are.

WHAT THIS TOOL IS NOT
---------------------
It is not a proof of the reading, and it is not a sequence-equivalence test.
It measures one clause's *extent* under each reading and records the numbers.
The independent evidence for the reading is the document's own use of
`exponent(S1.f) == 255` in `V_DIV_FIXUP_F32`, where 255 is the biased field
maximum; that comparison is recorded here by quoting the file, not by
asserting it.

Usage:  python phase16s/isa/exponent_reading_measurement.py
"""
from __future__ import annotations

import json
import math
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.dirname(HERE)                      # phase16s
ROOT = os.path.dirname(S)

ISA_TEXT = os.path.join(ROOT, "phase16r", "isa", "ref", "rdna2_isa.txt")
OUT = os.path.join(HERE, "EXPONENT_READING_MEASUREMENT.json")

F32_MANT_BITS = 23
F32_EXP_BITS = 8
F32_BIAS = 127


# ---------------------------------------------------------------------------
# the two readings, from the bit pattern
# ---------------------------------------------------------------------------
def biased_exponent(bits: int) -> int:
    """The ENCODED exponent field, 0..255.  This is what the bits store."""
    return (bits >> F32_MANT_BITS) & ((1 << F32_EXP_BITS) - 1)


def unbiased_exponent(bits: int) -> int | None:
    """The MATHEMATICAL exponent e such that |x| in [2**e, 2**(e+1)).

    None for zero, subnormals, infinity and NaN -- the function is not defined
    there, which is itself part of why the reading matters.
    """
    e = biased_exponent(bits)
    if e == 0 or e == 255:
        return None
    return e - F32_BIAS


def value_of(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", bits))[0]


# ---------------------------------------------------------------------------
# population counts: how much of the f32 space each reading calls "tiny"?
# ---------------------------------------------------------------------------
def population_counts():
    """Count, over every f32 pattern class, which reading calls S2 'tiny'.

    `exponent(S2.f) <= 23` is evaluated for each of the 2**32 patterns by
    CLASS rather than by enumeration, because the classes are exact.
    """
    n_patterns = 1 << 32
    out = {}

    # -- biased reading: field in [0, 23] ---------------------------------
    # field 0        -> +0/-0 and every subnormal (2 sign * 2**23 magnitudes)
    # fields 1..23   -> normal values 2**(field-127) .. below 2**(24-127)
    n_field0 = 2 * (1 << F32_MANT_BITS)              # both signs, all mantissas
    n_fields_1_23 = 2 * 23 * (1 << F32_MANT_BITS)    # both signs, 23 fields
    biased_tiny = n_field0 + n_fields_1_23
    out["biased"] = {
        "clause": "exponent(S2.f) <= 23 with exponent == the ENCODED field",
        "tiny_patterns": biased_tiny,
        "total_patterns": n_patterns,
        "fraction": biased_tiny / n_patterns,
        "largest_tiny_magnitude": math.ldexp(1.0, 23 - 127),
        "largest_tiny_magnitude_expr": "2**(23-127) = 2**-104",
        "smallest_non_tiny_magnitude": math.ldexp(1.0, 24 - 127),
        "includes_zero": True,
        "includes_subnormals": True,
        "includes_infinities_nans": False,
        "comment_is_coherent":
            "YES -- every value this reading calls 'tiny' is < 2**-103, which "
            "is what 'tiny' means; and the boundary 23 is far BELOW the "
            "smallest normal encoded field (1), so the clause selects exactly "
            "{zero, subnormals, and normals with |x| < 2**-103}.  The "
            "selected magnitude BAND spans 2**-149 to 2**-104 -- about 45 "
            "binades, which is a substantial band precisely because "
            "subnormals live in it.  (The fraction-of-all-patterns figure "
            "below is dominated by the subnormal field and should NOT be read "
            "as 'a vanishing band of magnitudes'.)",
    }

    # -- unbiased reading: mathematical exponent in [-126, 23] ------------
    # normal, both signs, unbiased exponent from -126 to 23 inclusive
    n_unbiased = 2 * (23 - (-126) + 1) * (1 << F32_MANT_BITS)
    out["unbiased"] = {
        "clause": ("exponent(S2.f) <= 23 with exponent == the MATHEMATICAL "
                   "(unbiased) exponent"),
        "tiny_patterns": n_unbiased,
        "total_patterns": n_patterns,
        "fraction": n_unbiased / n_patterns,
        "largest_tiny_magnitude": math.ldexp(1.0, 24) - math.ldexp(1.0, 1),
        "largest_tiny_magnitude_expr": "just under 2**24",
        "smallest_non_tiny_magnitude": math.ldexp(1.0, 24),
        "includes_zero": False,
        "includes_subnormals": False,
        "includes_infinities_nans": False,
        "comment_is_coherent":
            "NO -- this reading calls every finite |x| < 2**24 'tiny'.  2**24 "
            "is 16,777,216 in ordinary units: a colour value, a pixel "
            "coordinate, a texture dimension and an accumulation magnitude "
            "all sit comfortably below it.  A clause documented as 'Numerator "
            "is tiny' cannot be selecting them, and this reading would fire "
            "on the majority of ordinary finite f32 inputs (58.59% of all "
            "patterns, against 9.375% for the biased reading).",
    }
    return out


def document_evidence():
    """Quote the document's own uses of `exponent()`, with line numbers."""
    if not os.path.exists(ISA_TEXT):
        return {"isa_text_present": False}
    text = open(ISA_TEXT, encoding="utf-8", errors="replace").read()
    lines = text.splitlines()
    hits = []
    for i, ln in enumerate(lines, 1):
        if "exponent(" in ln:
            hits.append({"line": i, "text": ln.strip()[:160]})
    return {
        "isa_text_present": True,
        "path": "phase16r/isa/ref/rdna2_isa.txt",
        "n_exponent_uses": len(hits),
        "uses": hits,
        "the_fixup_comparison": {
            "line": next((h["line"] for h in hits if "== 255" in h["text"]),
                         None),
            "text": next((h["text"] for h in hits if "== 255" in h["text"]),
                         None),
            "why_it_matters":
                "255 is the f32 BIASED exponent-field maximum.  The "
                "mathematical exponent of a finite f32 never reaches 255.  "
                "A clause written `exponent(S1.f) == 255` is therefore only "
                "satisfiable if `exponent()` is the encoded field.  The same "
                "chain separately writes `S1.f == DENORM` as a VALUE "
                "predicate, which shows `exponent()` is a numeric function "
                "distinct from the value predicates -- not a synonym for "
                "'is denormal'.",
        },
        "the_double_comparison": {
            "line": next((h["line"] for h in hits if "== 2047" in h["text"]),
                         None),
            "text": next((h["text"] for h in hits if "== 2047" in h["text"]),
                         None),
            "why_it_matters":
                "2047 is the f64 biased exponent-field maximum -- the same "
                "argument at double precision, from a second opcode.",
        },
        "the_trig_counter_example": {
            "line": next((h["line"] for h in hits
                          if "1077" in h["text"] or "1968" in h["text"]),
                         None),
            "text": next((h["text"] for h in hits
                          if "1077" in h["text"] or "1968" in h["text"]),
                         None),
            "why_it_matters":
                "V_TRIG_PREOP_F64 compares `exponent(S0.d) > 1077` and "
                "`>= 1968`, neither of which is the biased f64 maximum "
                "(2047) nor reachable by the mathematical exponent of a "
                "finite f64 (max 1023).  This clause is INTERNALLY "
                "INCONSISTENT with either reading and is recorded as an "
                "unresolved counter-example, not explained away: the "
                "document's `exponent()` is used inconsistently across "
                "sections, which is itself evidence that the manual is a "
                "lossy summary of implementation behaviour.",
        },
    }


def main():
    t0 = time.time()
    doc = {
        "schema": "phase16s-exponent-reading-measurement/1", "phase": "16S",
        "track": "S2C",
        "host_only": True, "gpu_execution_performed": False,
        "currently_armed": False,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "what": ("quantify what fraction of the f32 input space the "
                 "V_DIV_SCALE_F32 `exponent(S2.f) <= 23` clause selects under "
                 "each reading of `exponent()`"),
    }

    print("=== the two readings, quantified over the whole f32 space ===")
    pc = population_counts()
    doc["population"] = pc
    for name in ("biased", "unbiased"):
        r = pc[name]
        print("   %-9s tiny = %14d / %d  (%.6f%%)  largest tiny = %s"
              % (name, r["tiny_patterns"], r["total_patterns"],
                 100.0 * r["fraction"], r["largest_tiny_magnitude_expr"]))
        print("             comment coherent? %s" % r["comment_is_coherent"])

    print("\n=== the f64 clause, for the same reason ===")
    # f64: mantissa 52 bits, exponent field 11 bits, bias 1023.
    n64 = 1 << 64
    biased64 = 2 * ((1 << 52) + 53 * (1 << 52))
    unbiased64 = 2 * (53 - (-1022) + 1) * (1 << 52)
    doc["population_f64"] = {
        "biased": {"tiny_patterns": biased64, "total": n64,
                   "fraction": biased64 / n64,
                   "largest_tiny_magnitude_expr": "2**(53-1023) = 2**-970"},
        "unbiased": {"tiny_patterns": unbiased64, "total": n64,
                     "fraction": unbiased64 / n64,
                     "largest_tiny_magnitude_expr": "just under 2**54"},
    }
    for name in ("biased", "unbiased"):
        r = doc["population_f64"][name]
        print("   %-9s tiny fraction = %.6f%%  largest tiny = %s"
              % (name, 100.0 * r["fraction"], r["largest_tiny_magnitude_expr"]))

    print("\n=== the document's own uses of exponent() ===")
    de = document_evidence()
    doc["document_evidence"] = de
    if de.get("isa_text_present"):
        print("   %d uses found" % de["n_exponent_uses"])
        fc = de["the_fixup_comparison"]
        print("   fixup `== 255` at line %s: %s" % (fc["line"], fc["text"]))
        dc = de["the_double_comparison"]
        print("   f64  `== 2047` at line %s: %s" % (dc["line"], dc["text"]))
        tc = de["the_trig_counter_example"]
        print("   trig counter-example at line %s: %s" % (tc["line"],
                                                           tc["text"]))

    print("\n=== what this does and does not establish ===")
    doc["conclusion"] = {
        "quantified":
            "Under the unbiased reading the clause selects 58.593750% of all "
            "f32 patterns, spanning every finite magnitude below 2**24 "
            "(~1.68e7) -- ordinary rendering and coordinate values, which "
            "cannot be described as 'tiny'.  Under the biased reading the "
            "clause selects 9.375000% of patterns and every one of them is "
            "below 2**-103, which can.  Both counts are exact over the "
            "pattern space (the subnormal exponent field carries the same "
            "2**23 magnitudes as any other field, which is why the biased "
            "count is large in PATTERNS while its magnitude band is narrow).",
        "independent_of_the_manual_prose":
            "The `== 255` / `== 2047` comparisons in V_DIV_FIXUP_F32 / _F64 "
            "are satisfiable only under the biased reading.  That is a "
            "consistency argument INSIDE the same document, not a second "
            "source; it raises the reading's plausibility but does not make "
            "it authoritative.",
        "NOT_established":
            "This tool does NOT establish what D is when no branch of the "
            "chain matches, and it is NOT a sequence-equivalence proof.  The "
            "reading is adjudicated in phase16s/div/SEQUENCE_ORACLE.json by "
            "whether the whole compiler sequence reproduces correctly "
            "rounded IEEE division.",
    }
    for k, v in doc["conclusion"].items():
        print("   %s: %s" % (k, v))

    doc["wall_s"] = round(time.time() - t0, 1)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print("\nwrote %s" % OUT)

    # read it back and check a property that is predictable from the inputs
    back = json.load(open(OUT, encoding="utf-8"))
    assert back["population"]["biased"]["tiny_patterns"] == (
        2 * (1 << 23) + 2 * 23 * (1 << 23)), "biased count round-trip"
    assert back["population"]["unbiased"]["tiny_patterns"] == (
        2 * 150 * (1 << 23)), "unbiased count round-trip"
    # The discrimination is in the MAGNITUDE BAND, not in the fraction of
    # patterns -- the first version of this file asserted on the fraction and
    # was wrong, because the subnormal field contributes 2**23 patterns like
    # any other field.  These checks are the corrected ones.
    assert (back["population"]["biased"]["largest_tiny_magnitude"]
            < 1e-31), "the biased reading must stop far below any normal input"
    assert (back["population"]["unbiased"]["largest_tiny_magnitude"]
            > 1e7), "the unbiased reading must reach ordinary magnitudes"
    assert (back["population"]["biased"]["largest_tiny_magnitude"]
            < back["population"]["unbiased"]["largest_tiny_magnitude"]), \
        "the two readings must be ordered"
    assert back["population"]["biased"]["fraction"] < \
        back["population"]["unbiased"]["fraction"], \
        "the biased reading must select the smaller share of the space"
    print("read-back checks: OK (4)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
