#!/usr/bin/env python3
"""Phase 16T -- build ISA_ORACLE_16T: the Phase 16S vector set with the two
ill-posed vector families corrected, in the SAME artifact shape.

WHY THIS IS A CORRECTION AND NOT A CONVENIENCE
----------------------------------------------
`phase16s/isa/build_oracle_vectors.py:1341` (`_fma_vecs`) builds every MIX
vector as

    V(mnem, name, "v1", ["v1", "v2", "v3"],
      {"v1": LANES(a), "v2": LANES(b), "v3": LANES(c), "v0": LANES(dst)}, ...)

The destination token is `v1`, the register holding source S0; the value the
expectation treats as the "pre-set destination" (0xAAAA5555) is seeded into
`v0`, which the instruction never reads.  Measured through `Harness.probe`,
the destination's old value is therefore `a`, not 0xAAAA5555, so the
expectation `dst16_*(0xAAAA5555, r, "preserve")` is not the correctly rounded
value for the state the vector sets up.  That is a defect of the TEST.

This tool recomputes those vectors' `expect.value` and their recorded
alternate readings from the state the vector ACTUALLY sets up, using
`phase16s/isa/oracle16.py` -- the same independent module, which imports
nothing -- and records every changed field.  It changes NOTHING else: no
setup dict, no operand string, no source value, no other vector.

The 16S measurements (`measured`, `diffs`, `matches_alternate_reading`) are
REMOVED, not carried: they are the live tree's observations and would be a
fabricated measurement if they travelled with a different revision's run.

This does NOT make the pre-revision implementation look better.  That body
reads each source's FULL 32 bits as an f32, so for the J3-shape vector it
computes f32(0x3C00) * f32(0x4000) + 0, which underflows to zero, and writes
0x00000000 over the whole destination where the ISA value is 0x40003C00.  Both
readings of the expectation reject it.

Usage:
    python phase16t/isa/build_isa_oracle_16t.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.dirname(HERE)
ROOT = os.path.dirname(T)
sys.path.insert(0, os.path.join(ROOT, "phase16s", "isa"))

SRC = os.path.join(ROOT, "phase16s", "isa", "ISA_ORACLE_16.json")
OUT = os.path.join(HERE, "ISA_ORACLE_16T.json")
MIX = ("v_fma_mixlo_f16", "v_fma_mixhi_f16")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    import oracle16 as O

    with open(SRC, encoding="utf-8") as f:
        doc = json.load(f)

    corrections = []
    for v in doc["vectors"]:
        # every vector, whatever its mnemonic, loses the 16S measurements
        for k in ("measured", "diffs", "matches_alternate_reading"):
            v.pop(k, None)
        if v["mnem"] not in MIX:
            continue
        hi = v["mnem"] == "v_fma_mixhi_f16"
        fold = O.dst16_hi if hi else O.dst16_lo
        dst = v["dst"]
        s = v["setup"].get(dst)
        if s is None:
            corrections.append({"name": v["name"], "mnem": v["mnem"],
                                "status": "DESTINATION_NOT_SEEDED"})
            continue
        dst_old = (s[0] if isinstance(s, list) else s) & 0xFFFFFFFF
        ops = v["ops"]
        a = v["setup"][ops[1]]
        b = v["setup"][ops[2]]
        c = v["setup"][ops[3]]
        a = (a[0] if isinstance(a, list) else a) & 0xFFFF
        b = (b[0] if isinstance(b, list) else b) & 0xFFFF
        c = (c[0] if isinstance(c, list) else c) & 0xFFFF
        r = O.f16_fma(a, b, c)
        dr = O.fma_double_rounding(a, b, c)
        old_value = v["expect"]["value"]
        old_alt = dict(v.get("alt") or {})
        v["expect"]["value"] = fold(dst_old, r, "preserve")
        v["alt"] = {
            "other_half_zeroed": fold(dst_old, r, "zero"),
            "double_rounding_mul_then_add": fold(dst_old, dr, "preserve"),
        }
        v["open_reading_flag"] = v.get("open_reading_flag")
        v["note"] = (v.get("note") or "") + (
            "  [16T CORRECTION] the expectation is computed from the state "
            "this vector actually sets up: %s holds 0x%08X, not the "
            "0xAAAA5555 the vector seeds into the unused v0."
            % (dst, dst_old))
        corrections.append({
            "name": v["name"], "mnem": v["mnem"], "dst": dst,
            "destination_register_old_value": dst_old,
            "sixteen_s_expectation": old_value,
            "sixteen_t_expectation": v["expect"]["value"],
            "expect_value_changed": old_value != v["expect"]["value"],
            "sixteen_s_alt": old_alt,
            "sixteen_t_alt": dict(v["alt"]),
            "sources": {"a": a, "b": b, "c": c},
        })

    out = dict(doc)
    out["schema"] = "phase16t-isa-oracle/1"
    out["phase"] = "16T"
    out["supersedes"] = {
        "artifact": "phase16s/isa/ISA_ORACLE_16.json",
        "sha256": sha256_file(SRC),
        "what_changed": ("the two MIX vector families' expectations are "
                         "recomputed from the state each vector sets up; the "
                         "16S measurements were removed; nothing else"),
    }
    out["independence"] = dict(doc.get("independence") or {})
    out["independence"]["recomputed_by"] = (
        "phase16t/isa/build_isa_oracle_16t.py, using phase16s/isa/oracle16.py "
        "unchanged (sha256 %s)" % sha256_file(
            os.path.join(ROOT, "phase16s", "isa", "oracle16.py")))
    out["corrections"] = corrections
    out["n_corrections"] = len(corrections)
    out["n_correction_value_changes"] = sum(
        1 for c in corrections if c.get("expect_value_changed"))

    os.makedirs(HERE, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print("vectors            : %d (unchanged count)" % len(out["vectors"]))
    print("corrections        : %d over %d MIX vectors; %d expectations moved"
          % (len(corrections), sum(1 for v in out["vectors"] if v["mnem"] in MIX),
             out["n_correction_value_changes"]))
    print("wrote %s" % OUT)
    print("sha256 %s" % sha256_file(OUT))
    if len(corrections) != 32:
        print("WARNING: expected 32 MIX vectors, corrected %d" % len(corrections))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
