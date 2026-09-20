#!/usr/bin/env python3
"""Phase 16K K15/K16 -- negative controls for the TargetProfile refactor.

A refactor that removes hidden assumptions is only worth anything if the
new explicit assumptions are ENFORCED.  These tests are the proof that the
guards fire, not merely that they exist.

Four controls:

  T1  an architecture string that is not gfx1030 is refused
  T2  relabelling a gfx1030 document as gfx1031/gfx1032 is refused
  T3  the PC-relative adjacency rule is really profile-driven: the SAME
      instruction sequence is accepted under the gfx1100 profile (whose
      filler set contains `s_delay_alu`) and refused under gfx1030 (whose
      does not)
  T4  an unknown profile name is refused rather than defaulted

T3 is the important one.  Before this refactor, `find_sites` tolerated any
two intervening instructions and never said which architecture that
tolerance was for.  Now the tolerance is a named property and a scan that
exceeds it stops.

SCOPE OF T3.  T3's instruction sequences are SYNTHETIC.  Its claim is that
the rule is profile-driven, not that a `s_delay_alu` filler occurs in this
repository -- measured, it does not: all 82 gfx1030 and all 82 gfx1100
sites have an intervening gap of 0, so the tolerance never fires on real
data.  T3 is the negative control for a dead allowance.

Host-only.  Parses text.  No toolchain, no GPU, no kernel launch.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
K15 = os.path.abspath(os.path.join(HERE, ".."))
ROOT = os.path.abspath(os.path.join(K15, "..", ".."))
sys.path.insert(0, K15)
sys.path.insert(0, os.path.join(ROOT, "phase16h_pcrel_fix", "tools"))

import target_profile as TP              # noqa: E402
import p16h_lib as L                     # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    print("  %-58s %s%s" % (name, "PASS" if ok else "FAIL",
                            ("  " + detail) if detail else ""))
    if not ok:
        FAILS.append(name)


def main():
    t = TP.profile_for("gfx1030")
    r = TP.profile_for("gfx1100")

    print("T1  architecture identity is true or it is an error")
    for bad in ("gfx1031", "gfx1032", "gfx1100", "gfx900"):
        try:
            t.assert_identity(bad, "T1")
            check("refuse identity %r" % bad, False, "NOT REFUSED")
        except TP.ArchIdentityError:
            check("refuse identity %r" % bad, True)

    print("\nT2  a gfx1030 document is never relabelled gfx1031/gfx1032")
    clean = ('\t.amdgcn_target "amdgcn-amd-amdhsa--gfx1030"\n'
             "amdhsa.target: amdgcn-amd-amdhsa--gfx1030\n")
    try:
        t.guard_arch_strings(clean, "T2")
        check("accept a truthful gfx1030 document", True)
    except TP.ArchIdentityError as e:
        check("accept a truthful gfx1030 document", False, str(e))
    for bad in ("gfx1031", "gfx1032"):
        doc = clean + "amdhsa.target: amdgcn-amd-amdhsa--%s\n" % bad
        try:
            t.guard_arch_strings(doc, "T2")
            check("refuse a document stamped %s" % bad, False, "NOT REFUSED")
        except TP.ArchIdentityError:
            check("refuse a document stamped %s" % bad, True)
        try:
            TP.refuse_relabel("amdgcn-amd-amdhsa--" + bad, "T2")
            check("refuse_relabel(%s)" % bad, False, "NOT REFUSED")
        except TP.ArchIdentityError:
            check("refuse_relabel(%s)" % bad, True)

    print("\nT3  the PC-relative adjacency rule is profile-driven")
    # A canonical triple with one intervening instruction.  Which mnemonic
    # that is decides whether the profile accepts the site.
    def triple(filler):
        ins = [(0x1000, "s_getpc_b64 s[4:5]", ""), ]
        if filler:
            ins.append((0x1004, filler, ""))
        ins += [(0x1008, "s_add_u32 s4, s4, 0x40", ""),
                (0x100C, "s_addc_u32 s5, s5, 0x0", "")]
        return ins

    gfx10_filler = triple("s_nop")
    gfx11_filler = triple("s_delay_alu")

    n = len(L.find_sites(gfx10_filler, profile=t))
    check("gfx1030 accepts an s_nop filler (1 site)", n == 1, "got %d" % n)

    try:
        n = len(L.find_sites(gfx10_filler, profile=r))
        check("gfx1100 accepts an s_nop filler", n == 1, "got %d" % n)
    except L.ProfileAdjacencyError as e:
        check("gfx1100 accepts an s_nop filler", False, str(e)[:40])

    n = len(L.find_sites(gfx11_filler, profile=r))
    check("gfx1100 accepts an s_delay_alu filler (1 site)", n == 1,
          "got %d" % n)

    try:
        n = len(L.find_sites(gfx11_filler, profile=t))
        check("gfx1030 REFUSES an s_delay_alu filler", False,
              "NOT REFUSED (found %d site)" % n)
    except L.ProfileAdjacencyError:
        check("gfx1030 REFUSES an s_delay_alu filler", True)

    # A mnemonic neither profile authorises must be refused by both.
    for prof in (t, r):
        try:
            L.find_sites(triple("v_mul_f32_e32 v1, v2, v3"), profile=prof)
            check("%s refuses an unauthorised filler" % prof.name, False,
                  "NOT REFUSED")
        except L.ProfileAdjacencyError:
            check("%s refuses an unauthorised filler" % prof.name, True)

    # The legacy compatibility path (profile=None) is unchanged.
    n = len(L.find_sites(gfx11_filler))
    check("legacy profile=None path is unchanged (1 site)", n == 1,
          "got %d" % n)

    print("\nT4  an unknown profile is refused, not defaulted")
    try:
        TP.profile_for("gfx9999")
        check("refuse profile_for('gfx9999')", False, "NOT REFUSED")
    except TP.UnknownProfile:
        check("refuse profile_for('gfx9999')", True)
    try:
        t.instruction_available("v_totally_made_up")
        check("refuse an unmeasured instruction class", False,
              "NOT REFUSED")
    except TP.ProfileError:
        check("refuse an unmeasured instruction class", True)

    print("\n" + ("ALL CONTROLS PASSED" if not FAILS
                  else "FAILURES: %s" % ", ".join(FAILS)))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    raise SystemExit(main())
