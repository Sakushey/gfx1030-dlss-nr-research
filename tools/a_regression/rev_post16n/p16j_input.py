#!/usr/bin/env python3
"""Phase 16J-J2 -- the deterministic nontrivial input, and its lazy memory.

WHY THIS EXISTS

J2 must run the authentic `<32,false>` dispatch on a *nontrivial* input,
because the kernel's control flow is data-dependent: an all-zero fill would
exercise a path the game never takes.  But the authentic tensor regions are
declared at 64 MiB each, and materialising six of those as Python dict
entries is ~335 million objects -- the emulator would die of the input
before it reached the kernel.

So the input is supplied as a *function of the offset* rather than as a
materialised buffer.  `PatternMem` is a dict that answers reads inside a
declared region by computing the pattern byte on demand, and falls back to
real entries wherever the kernel has written.  Memory stays proportional to
what the kernel actually touches.

The pattern is `pattern_at` from the J3 harness, reproduced here bit for
bit -- the same C uint32 wraparound, the same two LCG steps, the same
`x ^= x >> 13`, the same never-zero rule.  If the two ever disagree, a
physical result and its host reference would be compared across different
inputs, so `p16j_input_parity` checks them against each other.

Host-only.  No GPU.
"""
from __future__ import annotations

import hashlib
import os
import sys

MASK32 = 0xFFFFFFFF


def pattern_at(i):
    """The J3 harness's `pattern_at`, reproduced exactly.

    C:  uint32_t x = (uint32_t)i;
        x = x * 1664525u + 1013904223u;
        x ^= x >> 13;
        x = x * 1664525u + 1013904223u;
        uint8_t b = (uint8_t)(x >> 16);
        return b ? b : 1;
    """
    x = (i & MASK32)
    x = (x * 1664525 + 1013904223) & MASK32
    x ^= x >> 13
    x = (x * 1664525 + 1013904223) & MASK32
    b = (x >> 16) & 0xFF
    return b if b else 1


def pattern_b(i):
    """A second, independent legal nontrivial pattern.

    A different generator with a different structure (a multiply-shift hash
    rather than an LCG), so a result that survives both is not an artefact
    of one generator's correlations.  Also never zero.
    """
    x = ((i & MASK32) * 2654435761 + 0x9E3779B9) & MASK32
    x ^= (x >> 15)
    x = (x * 2246822519) & MASK32
    x ^= (x >> 13)
    b = (x >> 11) & 0xFF
    return b if b else 1


GENERATORS = {"A": pattern_at, "B": pattern_b}


class PatternMem(dict):
    """A dict whose absent reads inside a declared region are synthesised.

    Writes go to the real dict and therefore shadow the pattern, which is
    what a store should do.  Iteration and `len` see only the real entries,
    so the emulator's state signatures stay bounded.
    """

    def __init__(self, base, regions, gen=pattern_at):
        super().__init__(base)
        self.regions = list(regions)     # [(lo, hi, name)]
        self.gen = gen
        self.n_synth = 0

    def _base_of(self, addr):
        for lo, hi, _name in self.regions:
            if lo <= addr < hi:
                return lo
        return None

    def __contains__(self, addr):
        if dict.__contains__(self, addr):
            return True
        return self._base_of(addr) is not None

    def __getitem__(self, addr):
        if dict.__contains__(self, addr):
            return dict.__getitem__(self, addr)
        b = self._base_of(addr)
        if b is None:
            raise KeyError(addr)
        self.n_synth += 1
        return self.gen(addr - b)

    def get(self, addr, default=0):
        # `dict.get` does not consult `__missing__`, so the synthesis has to
        # be wired into `get` explicitly -- `_read_bytes` uses `.get`.
        if dict.__contains__(self, addr):
            return dict.__getitem__(self, addr)
        b = self._base_of(addr)
        if b is None:
            return default
        self.n_synth += 1
        return self.gen(addr - b)


# The `VarParams` fields that hold ADDRESSES.  Mirrors
# `p16i_authentic_harness.POINTER_OFFSETS`; `p16o_region_consistency.py`
# asserts the two agree, so the pair cannot drift apart silently.
POINTER_FIELD_OFFSETS = (0x00, 0x08, 0x10, 0x30, 0x38, 0xA0)


def regions_for(vals, canvas_size, tensor_size, extra=(),
                offsets=POINTER_FIELD_OFFSETS):
    """(lo, hi, name) for every authentic POINTER field, plus any extras.

    PHASE 16O DEFECT, REPAIRED HERE.  Until Phase 16O this looped over
    EVERY non-empty entry of `vals` and used the entry's VALUE as a region
    base.  `vals` also carries the scalar kernarg fields, so the harness
    declared 64 MiB of pattern-backed memory at address 1 (the `flags`
    value), at 0x240 (X) and at 0x3C0 (Y).  Those regions cover the whole
    low address space -- including the kernarg segment itself, at 0x10000.

    `PatternMem.__contains__` answers True for any address inside a declared
    region, so a byte-addressed reader could not tell a synthesised pattern
    byte from a real one.  That is what turned the Phase 16N `s_load` repair
    -- which is correct per the ISA -- into 15,104 out-of-bounds global reads
    and 4,352 out-of-bounds global writes on `swin<32,false>`: the kernel's
    scalar base pointers were assembled from pattern noise.

    The docstring always said "pointer field"; the code did not.  It does
    now.  `p16i_authentic_harness.run` had already been corrected the same
    way for the GATE's region declarations; this is the DATA side of the
    same rule.
    """
    # PRE-16O reconstruction: EVERY non-empty entry of `vals`, using the
    # entry's VALUE as a region base.  `vals` also carries the scalar kernarg
    # fields, so this declared 64 MiB of pattern-backed memory at address 1,
    # at 0x240 (X) and at 0x3C0 (Y) -- covering the kernarg segment at
    # 0x10000, which is the region Phase 16O measured.
    out = []
    for off, val in sorted(vals.items()):
        if not val:
            continue
        size = canvas_size if off == 0xA0 else tensor_size
        out.append((val, val + size, "authentic_0x%02X" % off))
    out.extend(extra)
    return out


def make_fill(vals, canvas_size, tensor_size, gen_name="A", extra=()):
    """A `fill_payload` hook for `run_workgroup_hw`.

    Returns a function taking the emulator's memory dict and returning the
    pattern-backed mapping, so the caller's region declarations and the
    filled data cannot drift apart.
    """
    gen = GENERATORS[gen_name]
    regions = regions_for(vals, canvas_size, tensor_size, extra)

    def fill(mem):
        return PatternMem(mem, regions, gen=gen)
    return fill


def canvas_bytes(mem, base, size):
    """Read back a region through the mapping (real writes shadow pattern)."""
    return bytes(mem[k] & 0xFF if k in mem else 0 for k in range(base, base + size))


def output_digest(mem, base, size, sample=4096):
    """A digest over the bytes the kernel actually WROTE into a region.

    Only real entries are hashed -- synthesised pattern bytes are input, not
    output, and including them would make the digest a function of the
    pattern rather than of the kernel.  The offsets are included so two
    different byte sets cannot collide.

    `sha256` samples at most `sample` written bytes, which is exact while
    `n_written <= sample` (true for every run in this phase: the largest is
    1248) but becomes lossy above it -- two different byte sets sharing an
    offset skeleton could then collide, and a J3 comparison against it would
    look healthy while comparing nothing.  `sha256_full` covers every
    written byte and is the value a physical result should be checked
    against.
    """
    written = sorted(k for k in dict.keys(mem)
                     if base <= k < base + size)
    h = hashlib.sha256()
    h.update(b"n_written=%d\n" % len(written))
    step = max(1, len(written) // sample)
    for k in written[::step]:
        h.update(b"%08x%02x" % (k - base, mem[k] & 0xFF))
    full = hashlib.sha256()
    full.update(b"n_written=%d\n" % len(written))
    for k in written:
        full.update(b"%08x%02x" % (k - base, mem[k] & 0xFF))
    return {"n_written": len(written),
            "offsets_min": (written[0] - base) if written else None,
            "offsets_max": (written[-1] - base) if written else None,
            "sha256": h.hexdigest(),
            "sha256_full": full.hexdigest(),
            "sha256_is_full_fidelity": step == 1}
