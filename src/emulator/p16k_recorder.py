#!/usr/bin/env python3
"""Phase 16K-K1 -- explicit recorder modes for per-lane memory accesses.

THE LEAK THIS EXISTS FOR

`RecCore.__init__` (`phase14d11_static/tools/p14d11_emu.py:110`) sets
`self.g_ops = []`, and `RecCore._gl_addr` appends one 4-tuple per global
lane-access.  Nothing drains it.

`RecCore` is not a historical curiosity: it is on the PRODUCTION path.  The
composed core's linearisation, read from `BothCore.__mro__` rather than
inferred, is

    BothCore, ScrtISACore, ScrtGateCore, DescLdsCore, GateCore, E16Core,
    HWCore, WG_SwinCore, SwinCore, RecCore, Core8, Core

and `_gl_addr` is owned by `GateCore` and `RecCore` only, so
`GateCore._gl_addr` -> `super()._gl_addr` -> `RecCore._gl_addr` on every
global access.  Measured: `swin256f` performs 8,370,176 global reads in one
8-wave dispatch, i.e. 8.37 M live 4-tuples.

The three sibling accumulators were already bounded (`AggRecords` covers
`hw_ev`, `hw_memviol`, `ds_ops`); `g_ops` was missed because it is created
in a different module from the one that was audited.

WHAT THIS PROVIDES

Three explicit modes, named, rather than a boolean:

  AGGREGATE       exact counts, min/max address, per-PC counts, per-opcode
                  counts, and a bounded sample (first N in arrival order
                  PLUS the first occurrence of every distinct site, so no
                  site is invisible).  Memory is O(N + sites), independent
                  of the event count.  This is the DEFAULT.
  TARGETED_TRACE  records EVERY event whose site is in an explicitly
                  requested set, and nothing else.  Counts stay exact for
                  all events.  For "what happened at this one PC".
  FULL_TRACE      records everything, under a HARD event budget that
                  raises rather than being quietly exceeded.  The budget
                  and its byte cost are printed BEFORE the run starts; an
                  optional declared `expected_events` adds a real estimate
                  on top of the bound.  For small diagnostics only.

The recorder is list-compatible (`__len__`, `__iter__`, `__getitem__`,
`append`), so a reader written against `for is_store, addr, nb, site in
core.g_ops` keeps working.  Records stay 4-tuples: the opcode is passed
alongside rather than folded in, because unpacking a 5-tuple into four
names would raise in every existing reader.

WHAT AGGREGATE DELIBERATELY DOES NOT KEEP

The addresses of individual in-range events.  `min`/`max` and the counts
are exact; the sample is a sample.  A consumer that needs every address
must ask for TARGETED_TRACE or FULL_TRACE, which is the point: the mode
makes the memory cost of that request explicit instead of silent.

Host-only.  No GPU.
"""
from __future__ import annotations

import sys

AGGREGATE = "AGGREGATE"
TARGETED_TRACE = "TARGETED_TRACE"
FULL_TRACE = "FULL_TRACE"
MODES = (AGGREGATE, TARGETED_TRACE, FULL_TRACE)

# A 4-tuple plus its ints, measured rather than guessed: sys.getsizeof of
# the tuple alone understates it, so the estimate below counts the tuple
# and four boxed ints.
_TUPLE_BYTES = 72
_INT_BYTES = 28
BYTES_PER_EVENT = _TUPLE_BYTES + 4 * _INT_BYTES


# Default hard budget for FULL_TRACE: ~200 MiB of retained records.  A run
# that wants more must say so explicitly, which is the point -- the mode is
# for small diagnostics, and the failure mode being designed out is a
# diagnostic run that quietly becomes a multi-GB one.
FULL_TRACE_MAX_EVENTS_DEFAULT = 2_000_000


class FullTraceBudgetExceeded(RuntimeError):
    """FULL_TRACE would exceed its declared budget.

    Raised rather than truncating: a FULL_TRACE that silently drops events
    is worse than no trace at all, because its whole purpose is to be
    complete for a small run.
    """


def estimate_full_trace_bytes(n_events):
    """Conservative estimate for FULL_TRACE at a declared event count."""
    return n_events * BYTES_PER_EVENT


class RecorderConfig:
    """Run parameters for every recorder built while it is installed.

    A class-level object on `RecCore`, not an argument to `__init__`:
    the cores are constructed inside `run_workgroup_hw`, which does not
    take recorder parameters, and threading one through would touch every
    caller in the tree.
    """

    mode = AGGREGATE
    targets = frozenset()          # sites, for TARGETED_TRACE
    sample_cap = 64
    expected_events = None         # optional, for a printed estimate
    max_events = FULL_TRACE_MAX_EVENTS_DEFAULT

    @classmethod
    def reset(cls):
        cls.mode = AGGREGATE
        cls.targets = frozenset()
        cls.sample_cap = 64
        cls.expected_events = None
        cls.max_events = FULL_TRACE_MAX_EVENTS_DEFAULT

    @classmethod
    def install(cls, mode, targets=None, sample_cap=64,
                expected_events=None, max_events=None, label="g_ops",
                quiet=False):
        """Set the mode, refusing the combinations that cannot be safe."""
        if mode not in MODES:
            raise ValueError("unknown recorder mode %r (want one of %s)"
                             % (mode, ", ".join(MODES)))
        if mode == TARGETED_TRACE and not targets:
            # A targeted trace with no targets records nothing and would
            # read downstream as "nothing happened at any site".  Refuse
            # rather than produce that.
            raise ValueError("TARGETED_TRACE requires a non-empty target "
                             "set; an empty one records nothing")
        cap = FULL_TRACE_MAX_EVENTS_DEFAULT if max_events is None \
            else int(max_events)
        if mode == FULL_TRACE:
            if cap <= 0:
                raise ValueError("FULL_TRACE budget must be positive; an "
                                 "unbounded full trace is what this mode "
                                 "exists to prevent")
            if not quiet:
                sys.stderr.write(
                    "[recorder] FULL_TRACE %s: hard budget %d events "
                    "(~%.1f MiB retained)%s\n"
                    % (label, cap, estimate_full_trace_bytes(cap) / 1048576.0,
                       "" if not expected_events else
                       "; declared expected_events=%d (~%.1f MiB)"
                       % (int(expected_events),
                          estimate_full_trace_bytes(int(expected_events))
                          / 1048576.0)))
                sys.stderr.flush()
        cls.mode = mode
        cls.targets = frozenset(targets or ())
        cls.sample_cap = int(sample_cap)
        cls.expected_events = expected_events
        cls.max_events = cap

    @classmethod
    def as_dict(cls):
        return {"mode": cls.mode, "n_targets": len(cls.targets),
                "sample_cap": cls.sample_cap,
                "expected_events": cls.expected_events,
                "max_events": cls.max_events}


class AccessRecorder:
    """Bounded, list-compatible recorder for one per-lane access stream.

    `rec` is the historical 4-tuple shape.  `opcode` is counted but not
    stored inside the record.
    """

    __slots__ = ("mode", "targets", "sample_cap", "label", "n", "n_read",
                 "n_write", "addr_min", "addr_max", "by_pc", "by_opcode",
                 "_kept", "_seen_sites", "n_events_kept", "n_events_dropped",
                 "est_bytes", "max_events")

    def __init__(self, mode=AGGREGATE, targets=None, sample_cap=64,
                 label="rec", max_events=None):
        self.mode = mode
        self.targets = frozenset(targets or ())
        self.sample_cap = int(sample_cap)
        self.max_events = (FULL_TRACE_MAX_EVENTS_DEFAULT if max_events is None
                           else int(max_events))
        self.label = label
        self.n = 0
        self.n_read = 0
        self.n_write = 0
        self.addr_min = None
        self.addr_max = None
        self.by_pc = {}
        self.by_opcode = {}
        self._kept = []
        self._seen_sites = set()
        self.n_events_kept = 0
        self.n_events_dropped = 0
        self.est_bytes = 0

    # ---- write ---------------------------------------------------------
    def append(self, rec, opcode=None, site=None):
        """Record one event.

        `rec` is `(store, addr, nbytes, site)`.  `site` may be passed
        explicitly when the caller has it more cheaply than by unpacking.
        """
        if self.mode == FULL_TRACE and self.n >= self.max_events:
            raise FullTraceBudgetExceeded(
                "%s: FULL_TRACE budget of %d events exceeded -- this run is "
                "not a small diagnostic; use AGGREGATE or TARGETED_TRACE"
                % (self.label, self.max_events))
        self.n += 1
        store, addr, _nb, rec_site = rec
        if store:
            self.n_write += 1
        else:
            self.n_read += 1
        if addr is not None:
            if self.addr_min is None or addr < self.addr_min:
                self.addr_min = addr
            if self.addr_max is None or addr > self.addr_max:
                self.addr_max = addr
        s = rec_site if site is None else site
        key = "0x%08X" % (s or 0)
        self.by_pc[key] = self.by_pc.get(key, 0) + 1
        if opcode:
            self.by_opcode[opcode] = self.by_opcode.get(opcode, 0) + 1

        if self.mode == FULL_TRACE:
            keep = True
        elif self.mode == TARGETED_TRACE:
            keep = (s in self.targets)
        else:                                   # AGGREGATE
            # Bounded, and every distinct site gets at least one sample:
            # a plain first-N prefix would leave a late site with a count
            # but no example, which reads as "site present, shape unknown".
            keep = (len(self._kept) < self.sample_cap
                    or s not in self._seen_sites)
        if keep:
            self._kept.append(rec)
            self._seen_sites.add(s)
            self.n_events_kept += 1
        else:
            self.n_events_dropped += 1
        return keep

    # ---- list compatibility -------------------------------------------
    def __len__(self):
        return self.n

    def __bool__(self):
        return self.n > 0

    def __iter__(self):
        return iter(self._kept)

    def __getitem__(self, i):
        return self._kept[i]

    def __repr__(self):
        return ("<AccessRecorder %s %s n=%d kept=%d dropped=%d>"
                % (self.label, self.mode, self.n, self.n_events_kept,
                   self.n_events_dropped))

    # ---- read ----------------------------------------------------------
    @property
    def truncated(self):
        return self.n_events_dropped > 0

    def summary(self):
        return {
            "label": self.label,
            "mode": self.mode,
            "n": self.n,
            "n_read": self.n_read,
            "n_write": self.n_write,
            "addr_min": self.addr_min,
            "addr_max": self.addr_max,
            "n_distinct_pcs": len(self.by_pc),
            "n_distinct_opcodes": len(self.by_opcode),
            "by_pc": dict(self.by_pc),
            "by_opcode": dict(self.by_opcode),
            "sample_cap": self.sample_cap,
            "max_events": self.max_events,
            "n_events_kept": self.n_events_kept,
            "n_events_dropped": self.n_events_dropped,
            "truncated": self.truncated,
        }


def force_full(core, max_events=None, label="core"):
    """Swap a directly-constructed core's recorders to FULL_TRACE, in place.

    For the diagnostic tools that build their own core and then iterate
    `core.g_ops` / `core.ds_ops` expecting every event.  Those tools would
    otherwise silently see only the AGGREGATE sample -- a truncated answer
    that looks like a complete one, which is the failure shape this whole
    module exists to remove.  Called at construction, so the swap happens
    before any event is recorded.
    """
    cap = FULL_TRACE_MAX_EVENTS_DEFAULT if max_events is None \
        else int(max_events)
    core.g_ops = AccessRecorder(FULL_TRACE, max_events=cap,
                                label=label + ".g_ops")
    if hasattr(core, "ds_ops"):
        core.ds_ops = AccessRecorder(FULL_TRACE, max_events=cap,
                                     label=label + ".ds_ops")
    return core


def recorder_for(label):
    """Build a recorder from the installed `RecorderConfig`."""
    return AccessRecorder(mode=RecorderConfig.mode,
                          targets=RecorderConfig.targets,
                          sample_cap=RecorderConfig.sample_cap,
                          label=label,
                          max_events=RecorderConfig.max_events)


def install(mode=AGGREGATE, **kw):
    RecorderConfig.install(mode, **kw)


def reset():
    RecorderConfig.reset()


class _Restore:
    """Context manager that installs a mode and restores the previous one.

    Exists so a tool that genuinely needs every record can say so in one
    line without leaving the mode set for whatever runs next in the same
    process -- a leaked FULL_TRACE is exactly the unbounded behaviour this
    module is here to remove.
    """

    def __init__(self, mode, **kw):
        self.mode = mode
        self.kw = kw
        self.prev = None

    def __enter__(self):
        c = RecorderConfig
        self.prev = (c.mode, c.targets, c.sample_cap, c.expected_events,
                     c.max_events)
        c.install(self.mode, **self.kw)
        return self

    def __exit__(self, *exc):
        c = RecorderConfig
        (c.mode, c.targets, c.sample_cap, c.expected_events,
         c.max_events) = self.prev
        return False


def full_trace(label="rec", **kw):
    """`with full_trace(...):` -- every event retained, under a budget."""
    return _Restore(FULL_TRACE, label=label, quiet=True, **kw)


def targeted(sites, label="rec", **kw):
    """`with targeted([...]):` -- every event at those sites, and only those."""
    return _Restore(TARGETED_TRACE, targets=sites, label=label, quiet=True,
                    **kw)


if __name__ == "__main__":
    import json
    print(json.dumps({"modes": list(MODES),
                      "bytes_per_event": BYTES_PER_EVENT,
                      "1M_events_MiB": estimate_full_trace_bytes(1 << 20)
                      / 1048576.0,
                      "8.4M_events_MiB": estimate_full_trace_bytes(8_370_176)
                      / 1048576.0}, indent=1))
