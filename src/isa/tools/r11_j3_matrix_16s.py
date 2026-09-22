#!/usr/bin/env python3
# ===========================================================================
# PHASE 16S COPY of phase16r/isa/tools/r11_j3_matrix.py.
#
# Byte-for-byte the 16R tool except for:
#   * OUT_REL / LOG_REL point at phase16s/isa, so this copy writes nothing
#     into phase16r/isa (which is 16R evidence and is not touched);
#   * one additive extension of the comparator (`_obs_diffs`) that only
#     acts when the oracle side declares an `extra` read-back;
#   * one optional argument to `measured_mutation` (the shapes to try),
#     defaulting to the 16R tuple;
#   * section 10 (added): the S1 independent ISA oracle suite, the additive
#     harness widening it needs, and the shapes its mutation control uses;
#   * the evidence join and the per-mnemonic mutation loop consume the S1
#     suite when a mnemonic has no other oracle;
#   * the artifact schema/phase fields, and the rule that a row resting on
#     the S1 suite is demoted to BLOCKED when it carries no detecting
#     mutation.
#
# Every other line is the 16R text, so the 16L / M2 / Q1 measurements this
# tool performs are the same measurements.
# ===========================================================================
"""Phase 16R / R11 -- the instruction-level J3 conformance matrix.

HOST ONLY.  No GPU, no HIP, no game, nothing armed.  This tool starts no
process other than the two phase-16L oracle verifiers, and writes only under
`phase16r/isa/`.

WHAT THIS ANSWERS
-----------------
`phase16q/j3_v2/J3_DEPENDENCY_STATUS_FINAL.json` reports
`OUTPUT_DEPENDENCY_UNVERIFIED = 0`, but that count is computed over FAMILIES.
A family status of VERIFIED_INDEPENDENTLY says one thing only: *some* oracle
vector of that family agreed with the emulator.  It does not say that every
mnemonic the J3 output cone actually depends on was ever observed.

This tool closes that hole at MNEMONIC level.  For every mnemonic on the J3
output-cone record (`phase16p/j3_v2/J3_OUTPUT_DEPENDENCY.json`) it records the
cone counts and the handler, joins every independent oracle suite in the tree
to the mnemonic, and assigns exactly one of the four permitted statuses:

    VERIFIED_INDEPENDENTLY         an independent oracle observed THIS mnemonic
    VERIFIED_BY_EXACT_EQUIVALENCE  no vector of its own, measured equivalent
    NOT_OUTPUT_RELEVANT            zero nodes in the J3 output cone
    BLOCKED                        none of the above

`VERIFIED_BY_PROVEN_FAMILY` is NOT used, for any instruction.

THE ORACLE SUITES JOINED (each re-run or replayed here, command recorded)
-----------------------------------------------------------------------
  1. the J3 conformance suite, 169 vectors / 24,417 comparisons
     `phase16q/j3_v2/J3_CONFORMANCE_FINAL.json`.  It CONTAINS the 117-vector M2
     suite; that containment is MEASURED here by set difference, not asserted.
  2. the 16L vector ISA oracle, 97 vectors   -- RE-RUN by this tool
  3. the 16L scalar ISA oracle, 69 vectors   -- RE-RUN by this tool
  4. the R9 division-sequence reference       -- cited where it applies

WHY THE 16L SUITES ARE RE-RUN RATHER THAN QUOTED
------------------------------------------------
Their recorded results were read back through a harness that CANNOT READ A
64-BIT SCALAR REGISTER PAIR: it reads `core.s[int(dst[1:])]` only when the
destination token is `s<digits>`, so for the destination `s[3:4]` it returns
None and the diff prints the emulator side as `0x00000000`.  One of the seven
recorded 16L scalar "disagreements" (`s_lshl_b64`) is therefore a HARNESS
read-back artifact, not a measured semantic defect.  This tool re-measures the
same vectors through the composed core with a pair-aware read-back and reports
exactly which observations the correction changes (negative control NC3), then
uses the corrected observation for the status.

THE MUTATION COLUMNS
--------------------
`detecting_mutation`, `mutation_effect_observed` and `mutation_rejected` are
per MNEMONIC and measured, never assumed:

  * a mnemonic with vectors in the J3/M2 suite inherits that suite's recorded
    mutation measurement, attributed to it when at least one vector the
    mutation CHANGED is a vector of that mnemonic;
  * a mnemonic whose only coverage is a 16L oracle vector gets a mutation
    measured here: the MRO-RESOLVED handler of that mnemonic -- the class the
    instantiated `BothCore` resolves the attribute from, per this project's
    "hook the instantiated class, not the base" rule -- is patched with a
    deliberately wrong implementation, the patch is proven to have fired by
    COUNTING invocations, and the change in observations is measured.  A
    mutation that changes nothing is recorded as
    `mutation_effect_observed = false` and is NOT counted as a control.

USAGE
-----
    python phase16r/isa/tools/r11_j3_matrix.py
    python phase16r/isa/tools/r11_j3_matrix.py --no-rerun   # recorded 16L runs
"""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True                      # never write a .pyc

import argparse                                     # noqa: E402
import collections                                  # noqa: E402
import hashlib                                      # noqa: E402
import inspect                                      # noqa: E402
import json                                         # noqa: E402
import os                                           # noqa: E402
import subprocess                                   # noqa: E402
import traceback                                    # noqa: E402

# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))              # phase16r/isa/tools
ISA = os.path.dirname(HERE)                                    # phase16r/isa
LOGS = os.path.join(ISA, "logs")
ROOT = os.path.dirname(os.path.dirname(ISA))                   # project root

CONE_REL = "phase16p/j3_v2/J3_OUTPUT_DEPENDENCY.json"
J3C_REL = "phase16q/j3_v2/J3_CONFORMANCE_FINAL.json"
DEPSTAT_REL = "phase16q/j3_v2/J3_DEPENDENCY_STATUS_FINAL.json"
R9_REL = "phase16r/isa/R9_DIVISION_SEMANTICS.json"
N7REPLAY_REL = "phase16r/isa/logs/r10_original_frozen_replay.json"
ALIAS_REL = "phase16n_semantic_freeze/n2_aliases/N2_N3_COVERAGE.json"
SIXTEEN_L = "phase16l_authoritative_rederive/isa_conformance"
OUT_REL = "phase16s/isa/J3_INSTRUCTION_CONFORMANCE.json"
LOG_REL = "phase16s/isa/logs/r11_matrix_16s.txt"
#: The Q1 oracle and the ISA document, for the one adjudication below.
Q1_ORACLE_REL = "phase16q/j3_v2/oracle/q1_oracle.py"
ISA_TEXT_REL = "phase16r/isa/ref/rdna2_isa.txt"

VEC_VERIFIER = SIXTEEN_L + "/verify_against_oracle.py"
SCA_VERIFIER = SIXTEEN_L + "/verify_scalar_against_oracle.py"

#: The only four statuses the brief permits.
STATUSES = ("VERIFIED_INDEPENDENTLY", "VERIFIED_BY_EXACT_EQUIVALENCE",
            "NOT_OUTPUT_RELEVANT", "BLOCKED")

#: R9's measured verdict and the three instructions it names.  Cited from
#: `phase16r/isa/R9_DIVISION_SEMANTICS.json`, not re-derived here.
DIV_MNEMONICS = ("v_div_scale_f32", "v_div_fmas_f32", "v_div_fixup_f32")
DIV_REASON = ("ISA_DIVISION_SEQUENCE_NOT_IMPLEMENTED: the emulator handler "
              "implements none of the RDNA2 V_DIV_SCALE_F32 / V_DIV_FMAS_F32 / "
              "V_DIV_FIXUP_F32 sequence; see phase16r/isa/"
              "R9_DIVISION_SEMANTICS.json")

LOG = []


def P(line=""):
    LOG.append(str(line))
    print(line, flush=True)


# ---------------------------------------------------------------------------
# write-scope audit -- this stream must write nothing outside phase16r/isa
# ---------------------------------------------------------------------------
_AUDIT = {"installed": False, "writes": [], "events": 0}
_ISA_ABS = os.path.abspath(ISA) + os.sep

#: per-event argument indices naming a WRITE target.  Without this map
#: `shutil.copyfile(src, dst)` is recorded as a write to `src`.
_WRITE_ARGS = {
    "os.remove": (0,), "os.mkdir": (0,), "os.rmdir": (0,),
    "os.truncate": (0,), "os.chmod": (0,), "os.utime": (0,),
    "os.link": (0, 1), "os.symlink": (1,), "os.rename": (0, 1),
    "os.replace": (0, 1), "shutil.copyfile": (1,), "shutil.copymode": (1,),
    "shutil.copystat": (1,), "shutil.move": (1,), "shutil.rmtree": (0,),
}


def _inside_isa(path):
    try:
        return os.path.abspath(path).startswith(_ISA_ABS)
    except Exception:                                            # noqa: BLE001
        return False


def _state_of(path):
    try:
        st = os.stat(path)
        return ["file", st.st_size, st.st_mtime_ns]
    except FileNotFoundError:
        return ["absent"]
    except Exception as exc:                                     # noqa: BLE001
        return ["unreadable", type(exc).__name__]


def _record(kind, args, idxs=None):
    if idxs is None:
        idxs = _WRITE_ARGS.get(kind, ())
    for i in idxs:
        if i >= len(args) or not isinstance(args[i], (str, bytes, os.PathLike)):
            continue
        sp = os.fsdecode(args[i])
        if not _inside_isa(sp):
            _AUDIT["writes"].append({"kind": kind, "path": sp,
                                     "state_at_attempt": _state_of(sp),
                                     "state_after_run": None,
                                     "state_changed": None})


def _hook(event, args):
    _AUDIT["events"] += 1
    if event in _WRITE_ARGS:
        _record(event, args)
    elif event == "open":
        mode = args[1] if len(args) > 1 else ""
        if isinstance(mode, str) and any(c in mode for c in "wxa+"):
            _record("open", args, (0,))


def install_audit():
    sys.addaudithook(_hook)
    _AUDIT["installed"] = True


def finalize_audit():
    for w in _AUDIT["writes"]:
        after = _state_of(w["path"])
        w["state_after_run"] = after
        w["state_changed"] = (w["state_at_attempt"] != after)
    _AUDIT["n_write_intents_outside"] = len(_AUDIT["writes"])
    _AUDIT["n_state_changing_outside"] = sum(
        1 for w in _AUDIT["writes"] if w["state_changed"])
    return _AUDIT


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for b in iter(lambda: fh.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def rel(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def nm(m):
    """The suites' own normalisation: strip the encoding suffix."""
    return m.replace("_e32", "").replace("_e64", "")


def load(rel_path):
    with open(os.path.join(ROOT, rel_path), encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# section 1 -- re-run the two 16L oracle suites, output under phase16r/isa
# ---------------------------------------------------------------------------
def run_sixteenl(script, label, out_name, do_run=True):
    out_abs = os.path.join(LOGS, out_name)
    cmd = [sys.executable, os.path.join(ROOT, script), "--label", label,
           "--out", out_abs]
    rec = {"command": " ".join(cmd), "cwd": ROOT,
           "env": "PYTHONDONTWRITEBYTECODE=1", "returncode": None,
           "stdout_tail": [], "stderr_tail": [], "ran": bool(do_run),
           "out_path": rel(out_abs), "out_sha256": None}
    if do_run:
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                               env=env, timeout=3600)
            rec["returncode"] = p.returncode
            rec["stdout_tail"] = p.stdout.strip().splitlines()[-25:]
            rec["stderr_tail"] = p.stderr.strip().splitlines()[-15:]
        except Exception as exc:                                 # noqa: BLE001
            rec["error"] = "%s: %s" % (type(exc).__name__, exc)
            return rec, None
    if not os.path.exists(out_abs):
        rec["error"] = "no output written"
        return rec, None
    rec["out_sha256"] = sha256_file(out_abs)
    with open(out_abs, encoding="utf-8") as fh:
        return rec, json.load(fh)


# ---------------------------------------------------------------------------
# section 2 -- live handler resolution on the INSTANTIATED class
# ---------------------------------------------------------------------------
def mro_definers(cls, attr):
    return [c.__name__ for c in cls.__mro__ if attr in c.__dict__]


def resolve_attr(cls, attr):
    for c in cls.__mro__:
        if attr in c.__dict__:
            return c, c.__dict__[attr]
    return None, None


def handler_source(obj):
    fn = getattr(obj, "__func__", obj)
    try:
        f = inspect.getsourcefile(fn) or inspect.getfile(fn)
        return "%s:%d" % (rel(f), inspect.getsourcelines(fn)[1])
    except Exception as exc:                                     # noqa: BLE001
        return "unresolved(%s)" % type(exc).__name__


def find_table_entry(owner_obj, base):
    """The file:line where a dispatch table entry for `base` is written.

    The `v_cmp_*` / `v_cmpx_*` forms have NO `op_<mnemonic>` attribute: the
    dispatcher takes the base name and looks the condition up in a table, so
    the semantics of the instruction are the table entry, and that entry's
    line is the semantic source.
    """
    fn = getattr(owner_obj, "__func__", owner_obj)
    try:
        src, first = inspect.getsourcelines(fn)
        f = inspect.getsourcefile(fn) or inspect.getfile(fn)
    except Exception:                                            # noqa: BLE001
        return None
    for i, line in enumerate(src):
        if ('"%s"' % base) in line or ("'%s'" % base) in line:
            return "%s:%d" % (rel(f), first + i)
    return None


def describe_handler(core_cls, recorded, base):
    """Live description of the handler the cone record names.

    For the dispatched forms the cone record names the DISPATCHER (for example
    `GateCore._cmp_dispatch -> getattr(self, 'op_v_cmp_lt_<cond>')`).  There is
    no `op_v_cmp_lt_i32` to resolve: the dispatcher resolves the condition
    through a table.  So the dispatcher is resolved, and the table entry that
    actually carries the semantics is located and recorded separately, rather
    than substituting one for the other.
    """
    out = {"recorded": recorded, "attr": None, "attr_owner": None,
           "definers_in_mro": [], "handler_source": None,
           "attr_resolves_live": False, "table_entry_source": None}
    if not recorded:
        return out
    attr = recorded.split(".")[-1].strip()
    if "->" in recorded:
        attr = attr.split("->")[0].strip()
        out["attr"] = attr
        owner, obj = resolve_attr(core_cls, attr)
        out["attr_owner"] = owner.__name__ if owner is not None else None
        out["definers_in_mro"] = mro_definers(core_cls, attr)
        out["attr_resolves_live"] = owner is not None
        if obj is not None:
            out["handler_source"] = handler_source(obj)
        cond_owner, cond_obj = resolve_attr(core_cls,
                                            "_int_cmp_cond" if "_cmp" in base
                                            else "_fp_cmp_cond")
        if cond_obj is None:
            cond_owner, cond_obj = resolve_attr(core_cls, "_int_cmp_cond")
        if cond_obj is not None:
            out["table_entry_source"] = find_table_entry(cond_obj, base)
            out["cond_table_owner"] = (cond_owner.__name__
                                       if cond_owner is not None else None)
        return out
    out["attr"] = attr
    owner, obj = resolve_attr(core_cls, attr)
    out["attr_owner"] = owner.__name__ if owner is not None else None
    out["definers_in_mro"] = mro_definers(core_cls, attr)
    out["attr_resolves_live"] = owner is not None
    if obj is not None:
        out["handler_source"] = handler_source(obj)
    return out


# ---------------------------------------------------------------------------
# section 3 -- the probe harness, over the composed BothCore
# ---------------------------------------------------------------------------
class Harness:
    """Runs ONE instruction through the class the runner INSTANTIATES.

    The 16L verifiers bind production handlers onto a bare `Core`.  This does
    not: it builds the composed `BothCore` through the same `new_core` the M2
    verifier uses, so the method that runs is the first one the instantiated
    class's own MRO finds.
    """

    def __init__(self, env, m2):
        self.V = m2
        self.runner = m2.Runner(env)
        self.BOTH = self.runner.BOTH

    def build(self, mnem, ops, setup):
        core, gate = self.runner.new_core(mnem, ops, {})
        for i in range(128):
            core.s[i] = 0xDEADBEEF
        core.exec_l = 0xFFFFFFFF
        core.scc = 0
        for k, v in (setup or {}).items():
            if k == "exec":
                core.exec_l = v & 0xFFFFFFFF
            elif k == "scc":
                core.scc = v & 1
            elif k in ("vcc", "vcc_lo"):
                core.vcc_l = v & 0xFFFFFFFF
            elif k.startswith("s") and k[1:].isdigit():
                core.s[int(k[1:])] = v & 0xFFFFFFFF
            elif k.startswith("v") and k[1:].isdigit():
                core.v[0][int(k[1:])] = v & 0xFFFFFFFF
        return core

    @staticmethod
    def read_dst(core, dst):
        """Pair-aware destination read-back (the 16L harness reads s<digit>
        only, so `s[3:4]` came back as None)."""
        d = (dst or "").strip()
        if d.startswith("s[") and d.endswith("]") and ":" in d:
            lo, hi = d[2:-1].split(":")
            return (core.s[int(hi)] << 32) | core.s[int(lo)]
        if d.startswith("v[") and d.endswith("]") and ":" in d:
            lo, hi = d[2:-1].split(":")
            return (core.v[0][int(hi)] << 32) | core.v[0][int(lo)]
        if d.startswith("s") and d[1:].isdigit():
            return core.s[int(d[1:])]
        if d.startswith("v") and d[1:].isdigit():
            return core.v[0][int(d[1:])]
        if d in ("vcc", "vcc_lo"):
            return core.vcc_l
        if d in ("scc",):
            return core.scc
        if d in ("exec", "exec_lo"):
            return core.exec_l
        return None

    def probe(self, v):
        """One uniform observation for a 16L oracle vector, whatever its kit."""
        core = self.build(v["mnem"], v["ops"], v["setup"])
        err = None
        try:
            core.step()
        except Exception as exc:                                 # noqa: BLE001
            err = "%s: %s" % (type(exc).__name__, exc)
        return {"error": err, "value": self.read_dst(core, v["dst"]),
                "scc": core.scc, "exec": core.exec_l}


# ---------------------------------------------------------------------------
# section 4 -- per-mnemonic mutation, measured on the MRO-resolved handler
# ---------------------------------------------------------------------------
def _obs_diffs(emu, orc):
    """The fields that differ, compared exactly the way the 16L comparator
    does -- error, then scc / exec / destination value whenever the oracle side
    carries one.  Comparing only the value, as a first attempt did, silently
    accepted an EXEC disagreement (s_andn2_saveexec_b32)."""
    d = []
    if emu.get("error") != orc.get("error"):
        d.append({"field": "error", "emulator": emu.get("error"),
                  "oracle": orc.get("error")})
    for k in ("scc", "exec", "value"):
        if orc.get(k) is None:
            continue
        if emu.get(k) != orc.get(k):
            d.append({"field": k, "emulator": emu.get(k), "oracle": orc.get(k)})
    # 16S additive: an oracle side that declares `extra` read-backs has those
    # compared as well.  Observations without an `extra` key are unaffected, so
    # every 16L / M2 / Q1 comparison is exactly what it was.
    for reg, want in (orc.get("extra") or {}).items():
        got = (emu.get("extra") or {}).get(reg)
        if got != want:
            d.append({"field": "extra." + reg, "emulator": got,
                      "oracle": want})
    return d


def _wrong_lsb_cleared(orig):
    def h(*a, **k):
        r = orig(*a, **k)
        return (r & ~1) & 0xFFFFFFFF if isinstance(r, int) else r
    return h


def _wrong_swapped(orig):
    def h(*a, **k):
        if len(a) >= 3:                       # (self, src0, src1, ...)
            a = (a[0], a[2], a[1]) + tuple(a[3:])
        return orig(*a, **k)
    return h


MUTATION_SHAPES = (("result_lsb_cleared", _wrong_lsb_cleared),
                   ("src1_src0_swapped", _wrong_swapped))


def measured_mutation(harness, core_cls, attr, vectors, shapes=None):
    """Patch the MRO owner of `attr`; prove the patch fired; measure the delta.

    Returns a record for the first shape that both fires and changes an
    observation, or for the last shape tried if none does (with
    `mutation_effect_observed` false, which is a real measurement).
    """
    owner, orig = resolve_attr(core_cls, attr)
    if owner is None or not callable(orig):
        return None
    raw = getattr(orig, "__func__", orig)
    base = [harness.probe(v) for v in vectors]
    last = None
    for shape_name, shape in (shapes or MUTATION_SHAPES):
        calls = {"n": 0}

        def counting(fn):
            def h(*a, **k):
                calls["n"] += 1
                return fn(*a, **k)
            return h

        wrapped = shape(counting(raw))
        setattr(owner, attr, wrapped)
        try:
            _, now = resolve_attr(core_cls, attr)
            resolves_to_patched = getattr(now, "__func__", now) is wrapped
        except Exception:                                        # noqa: BLE001
            resolves_to_patched = None
        try:
            after = [harness.probe(v) for v in vectors]
        finally:
            setattr(owner, attr, orig)
        changed = [i for i, (b, a) in enumerate(zip(base, after)) if b != a]
        fields = sorted({f["field"] for i in changed
                         for f in _obs_diffs(base[i], after[i])})
        obs = bool(calls["n"])
        last = {"mutation": "%s@%s.%s" % (shape_name, owner.__name__, attr),
                "patched_class": owner.__name__,
                "patched_is_mro_owner": True,
                "attr_resolves_to_patched": resolves_to_patched,
                "invocations_measured": calls["n"],
                "mutation_effect_observed": obs,
                "n_vectors_changed": len(changed),
                "vectors_changed": [vectors[i]["name"] for i in changed][:6],
                "changed_fields": fields,
                "mutation_rejected": bool(obs and changed)}
        if last["mutation_rejected"]:
            return last
    return last


# ---------------------------------------------------------------------------
# section 10 (16S) -- the S1 independent ISA oracle suite
# ---------------------------------------------------------------------------
#: The Phase 16S item-S1 oracle.  It supplies EXPECTED values only.
S1_ORACLE_REL = "phase16s/isa/ISA_ORACLE_16.json"


class HarnessS1(Harness):
    """The R11 harness, with two ADDITIVE and values-only widenings.

    Nothing about HOW an instruction executes or how the destination is read
    changes: `step()` and `read_dst` are inherited untouched and the primary
    observation is `Harness.probe`'s own.

      * `build` -- a `setup` value that is a LIST seeds that VGPR per lane.
        Every non-list key is handed to `super().build`, so the 16L / M2 kit
        setup path is literally the base code; an int-valued `vN` still seeds
        lane 0 only, exactly as in 16R.
      * `probe` -- when a vector declares `expect.extra`, the instruction is
        executed a second time on a fresh core to read the named registers
        (`sN`, `vN`, `vN@lane`, `vcc`, `scc`, `exec`).  The second execution's
        primary observation is REQUIRED to equal the first, so the extra
        read-back cannot perturb or reinterpret what was measured.

    `s1_harness_equivalence` below measures both widenings.
    """

    def build(self, mnem, ops, setup):
        base = {k: v for k, v in (setup or {}).items()
                if not isinstance(v, list)}
        core = super().build(mnem, ops, base)
        for k, v in (setup or {}).items():
            if not isinstance(v, list):
                continue
            if not (k.startswith("v") and k[1:].isdigit()):
                raise ValueError("list-valued setup key is not a VGPR: " + k)
            i = int(k[1:])
            if len(v) != self.V.LANES:
                raise ValueError("per-lane setup needs %d entries" % self.V.LANES)
            for lane in range(self.V.LANES):
                core.v[lane][i] = v[lane] & 0xFFFFFFFF
        return core

    @staticmethod
    def _read_extra(core, key):
        if "@" in key:
            reg, lane = key.split("@")
            if reg.startswith("v") and reg[1:].isdigit():
                return core.v[int(lane)][int(reg[1:])]
            if reg.startswith("s") and reg[1:].isdigit():
                return core.s[int(reg[1:])]
            raise ValueError("bad per-lane read-back: " + key)
        return Harness.read_dst(core, key)

    def probe(self, v):
        obs = super().probe(v)
        extra = ((v.get("expect") or {}).get("extra") or {})
        if not extra:
            return obs
        core = self.build(v["mnem"], v["ops"], v["setup"])
        err = None
        try:
            core.step()
        except Exception as exc:                                 # noqa: BLE001
            err = "%s: %s" % (type(exc).__name__, exc)
        again = {"error": err, "value": Harness.read_dst(core, v["dst"]),
                 "scc": core.scc, "exec": core.exec_l}
        if again != obs:
            raise AssertionError("re-execution is not deterministic for "
                                 + v["name"])
        obs = dict(obs)
        obs["extra"] = {k: self._read_extra(core, k) for k in extra}
        return obs


#: int-valued-setup probes only: these are exactly the shape the 16L kits use,
#: so `Harness` and `HarnessS1` must agree on every one of them.
S1_EQUIV_PROBES = [
    {"name": "eq_add_co_u32", "mnem": "v_add_co_u32",
     "ops": ["v0", "s0", "v1", "v2"], "dst": "v0",
     "setup": {"v1": 7, "v2": 5, "s0": 0}},
    {"name": "eq_add_co_ci", "mnem": "v_add_co_ci_u32",
     "ops": ["v0", "null", "v1", "v2", "vcc_lo"], "dst": "v0",
     "setup": {"v1": 0xFFFFFFFF, "v2": 0, "vcc": 1}},
    {"name": "eq_pack", "mnem": "v_pack_b32_f16",
     "ops": ["v0", "v1", "v2"], "dst": "v0",
     "setup": {"v1": 0x3C00, "v2": 0x4000}},
    {"name": "eq_mul_lo_u16", "mnem": "v_mul_lo_u16",
     "ops": ["v0", "v1", "v2"], "dst": "v0",
     "setup": {"v1": 0xFFFF, "v2": 0xFFFF}},
    {"name": "eq_cvt_f16_f32", "mnem": "v_cvt_f16_f32",
     "ops": ["v1", "v1"], "dst": "v1", "setup": {"v1": 0x33400000}},
    {"name": "eq_s_mov_b64", "mnem": "s_mov_b64",
     "ops": ["s[3:4]", "s[0:1]"], "dst": "s[3:4]",
     "setup": {"s0": 0x11223344, "s1": 0x55667788}},
    {"name": "eq_cmp_gt_i32", "mnem": "v_cmp_gt_i32",
     "ops": ["s4", "s0", "v5"], "dst": "s4",
     "setup": {"s0": 0x80000000, "v5": 1}},
    {"name": "eq_fma_mixlo", "mnem": "v_fma_mixlo_f16",
     "ops": ["v0", "v1", "v2", "v3"], "dst": "v0",
     "setup": {"v0": 0x11110000, "v1": 0x3C00, "v2": 0x3C00, "v3": 0}},
]


def s1_harness_equivalence(harness, harness_s1):
    """NC_E -- prove the S1 widenings change no primary observation.

    Two halves:
      * every int-valued-setup probe gives the SAME observation through both
        classes (so the seeding path the 16L kits use is unchanged);
      * a list-valued-setup probe RAISES through the base class and runs
        through the S1 class (so the widening is what is doing the work).
    """
    rec = {"name": "NC_E_HarnessS1_widening_is_additive", "same": [],
           "widening_needed": [], "ok": False}
    for p in S1_EQUIV_PROBES:
        a = harness.probe(p)
        b = harness_s1.probe(p)
        rec["same"].append({"probe": p["name"], "identical": a == b,
                            "base": a, "s1": b})
    listy = {"name": "eq_list_setup", "mnem": "v_add_co_u32",
             "ops": ["v0", "s0", "v1", "v2"], "dst": "v0",
             "setup": {"v1": list(range(32)), "v2": 3, "s0": 0}}
    try:
        harness.probe(listy)
        base_raised = None
    except Exception as exc:                                     # noqa: BLE001
        base_raised = type(exc).__name__
    try:
        got = harness_s1.probe(listy)
    except Exception as exc:                                     # noqa: BLE001
        got = {"error": "%s: %s" % (type(exc).__name__, exc)}
    rec["widening_needed"].append({"probe": "eq_list_setup",
                                   "base_class_raised": base_raised,
                                   "s1_class_value": got.get("value"),
                                   "s1_class_error": got.get("error")})
    rec["ok"] = (all(x["identical"] for x in rec["same"])
                 and base_raised is not None
                 and got.get("error") is None)
    return rec


def load_s1_suite(path=None):
    """The S1 vectors, in a shape `Harness.probe` can run."""
    p = path or os.path.join(ROOT, S1_ORACLE_REL)
    if not os.path.exists(p):
        return None, None, None
    with open(p, encoding="utf-8") as fh:
        doc = json.load(fh)
    kit = collections.defaultdict(list)
    for v in doc["vectors"]:
        kit[nm(v["mnem"])].append({
            "suite": "S1_ISA_ORACLE", "name": v["name"], "mnem": v["mnem"],
            "ops": [v["dst"]] + list(v["srcs"]), "dst": v["dst"],
            "setup": v["setup"], "expect": v["expect"],
            "alt": v.get("alt") or {}, "note": v.get("note"),
            "source": v.get("source"),
        })
    return kit, doc, sha256_file(p)


def alts_that_explain(v, obs, diffs):
    """Which admissible ALTERNATE reading accounts for EVERY differing field.

    An alternate only explains a disagreement when it covers every field that
    differs: otherwise a vector whose destination is wrong could be moved from
    a disagreement to an open-semantics note by an alternate that happens to
    match one unrelated read-back.
    """
    hits = []
    for name, spec in (v.get("alt") or {}).items():
        if spec is None:
            continue
        if isinstance(spec, int):
            spec = {"value": spec}
        cover, ok = set(), True
        for k, want in spec.items():
            if k == "extra":
                for reg, wv in want.items():
                    cover.add("extra." + reg)
                    if (obs.get("extra") or {}).get(reg) != wv:
                        ok = False
            else:
                cover.add(k)
                if obs.get(k) != want:
                    ok = False
        if ok and cover and all(d["field"] in cover for d in diffs):
            hits.append(name)
    return hits


def s1_evidence(suite, harness_s1):
    """Measure every S1 vector through `Harness.probe` and the tool's own
    comparator, and return per-mnemonic evidence in the tool's shape."""
    out = collections.defaultdict(lambda: {"vectors": [], "comparisons": 0,
                                           "mismatches": 0, "suites": set(),
                                           "s1": True})
    for mnem, vs in sorted(suite.items()):
        for v in vs:
            obs = harness_s1.probe(v)
            diffs = _obs_diffs(obs, v["expect"])
            n = 1 + sum(1 for k in ("scc", "exec")
                        if v["expect"].get(k) is not None)
            n += len(v["expect"].get("extra") or {})
            agree = not diffs
            out[mnem]["vectors"].append({
                "suite": "S1_ISA_ORACLE", "name": v["name"],
                "comparisons": n, "agree": agree,
                "mismatches": 0 if agree else n,
                "handler_from": "BothCore (MRO)",
                "diffs": diffs, "expect": v["expect"], "measured": obs,
                "alt": v["alt"], "note": v["note"], "source": v["source"],
                "matches_alternate_reading":
                    alts_that_explain(v, obs, diffs)})
            out[mnem]["comparisons"] += n
            if not agree:
                out[mnem]["mismatches"] += n
            out[mnem]["suites"].add("S1_ISA_ORACLE")
    return out


def _ops_index(args):
    """Where the operand list sits, for both the `op_*(self, ins, ops)`
    handlers and the `_cmp_dispatch(self, m, ins, ops)` dispatcher."""
    for i, a in enumerate(args):
        if isinstance(a, list) and len(a) >= 3 and all(
                isinstance(x, str) for x in a):
            return i
    return None


def _wrong_src_swap_ops(orig):
    """Known-bad: the two SOURCE operand tokens exchanged."""
    def h(*a, **k):
        i = _ops_index(a)
        if i is None:
            return orig(*a, **k)
        ops = [a[i][0], a[i][2], a[i][1]] + list(a[i][3:])
        return orig(*(a[:i] + (ops,) + a[i + 1:]), **k)
    return h


def _wrong_dst_bit0(orig):
    """Known-bad: bit 0 of the destination register forced after the handler."""
    def h(*a, **k):
        try:
            return orig(*a, **k)
        finally:
            try:
                me = a[0]
                i = _ops_index(a)
                d = a[i][0] if i is not None else ""
                if d.startswith("v") and d[1:].isdigit():
                    me.v[0][int(d[1:])] |= 1
                elif d.startswith("s[") and d.endswith("]"):
                    me.s[int(d[2:-1].split(":")[0])] |= 1
                elif d.startswith("s") and d[1:].isdigit():
                    me.s[int(d[1:])] |= 1
                elif d in ("vcc", "vcc_lo"):
                    me.vcc_l |= 1
            except Exception:                                    # noqa: BLE001
                pass
    return h


#: The 16R shapes are written for handlers whose signature is
#: `(self, src0, src1, ...)`; every handler in this matrix is
#: `(self, ins, ops)`, so the two added shapes address the OPERAND LIST
#: instead.  They are tried only after the 16R shapes and only for rows whose
#: vectors come from the S1 suite, so no 16R row changes shape.
S1_MUTATION_SHAPES = MUTATION_SHAPES + (
    ("src1_src0_swapped_ops", _wrong_src_swap_ops),
    ("dst_bit0_forced", _wrong_dst_bit0),
)


# ---------------------------------------------------------------------------
# section 4b -- adjudicating an oracle the ISA document refutes
# ---------------------------------------------------------------------------
#: The opcode name is wrapped across two lines in the document, so the reader
#: matches this head and then reads on to the expression line.
SAVEEXEC_ISA_HEAD = "S_ANDN2_SAVEEXE"
#: The B32 reading, as the document prints it.  The reader COMPARES the file
#: against this string and records the comparison; it never substitutes it.
SAVEEXEC_ISA_EXPR = "EXEC_LO = S0.u32 & ~EXEC_LO;"


def isa_saveexec_expressions(path):
    """Every saveexec expression the ISA document gives for S_ANDN2_SAVEEXEC*.

    Returns one candidate per opcode block: the description line number, the
    expression line number, the expression text, and the text of the block
    between them (which carries the `C_B32` / `C_B64` tail of the wrapped
    opcode name).  An expression that is not in the file is reported missing,
    never guessed.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    cands = []
    for i, ln in enumerate(lines):
        if SAVEEXEC_ISA_HEAD not in ln:
            continue
        for j in range(i + 1, min(i + 15, len(lines))):
            s = lines[j].strip()
            if s.startswith("EXEC_LO =") or s.startswith("EXEC ="):
                cands.append({"desc_line": i + 1, "expr_line": j + 1,
                              "expr": s,
                              "block_text": " ".join(
                                  x.strip() for x in lines[i:j + 1])})
                break
    return cands


def _reading_isa(src, old):
    """`S0 & ~EXEC_old` -- the B32 saveexec reading this project reads out of
    the ISA document (rdna2_isa.txt line 6450)."""
    return (src & ~old) & 0xFFFFFFFF


def _reading_legacy(src, old):
    """`EXEC_old & ~S0` -- the same two operands the other way round."""
    return (old & ~src) & 0xFFFFFFFF


def _legacy_saveexec_patch(counter):
    """A known-bad saveexec handler: the legacy reading, in place of the
    live one, counting its own invocations.  Signature `(self, ins, ops)`,
    which is what the MRO owner of `op_s_*_saveexec_b32` resolves to."""
    def h(self, ins, ops):
        counter["n"] += 1
        old = self.exec_l
        src = self.sget(ops[1])
        self._saveexec(ops[0], (old & ~src) & 0xFFFFFFFF)
    return h


def _probe_kit(name, mnem, ops, init):
    """A Q1 oracle vector as something `Harness.probe` can run."""
    setup = {"s%d" % k: v for k, v in (init.get("s") or {}).items()}
    if "exec" in init:
        setup["exec"] = init["exec"]
    if "scc" in init:
        setup["scc"] = init["scc"]
    return {"name": name, "mnem": mnem, "ops": list(ops), "dst": ops[0],
            "setup": setup}


def adjudicate_saveexec(harness, OS, core_cls, Q1, q1_vectors, j3_vec_names):
    """NC4 -- measure which side of the disagreement the ISA document refutes.

    The live emulator and the 16L scalar oracle disagree on exactly one
    mnemonic (`s_andn2_saveexec_b32`).  Two readings are possible and the ISA
    document prints one of them.  This probe measures, on the Q1 oracle's own
    discriminating vector:

      * that the vector really separates the two readings (otherwise the
        whole exercise is vacuous -- the probe records `readings_differ`);
      * which reading the live emulator produced;
      * which reading each oracle produced;
      * that the legacy reading, patched into the live handler, is rejected by
        that vector -- and survives one whose inputs cannot separate the
        readings, which is what a suite carrying only such a vector would see.

    `ok` is the conjunction.  When `ok` is false nothing is adjudicated and the
    row stays BLOCKED; the record of why is kept either way.
    """
    rec = {"name": "NC4_refuted_oracle_adjudication",
           "what": ("measure, on one discriminating vector, whether the oracle "
                    "that disagrees with the live emulator is the side that "
                    "contradicts the ISA document"),
           "isa_document": {"file": ISA_TEXT_REL,
                            "sha256": sha256_file(os.path.join(ROOT, ISA_TEXT_REL)),
                            "head": SAVEEXEC_ISA_HEAD,
                            "expected_b32_expression": SAVEEXEC_ISA_EXPR,
                            "candidates": []},
           "ok": False, "refuted": {}}
    try:
        cands = isa_saveexec_expressions(os.path.join(ROOT, ISA_TEXT_REL))
    except Exception as exc:                                     # noqa: BLE001
        rec["error"] = "%s: %s" % (type(exc).__name__, exc)
        return rec
    for c in cands:
        c["is_b32_form"] = ("C_B32" in c["block_text"]
                            and SAVEEXEC_ISA_HEAD in c["block_text"])
        c["matches_expected_expression"] = (c["expr"] == SAVEEXEC_ISA_EXPR)
        rec["isa_document"]["candidates"].append(c)
    b32 = [c for c in cands if c["is_b32_form"]]
    rec["isa_b32_blocks_found"] = len(b32)
    rec["isa_b32_expressions_all_match"] = bool(b32) and all(
        c["matches_expected_expression"] for c in b32)

    vec_name = "q1_andn2_saveexec_b32_operand_order"
    v = q1_vectors.get(vec_name)
    rec["mnemonic"] = nm(v["mnem"]) if v else None
    rec["vector"] = {"name": vec_name,
                     "source": Q1_ORACLE_REL + " build_vectors()",
                     "present_in_J3_artifact": vec_name in j3_vec_names}
    if v is None:
        rec["error"] = "the Q1 discriminating vector is not in the oracle"
        return rec
    ops = list(v["ops"])
    init = dict(v["init"])
    src = init["s"][int(ops[1][1:])]
    old = init["exec"]
    isa_val = _reading_isa(src, old)
    legacy_val = _reading_legacy(src, old)
    kit = _probe_kit(vec_name, v["mnem"], ops, init)

    emu = harness.probe(kit)
    # `model()` returns the OBSERVATIONS the vector declares -- here
    # {"s": {0: <old EXEC>}, "exec": <new EXEC>} -- not a bare tuple.
    q1_model = Q1.model(v)
    q1_exec = q1_model.get("exec")
    q1_dst = (q1_model.get("s") or {}).get(int(ops[0][1:]))
    try:
        six = OS.eval_scalar({"mnem": v["mnem"], "operands": ops,
                              "setup": kit["setup"], "family": "",
                              "name": vec_name})
    except Exception as exc:                                     # noqa: BLE001
        six = {"error": "%s: %s" % (type(exc).__name__, exc)}

    rec["vector"]["inputs"] = {"old_exec": old, "src_S0": src,
                               "dst": ops[0], "setup": kit["setup"]}
    rec["readings"] = {
        "isa_S0_and_not_exec": isa_val,
        "legacy_exec_and_not_S0": legacy_val,
        "readings_differ": isa_val != legacy_val,
        "differing_bits": bin(isa_val ^ legacy_val).count("1")}
    rec["emulator_live"] = {"exec": emu.get("exec"), "dst": emu.get("value"),
                            "scc": emu.get("scc"), "error": emu.get("error")}
    rec["q1_oracle_model"] = {"observations": q1_model,
                              "exec": q1_exec, "dst": q1_dst,
                              "source": Q1_ORACLE_REL}
    rec["sixteen_l_scalar_oracle"] = {"exec": six.get("exec"),
                                      "dst": six.get("value"),
                                      "error": six.get("error"),
                                      "source": SIXTEEN_L +
                                      "/isa_oracle_scalar.py"}
    rec["emulator_matches_isa_reading"] = (
        emu.get("exec") == isa_val and emu.get("value") == old)
    rec["emulator_matches_legacy_reading"] = (emu.get("exec") == legacy_val)
    rec["q1_oracle_matches_isa_reading"] = (
        q1_exec == isa_val and q1_dst == old)
    rec["sixteen_l_oracle_matches_legacy_reading"] = (
        six.get("exec") == legacy_val and six.get("value") == old)

    # the same known-bad, on the discriminating vector and on one that cannot
    # separate the readings: rejected there, invisible here.
    attr = "op_s_andn2_saveexec_b32"
    owner, orig = resolve_attr(core_cls, attr)
    nondisc = {"name": "constructed_nondiscriminating", "mnem": v["mnem"],
               "ops": ops, "dst": ops[0],
               "setup": {"s%d" % int(ops[1][1:]): 0, ops[0]: 0, "exec": 0}}
    rec["known_bad"] = {"patch": "legacy_saveexec_reading@" +
                        (owner.__name__ if owner else "?") + "." + attr,
                        "patched_class": owner.__name__ if owner else None,
                        "patched_is_mro_owner": True}
    if owner is not None and callable(orig):
        before = harness.probe(kit)
        nb = harness.probe(nondisc)
        calls = {"n": 0}
        wrapped = _legacy_saveexec_patch(calls)
        setattr(owner, attr, wrapped)
        try:
            now = getattr(owner, attr, None)
            resolves = getattr(now, "__func__", now) is wrapped
            after = harness.probe(kit)
            na = harness.probe(nondisc)
        finally:
            setattr(owner, attr, orig)
        rec["known_bad"].update({
            "attr_resolves_to_patched": resolves,
            "invocations_measured": calls["n"],
            "discriminating_vector_changed": before != after,
            "discriminating_vector_now_reads": {
                "exec": after.get("exec"), "dst": after.get("value")},
            "discriminating_vector_rejects_the_known_bad":
                before != after and after.get("exec") == legacy_val,
            "nondiscriminating_probe_changed": nb != na,
            "known_bad_survives_a_nondiscriminating_vector": nb == na,
            "nondiscriminating_probe": nondisc["setup"],
        })

    ok = all([rec.get("isa_b32_expressions_all_match"),
              rec["readings"]["readings_differ"],
              rec["emulator_matches_isa_reading"],
              not rec["emulator_matches_legacy_reading"],
              rec["q1_oracle_matches_isa_reading"],
              rec["sixteen_l_oracle_matches_legacy_reading"],
              rec["known_bad"].get(
                  "discriminating_vector_rejects_the_known_bad"),
              rec["known_bad"].get(
                  "known_bad_survives_a_nondiscriminating_vector")])
    rec["ok"] = bool(ok)
    if rec["ok"]:
        rec["refuted"] = {
            nm(v["mnem"]): {
                "suite": "16L_ISA_SCALAR_ORACLE",
                "oracle_file": SIXTEEN_L + "/isa_oracle_scalar.py",
                "measured_on": vec_name,
                "oracle_exec": six.get("exec"),
                "legacy_reading": legacy_val,
                "isa_reading": isa_val,
                "emulator_exec": emu.get("exec"),
                "why": ("that oracle computes EXEC_old & ~mask where the ISA "
                        "document prints EXEC_LO = S0.u32 & ~EXEC_LO; on this "
                        "vector the two readings differ in %d bit(s)"
                        % bin(isa_val ^ legacy_val).count("1")),
            }}
    return rec


# ---------------------------------------------------------------------------
# section 5 -- classification
# ---------------------------------------------------------------------------
def classify(row, evid, r9_verdict, adjudication=None):
    """Exactly one of the four permitted statuses.  No other value is possible."""
    if row["nodes_in_union_cone"] == 0:
        return ("NOT_OUTPUT_RELEVANT",
                "zero nodes in the J3 output cone", None)
    e = evid.get(nm(row["mnemonic"]))
    has_vec = bool(e and e["vectors"])
    if has_vec:
        bad = [v for v in e["vectors"] if not v.get("agree", True)]
        good = [v for v in e["vectors"] if v.get("agree", True)]
        if not bad:
            return ("VERIFIED_INDEPENDENTLY",
                    "%d oracle vector(s) over %d comparison(s), 0 "
                    "disagreements, suites: %s"
                    % (len(e["vectors"]), e["comparisons"],
                       ",".join(sorted(e["suites"]))), None)
        # A disagreement does not by itself convict the emulator: an oracle
        # measured to contradict the ISA document is refuted, and its
        # disagreement is then not evidence about the emulator.  This is only
        # reachable when the adjudication MEASURED that (see NC4).
        ref = ((adjudication or {}).get("refuted") or {}).get(nm(row["mnemonic"]))
        ref_suite = ref["suite"] if ref else None
        if (ref and good
                and all(v["suite"] == ref_suite for v in bad)
                and all(v["suite"] != ref_suite for v in good)):
            return ("VERIFIED_INDEPENDENTLY",
                    ("%d of %d comparisons disagree, all of them from %s, "
                     "which NC4 measured to compute the reading the ISA "
                     "document refutes (%s); the live emulator matches the "
                     "discriminating vector's oracle reading"
                     % (e["mismatches"], e["comparisons"], ref_suite,
                        ref["why"])), None)
        return ("BLOCKED",
                "%d of %d comparisons disagree with the independent oracle"
                % (e["mismatches"], e["comparisons"]),
                "MEASURED_ORACLE_DISAGREEMENT")
    if row["mnemonic"] in DIV_MNEMONICS and r9_verdict:
        return "BLOCKED", DIV_REASON, "ISA_DIVISION_SEQUENCE_NOT_IMPLEMENTED"
    return ("BLOCKED",
            "no independent oracle vector observes this mnemonic and no "
            "measured exact equivalence to a verified mnemonic was found",
            "NO_INDEPENDENT_ORACLE_VECTOR_FOR_THIS_MNEMONIC")


def build_rows(cone, evid, handlers, aliases, r9_verdict, adjudication=None):
    rows = []
    per_cone = {k: (cone["cones"][k].get("mnemonics") or {})
                for k in ("value", "address", "predicate", "union")}
    for rec in cone["per_mnemonic"]:
        m = rec["mnemonic"]
        e = evid.get(nm(m))
        row = {
            "mnemonic": m,
            "family": rec["family"],
            "executed_count_on_j3_path": rec["executions_on_j3_path"],
            "nodes_in_value_cone": per_cone["value"].get(m, 0),
            "nodes_in_address_cone": per_cone["address"].get(m, 0),
            "nodes_in_predicate_cone": per_cone["predicate"].get(m, 0),
            "nodes_in_union_cone": per_cone["union"].get(m, 0),
            "contributes_to_written_bytes": rec["contributes_to_written_bytes"],
            "handler": rec["handler"],
            "handler_live": handlers.get(m),
            "alias_base": (aliases.get(m) or {}).get("base"),
            "alias_owner_recorded": (aliases.get(m) or {}).get("owner"),
            "independent_oracle": sorted(e["suites"]) if e else [],
            "oracle_vectors": len(e["vectors"]) if e else 0,
            "comparisons": e["comparisons"] if e else 0,
            "oracle_mismatches": e["mismatches"] if e else 0,
            "oracle_vector_names": ([v["name"] for v in e["vectors"]][:8]
                                    if e else []),
            "oracle_vector_handler_from": sorted({
                v.get("handler_from") for v in e["vectors"]
                if v.get("handler_from")}) if e else [],
            "detecting_mutation": None,
            "mutation_effect_observed": None,
            "mutation_rejected": None,
            "status": None,
            "verification_basis": None,
            "blocked_reason": None,
        }
        row["status"], row["verification_basis"], row["blocked_reason"] = \
            classify(row, evid, r9_verdict, adjudication)
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-rerun", action="store_true",
                    help="use the recorded 16L results instead of re-running")
    a = ap.parse_args(argv)

    install_audit()
    os.makedirs(LOGS, exist_ok=True)

    P("=" * 96)
    P("PHASE 16S / R11-INTEGRATION -- instruction-level J3 conformance matrix")
    P("   (copy of the 16R tool; adds the S1 oracle suite)")
    P("  host only; no GPU, no HIP, nothing armed")
    P("=" * 96)
    P("")

    # -- section 1: oracle suites re-run ------------------------------------
    P("1. oracle suites")
    v_rec, v_doc = run_sixteenl(VEC_VERIFIER, "r11_current",
                                "r11_16l_vector_oracle.json", not a.no_rerun)
    s_rec, s_doc = run_sixteenl(SCA_VERIFIER, "r11_current",
                                "r11_16l_scalar_oracle.json", not a.no_rerun)
    P("   16L vector oracle: %s" % v_rec.get("command"))
    P("      rc=%s vectors=%s agree=%s disagree=%s" % (
        v_rec.get("returncode"), (v_doc or {}).get("n_vectors"),
        (v_doc or {}).get("n_agree"), (v_doc or {}).get("n_disagree")))
    P("   16L scalar oracle: %s" % s_rec.get("command"))
    P("      rc=%s vectors=%s agree=%s disagree=%s" % (
        s_rec.get("returncode"), (s_doc or {}).get("n_vectors"),
        (s_doc or {}).get("n_agree"), (s_doc or {}).get("n_disagree")))
    if v_doc:
        P("      loaded from %s sha256 %s" % (v_doc.get("emulator_loaded_from"),
                                              v_doc.get("emulator_sha256")))
    if s_doc:
        P("      loaded from %s sha256 %s" % (s_doc.get("emulator_loaded_from"),
                                              s_doc.get("emulator_sha256")))
    P("")

    cone = load(CONE_REL)
    j3c = load(J3C_REL)
    depstat = load(DEPSTAT_REL)
    r9 = load(R9_REL)
    n7rep = load(N7REPLAY_REL)
    aliases = {r["mnemonic"]: r for r in load(ALIAS_REL)["rows"]}
    union = sorted(cone["cones"]["union"]["mnemonics"])
    cone_handler = {r["mnemonic"]: r["handler"] for r in cone["per_mnemonic"]}

    m2_names = {v["name"] for v in n7rep["vectors"]}
    j3_names = {v["name"] for v in j3c["vector_results"]}
    superset = m2_names <= j3_names
    P("   M2 suite contained in the J3 suite: %s (%d of %d names present; "
      "%d extra)" % (superset, len(m2_names & j3_names), len(m2_names),
                     len(j3_names - m2_names)))
    P("   J3 suite : %d vectors / %d comparisons / %d failures"
      % (j3c["cases"], j3c["comparisons"], j3c["failures"]))
    P("   R9       : %s" % r9.get("verdict"))
    P("")

    # -- section 2: emulator + live handlers --------------------------------
    sys.path.insert(0, os.path.join(ROOT, "phase16m_final_host", "m2_isa"))
    import verify_m2 as m2                                       # noqa: E402
    env = m2.load_emulator()
    harness = Harness(env, m2)
    # 16S: the same harness with the two additive, values-only widenings the
    # S1 suite needs.  Every recorded suite keeps using `harness` unchanged.
    harness_s1 = HarnessS1(env, m2)
    core_cls = harness.BOTH
    P("2. live handler resolution on %s" % core_cls.__name__)
    P("   MRO: %s" % " -> ".join(c.__name__ for c in core_cls.__mro__[:12]))
    handlers = {}
    for m in union:
        base = (aliases.get(m) or {}).get("base") or nm(m)
        handlers[m] = describe_handler(core_cls, cone_handler.get(m), base)
    n_live = sum(1 for m in union if handlers[m]["attr_resolves_live"])
    P("   handler attributes resolving live: %d of %d" % (n_live, len(union)))
    for m in union:
        if not handlers[m]["attr_resolves_live"]:
            P("     UNRESOLVED %s (recorded %s)"
              % (m, cone_handler.get(m)))
    P("")

    # -- section 3: the 16L vector kits, as probe-able vectors --------------
    sys.path.insert(0, os.path.join(ROOT, SIXTEEN_L))
    import isa_oracle as O                                       # noqa: E402
    import isa_oracle_scalar as OS                               # noqa: E402
    kit = {}
    for v in O.build_vectors():
        kit.setdefault(nm(v["mnem"]), []).append(
            {"kit": "vector", "name": v["name"], "mnem": v["mnem"],
             "ops": list(v["srcs"]), "dst": v["dst"], "setup": dict(v["setup"])})
    for v in OS.build_scalar_vectors():
        if v["family"] == "addr":
            continue                      # oracle-only reference values
        kit.setdefault(nm(v["mnem"]), []).append(
            {"kit": "scalar", "name": v["name"], "mnem": v["mnem"],
             "ops": list(v["operands"]), "dst": v["operands"][0],
             "setup": dict(v["setup"])})
    nc_e = s1_harness_equivalence(harness, harness_s1)
    P("2b. NC_E HarnessS1 widening is additive: %s" % nc_e["ok"])
    P("    int-valued-setup probes identical through both classes: %d of %d"
      % (sum(1 for x in nc_e["same"] if x["identical"]), len(nc_e["same"])))
    for x in nc_e["widening_needed"]:
        P("    list-valued setup: base class raised %s, S1 class value=%s"
          % (x["base_class_raised"], x["s1_class_value"]))
    P("")
    P("3. probe-able 16L vectors: %d over %d mnemonics"
      % (sum(len(x) for x in kit.values()), len(kit)))
    P("")

    # -- section 4: NC3, the pair read-back ---------------------------------
    scalar_corr = {}
    for v in [x for xs in kit.values() for x in xs if x["kit"] == "scalar"]:
        try:
            got = harness.probe(v)
            orc = OS.eval_scalar({"operands": v["ops"], "setup": v["setup"],
                                  "mnem": v["mnem"], "family": "", "name": ""})
        except Exception as exc:                                 # noqa: BLE001
            got = {"error": "%s: %s" % (type(exc).__name__, exc)}
            orc = {}
        diffs = _obs_diffs(got, orc)
        scalar_corr[v["name"]] = {"mnem": v["mnem"], "dst": v["dst"],
                                  "recomposed_value": got.get("value"),
                                  "recomposed_scc": got.get("scc"),
                                  "recomposed_exec": got.get("exec"),
                                  "oracle_value": orc.get("value"),
                                  "oracle_scc": orc.get("scc"),
                                  "oracle_exec": orc.get("exec"),
                                  "recomposed_agrees": not diffs,
                                  "differences": diffs,
                                  "error": got.get("error")}
    recorded_dis = {r["name"] for r in (s_doc or {}).get("results", [])
                    if not r.get("agree")}
    corrected = [n for n in recorded_dis
                 if scalar_corr.get(n, {}).get("recomposed_agrees")]
    still = [n for n in recorded_dis
             if not scalar_corr.get(n, {}).get("recomposed_agrees")]
    nc3 = {"name": "NC3_pair_readback_is_load_bearing",
           "what": ("re-measure every 16L scalar vector through the composed "
                    "core with a pair-aware destination read-back and compare "
                    "with the recorded 16L harness verdict"),
           "n_scalar_vectors_recomposed": len(scalar_corr),
           "recorded_disagreements": sorted(recorded_dis),
           "changed_to_agree_by_correction": sorted(corrected),
           "still_disagreeing": sorted(still),
           "ok": bool(recorded_dis) and bool(corrected)}
    P("4. NC3 pair read-back: %d scalar vectors recomposed; recorded "
      "disagreements %s; changed to AGREES by the correction %s; still "
      "disagreeing %s" % (nc3["n_scalar_vectors_recomposed"],
                          sorted(recorded_dis), sorted(corrected),
                          sorted(still)))
    P("")

    # -- section 4b: NC4, adjudicating the one disagreeing oracle ------------
    q1_dir = os.path.join(ROOT, os.path.dirname(Q1_ORACLE_REL))
    if q1_dir not in sys.path:
        sys.path.insert(0, q1_dir)
    import q1_oracle as Q1                                        # noqa: E402
    q1_vectors = {v["name"]: v for v in Q1.build_vectors()}
    j3_vec_names = {v["name"] for v in j3c["vector_results"]}
    adj = adjudicate_saveexec(harness, OS, core_cls, Q1, q1_vectors,
                              j3_vec_names)
    P("4b. NC4 refuted-oracle adjudication (single mnemonic, measured)")
    P("   ISA document %s sha256 %s" % (adj["isa_document"]["file"],
                                        adj["isa_document"]["sha256"][:16]))
    P("   B32 blocks found %s, all match %r : %s"
      % (adj.get("isa_b32_blocks_found"),
         adj["isa_document"]["expected_b32_expression"],
         adj.get("isa_b32_expressions_all_match")))
    if "readings" in adj:
        P("   vector %s inputs %s" % (adj["vector"]["name"],
                                      json.dumps(adj["vector"]["inputs"])))
        P("   readings: ISA %s  legacy %s  differ=%s (%d bit(s))"
          % (adj["readings"]["isa_S0_and_not_exec"],
             adj["readings"]["legacy_exec_and_not_S0"],
             adj["readings"]["readings_differ"],
             adj["readings"]["differing_bits"]))
        P("   live emulator  exec=%s dst=%s"
          % (adj["emulator_live"]["exec"], adj["emulator_live"]["dst"]))
        P("   Q1 oracle      exec=%s" % adj["q1_oracle_model"]["exec"])
        P("   16L oracle     exec=%s dst=%s"
          % (adj["sixteen_l_scalar_oracle"]["exec"],
             adj["sixteen_l_scalar_oracle"]["dst"]))
        P("   emulator matches ISA reading %s, legacy reading %s"
          % (adj["emulator_matches_isa_reading"],
             adj["emulator_matches_legacy_reading"]))
        P("   Q1 oracle matches ISA reading %s ; 16L oracle matches legacy "
          "reading %s" % (adj["q1_oracle_matches_isa_reading"],
                          adj["sixteen_l_oracle_matches_legacy_reading"]))
        P("   known-bad: %s" % json.dumps(adj["known_bad"]))
    P("   ADJUDICATED: %s refuted=%s"
      % (adj["ok"], sorted((adj.get("refuted") or {}).keys())))
    if adj.get("error"):
        P("   error: %s" % adj["error"])
    P("")

    # -- section 5: evidence join -------------------------------------------
    evid = collections.defaultdict(lambda: {"vectors": [], "comparisons": 0,
                                            "mismatches": 0, "suites": set()})
    for r in j3c["vector_results"]:
        d = evid[nm(r["mnem"])]
        d["vectors"].append({"suite": "J3_CONFORMANCE/" + str(r["oracle"]),
                             "name": r["name"],
                             "comparisons": r["comparisons"],
                             "agree": r["mismatches"] == 0,
                             "mismatches": r["mismatches"],
                             "handler_from": None})
        d["comparisons"] += r["comparisons"]
        d["mismatches"] += r["mismatches"]
        d["suites"].add("J3_CONFORMANCE")
    # the live recheck NC4 performed: the same Q1 model on the live emulator,
    # measured in THIS run rather than quoted from the 16Q artifact.
    if adj.get("readings"):
        live_agree = (adj["emulator_matches_isa_reading"]
                      and adj["q1_oracle_matches_isa_reading"])
        d = evid[nm(adj["mnemonic"])]
        d["vectors"].append({"suite": "Q1_ORACLE_LIVE_RECHECK",
                             "name": adj["vector"]["name"],
                             "comparisons": 2, "agree": bool(live_agree),
                             "mismatches": 0 if live_agree else 2,
                             "handler_from": "BothCore (MRO)"})
        d["comparisons"] += 2
        if not live_agree:
            d["mismatches"] += 2
        d["suites"].add("Q1_ORACLE_LIVE_RECHECK")
    for suite, doc in (("16L_ISA_VECTOR_ORACLE", v_doc),
                       ("16L_ISA_SCALAR_ORACLE", s_doc)):
        for r in (doc or {}).get("results", []):
            d = evid[nm(r["mnem"])]
            o = r.get("oracle") or {}
            n_cmp = 1 + sum(1 for k in ("scc", "exec", "value")
                            if o.get(k) is not None)
            if suite == "16L_ISA_SCALAR_ORACLE" and r["name"] in scalar_corr:
                agree = scalar_corr[r["name"]]["recomposed_agrees"]
            elif "agree" in r:
                agree = bool(r["agree"])
            else:
                agree = (r.get("error") is None and
                         not r.get("disagreements") and
                         r.get("oracle") == r.get("emulator"))
            d["vectors"].append({"suite": suite, "name": r["name"],
                                 "comparisons": n_cmp, "agree": bool(agree),
                                 "mismatches": 0 if agree else n_cmp,
                                 "handler_from": (r.get("emulator") or {})
                                 .get("handler_from")})
            d["comparisons"] += n_cmp
            if not agree:
                d["mismatches"] += n_cmp
            d["suites"].add(suite)
    # 16S: the S1 independent ISA oracle suite, measured in THIS run through
    # the same `Harness.probe` path, the file supplying expectations only.
    s1_kit, s1_doc, s1_sha = load_s1_suite()
    evid_s1 = {}
    if s1_kit:
        evid_s1 = s1_evidence(s1_kit, harness_s1)
        for mnem, e in evid_s1.items():
            d = evid[mnem]
            d["vectors"].extend(e["vectors"])
            d["comparisons"] += e["comparisons"]
            d["mismatches"] += e["mismatches"]
            d["suites"].update(e["suites"])
            d["s1"] = True
        P("5b. S1 oracle suite joined: %d vectors over %d mnemonics, "
          "%d comparisons, %d disagreeing"
          % (sum(len(e["vectors"]) for e in evid_s1.values()), len(evid_s1),
             sum(e["comparisons"] for e in evid_s1.values()),
             sum(1 for e in evid_s1.values()
                 for v in e["vectors"] if not v["agree"])))
        for mnem in sorted(evid_s1):
            e = evid_s1[mnem]
            P("     %-24s %2d vectors %4d comparisons %2d disagreeing"
              % (mnem, len(e["vectors"]), e["comparisons"],
                 sum(1 for v in e["vectors"] if not v["agree"])))
        P("")
    covered = [m for m in union if evid.get(nm(m), {}).get("comparisons")]
    P("5. evidence join over the %d union-cone mnemonics" % len(union))
    P("   with an independent oracle : %d" % len(covered))
    P("   without one                : %d" % (len(union) - len(covered)))
    for m in sorted(set(union) - set(covered)):
        P("     NO ORACLE %-24s family=%-14s exec=%d handler=%s"
          % (m, next(r["family"] for r in cone["per_mnemonic"]
                     if r["mnemonic"] == m),
             next(r["executions_on_j3_path"] for r in cone["per_mnemonic"]
                  if r["mnemonic"] == m),
             cone_handler.get(m)))
    P("")

    # -- section 6: rows + per-mnemonic mutation ----------------------------
    rows = build_rows(cone, evid, handlers, aliases, r9.get("verdict"), adj)
    mut_suite = _suite_mutation_index(j3c)
    n_measured = 0
    for row in rows:
        if row["nodes_in_union_cone"] == 0:
            continue
        m = row["mnemonic"]
        det = mut_suite.get(nm(m))
        if det:
            row["detecting_mutation"] = det["mutation"]
            row["mutation_effect_observed"] = det["mutation_effect_observed"]
            row["mutation_rejected"] = det["mutation_rejected"]
            row["mutation_source"] = "recorded J3/M2 mutation table"
            continue
        s1v = (s1_kit or {}).get(nm(m)) or []
        vectors = s1v if s1v else kit.get(nm(m))
        attr = (row["handler_live"] or {}).get("attr")
        if not vectors or not attr:
            row["mutation_effect_observed"] = False
            row["mutation_rejected"] = False
            row["mutation_source"] = "none available"
            continue
        rec = measured_mutation(harness_s1 if s1v else harness, core_cls,
                                attr, vectors,
                                S1_MUTATION_SHAPES if s1v else None)
        n_measured += 1
        row["mutation_source"] = ("measured here on the MRO-resolved handler"
                                  + (" (S1 suite)" if s1v else ""))
        if rec:
            row["detecting_mutation"] = rec["mutation"]
            row["mutation_effect_observed"] = rec["mutation_effect_observed"]
            row["mutation_rejected"] = rec["mutation_rejected"]
            row["mutation_measurement"] = rec
        else:
            row["mutation_effect_observed"] = False
            row["mutation_rejected"] = False
    # 16S rule: a row that rests on the S1 suite is VERIFIED only when the
    # oracle OBSERVED the mnemonic, the emulator AGREED on at least one vector,
    # AND a detecting mutation was measured.  Without the mutation the row is
    # demoted, with the reason recorded -- the bar is not lowered to reach 0.
    demoted = []
    for row in rows:
        e = evid.get(nm(row["mnemonic"])) or {}
        s1_hit = any(v["suite"] == "S1_ISA_ORACLE"
                     for v in e.get("vectors", []))
        row["s1_suite_observed"] = bool(s1_hit)
        row["s1_agreeing_vectors"] = sum(
            1 for v in e.get("vectors", [])
            if v["suite"] == "S1_ISA_ORACLE" and v.get("agree"))
        if (s1_hit and row["status"] == "VERIFIED_INDEPENDENTLY"
                and not row["mutation_rejected"]):
            row["status"] = "BLOCKED"
            row["blocked_reason"] = ("NO_DETECTING_MUTATION_FOR_THE_"
                                     "INDEPENDENT_ORACLE")
            row["verification_basis"] += (
                " ; DEMOTED from VERIFIED_INDEPENDENTLY: no mutation of the "
                "MRO-resolved handler changed any observation")
            demoted.append(row["mnemonic"])
    if demoted:
        P("   DEMOTED (no detecting mutation) : %s" % sorted(demoted))
    # rows whose status rests on an adjudicated oracle carry the measurement
    for row in rows:
        ref = (adj.get("refuted") or {}).get(nm(row["mnemonic"]))
        if ref:
            row["refuted_oracle_evidence"] = ref
    P("6. per-mnemonic negative controls")
    P("   mutations measured here              : %d" % n_measured)
    P("   mnemonics with mutation_rejected True: %d"
      % sum(1 for r in rows if r["mutation_rejected"]))
    P("   mnemonics with effect_observed False : %d"
      % sum(1 for r in rows if r["mutation_effect_observed"] is False
            and r["nodes_in_union_cone"]))
    P("")

    # -- section 7: statuses ------------------------------------------------
    counts = collections.Counter(r["status"] for r in rows)
    blocked = [r["mnemonic"] for r in rows if r["status"] == "BLOCKED"]
    P("7. statuses over the %d union-cone mnemonics" % len(rows))
    for s in STATUSES:
        P("   %-30s %d" % (s, counts.get(s, 0)))
    P("   J3_INSTRUCTION_SEMANTICS_BLOCKED = %d" % len(blocked))
    for m in blocked:
        r = next(x for x in rows if x["mnemonic"] == m)
        P("     BLOCKED %-24s %s" % (m, r["blocked_reason"]))
    P("")

    # -- section 8: NC1, the classifier must be able to fail ----------------
    nc1 = {"name": "NC1_classifier_is_falsifiable",
           "what": ("run the SAME classifier over deliberately corrupted "
                    "evidence and show the statuses change"),
           "cases": [], "bounded_adjudication": [], "ok": False}

    def _corrupt_all():
        return {k: {"vectors": [dict(x) for x in v["vectors"]],
                    "comparisons": v["comparisons"],
                    "mismatches": v["comparisons"],
                    "suites": set(v["suites"])}
                for k, v in evid.items()}

    def _mark_disagreeing(store, mnem, skip_suite=None):
        for vec in store[nm(mnem)]["vectors"]:
            if skip_suite and vec["suite"] == skip_suite:
                continue
            vec["agree"] = False
            vec["mismatches"] = vec["comparisons"]

    victims = [r["mnemonic"] for r in rows
               if r["status"] == "VERIFIED_INDEPENDENTLY"][:3]
    for victim in victims:
        corrupt = _corrupt_all()
        for vec in corrupt[nm(victim)]["vectors"]:
            vec["agree"] = False
        row = next(x for x in rows if x["mnemonic"] == victim)
        st, basis, why = classify(row, corrupt, r9.get("verdict"), adj)
        nc1["cases"].append({"corruption": "every comparison of %s marked "
                             "disagreeing" % victim, "was": row["status"],
                             "now": st, "reason": why,
                             "changed": st != row["status"]})
    nc1["ok"] = bool(nc1["cases"]) and all(c["changed"] for c in nc1["cases"])

    # The adjudication must not be a blanket excuse: corrupting the evidence
    # of every suite EXCEPT the refuted one must still convict.
    for mnem, ref in sorted((adj.get("refuted") or {}).items()):
        row = next((x for x in rows if nm(x["mnemonic"]) == mnem), None)
        if row is None:
            continue
        corrupt = _corrupt_all()
        _mark_disagreeing(corrupt, mnem, skip_suite=ref["suite"])
        st, basis, why = classify(row, corrupt, r9.get("verdict"), adj)
        nc1["bounded_adjudication"].append({
            "mnemonic": mnem, "refuted_suite": ref["suite"],
            "corruption": ("every comparison NOT from the refuted suite "
                           "marked disagreeing"),
            "was": row["status"], "now": st, "reason": why,
            "changed": st != row["status"]})
    if nc1["bounded_adjudication"]:
        nc1["ok"] = nc1["ok"] and all(c["changed"]
                                      for c in nc1["bounded_adjudication"])
    P("8. NC1 classifier falsifiability: %s" % nc1["ok"])
    for c in nc1["cases"]:
        P("   %s -> %s (%s) changed=%s" % (c["was"], c["now"], c["reason"],
                                           c["changed"]))
    for c in nc1["bounded_adjudication"]:
        P("   adjudication bounded (%s): %s -> %s changed=%s"
          % (c["mnemonic"], c["was"], c["now"], c["changed"]))
    P("")

    # -- section 9: verdict + artifact --------------------------------------
    verdict = "BLOCKED_J3_INSTRUCTION_SEMANTICS" if blocked else "PASS"
    audit = finalize_audit()
    doc = {
        "schema": "phase16s-j3-instruction-conformance/1",
        "phase": "16S",
        "requirement": "S1 (R11 integration)",
        "copy_provenance": {
            "copy_of": "phase16r/isa/tools/r11_j3_matrix.py",
            "copy_of_sha256": sha256_file(os.path.join(
                ROOT, "phase16r/isa/tools/r11_j3_matrix.py")),
            "the_16r_artifact": "phase16r/isa/J3_INSTRUCTION_CONFORMANCE.json",
            "the_16r_tool_and_artifact_were_not_modified": True,
        },
        "host_only": True,
        "gpu_execution_performed": False,
        "gta_launched": False,
        "currently_armed": False,
        "what": ("instruction-level J3 conformance matrix over the actual J3 "
                 "output-cone record: one row per mnemonic with the recorded "
                 "cone counts, the live MRO-resolved handler, every "
                 "independent oracle that observes it, and a measured "
                 "per-mnemonic negative control.  Phase 16S adds the S1 "
                 "instruction-level oracle suite for the sixteen mnemonics for "
                 "which 16R found no oracle at all."),
        "verdict": verdict,
        "J3_INSTRUCTION_SEMANTICS_BLOCKED": len(blocked),
        "blocked_mnemonics": blocked,
        "status_counts": dict(counts),
        "allowed_statuses": list(STATUSES),
        "statuses_outside_the_allowed_set": sorted(
            {r["status"] for r in rows} - set(STATUSES)),
        "sources": {
            "cone_record": CONE_REL,
            "j3_conformance": J3C_REL,
            "dependency_status": DEPSTAT_REL,
            "r9_division": R9_REL,
            "n7_replay": N7REPLAY_REL,
            "alias_table": ALIAS_REL,
            "oracle_s1": {
                "path": S1_ORACLE_REL, "sha256": s1_sha,
                "loaded": bool(s1_doc),
                "supplied_by": "the S1 independent oracle (oracle16.py); it "
                               "supplies EXPECTED values only -- every "
                               "emulator-side observation of this suite is "
                               "Harness.probe's, measured in this run",
                "host_only": (s1_doc or {}).get("host_only"),
                "gpu_execution_performed":
                    (s1_doc or {}).get("gpu_execution_performed"),
                "tool": "phase16s/isa/tools/r11_j3_matrix_16s.py",
            },
            "oracle_16l_vector": v_rec,
            "oracle_16l_scalar": s_rec,
            "oracle_q1": {"path": Q1_ORACLE_REL,
                          "sha256": sha256_file(os.path.join(ROOT,
                                                             Q1_ORACLE_REL)),
                          "used_by": "NC4 only, on the one vector it defines "
                                     "for s_andn2_saveexec_b32"},
            "isa_text": {"path": ISA_TEXT_REL,
                         "sha256": adj["isa_document"]["sha256"],
                         "used_by": "NC4 only, to read the B32 saveexec "
                                    "reading out of the document"},
            "upstream_dependency_claim": {
                "file": DEPSTAT_REL,
                "OUTPUT_DEPENDENCY_UNVERIFIED":
                    depstat.get("OUTPUT_DEPENDENCY_UNVERIFIED"),
                "measured_over": "FAMILIES",
                "note": ("that claim is not contradicted here; it is coarser "
                         "than this matrix, which is per mnemonic"),
            },
        },
        "handler_resolution_context": {
            "instantiated_class": core_cls.__name__,
            "MRO": [c.__name__ for c in core_cls.__mro__],
            "resolved_live_here": True,
            "n_union_cone_handlers_resolving": n_live,
            "why": ("the runner instantiates this class; every row's handler "
                    "owner is resolved on it, so a method shadowed higher in "
                    "the MRO cannot be patched by mistake"),
        },
        "cone_record_identity": {
            "trace": cone.get("trace"),
            "store_sites": len(cone.get("store_sites") or {}),
            "n_executed_mnemonics": len(cone["per_mnemonic"]),
            "n_union_cone_mnemonics": len(union),
            "union_cone_n_nodes": cone["cones"]["union"]["n_nodes"],
            "value_cone_n_nodes": cone["cones"]["value"]["n_nodes"],
        },
        "oracle_coverage": {
            "M2_suite_is_subset_of_J3_suite": superset,
            "M2_vectors": len(m2_names),
            "M2_comparisons": n7rep["n_comparisons"],
            "M2_disagreeing": n7rep["n_disagreeing"],
            "J3_vectors": j3c["cases"],
            "J3_comparisons": j3c["comparisons"],
            "J3_failures": j3c["failures"],
            "16L_vector_vectors": (v_doc or {}).get("n_vectors"),
            "16L_vector_agree": (v_doc or {}).get("n_agree"),
            "16L_scalar_vectors": (s_doc or {}).get("n_vectors"),
            "16L_scalar_agree": (s_doc or {}).get("n_agree"),
            "16L_scalar_disagree_recorded": (s_doc or {}).get("n_disagree"),
            "16L_scalar_recomposed": scalar_corr,
            "uncovered_by_any_oracle": sorted(set(union) - set(covered)),
        },
        "s1_integration": {
            "tool": ("phase16s/isa/tools/r11_j3_matrix_16s.py -- a copy of the "
                     "16R tool; the 16R tool is neither imported nor edited"),
            "suite": "S1_ISA_ORACLE",
            "oracle_path": S1_ORACLE_REL,
            "oracle_sha256": s1_sha,
            "n_vectors": sum(len(e["vectors"]) for e in evid_s1.values()),
            "n_comparisons": sum(e["comparisons"] for e in evid_s1.values()),
            "n_mnemonics": len(evid_s1),
            "harness": ("the tool's own Harness.probe, reached through "
                        "HarnessS1, whose two widenings are additive and whose "
                        "additivity NC_E measures"),
            "harness_equivalence": nc_e,
            "demoted_for_no_detecting_mutation": sorted(demoted),
            "per_mnemonic": {
                m: {
                    "oracle_vectors": len(e["vectors"]),
                    "comparisons": e["comparisons"],
                    "disagreements": sum(1 for v in e["vectors"]
                                         if not v["agree"]),
                    "agreeing_vectors": sum(1 for v in e["vectors"]
                                            if v["agree"]),
                    "status_in_the_matrix": next(
                        r["status"] for r in rows if nm(r["mnemonic"]) == m),
                    "blocked_reason": next(
                        r["blocked_reason"] for r in rows
                        if nm(r["mnemonic"]) == m),
                    "detecting_mutation": next(
                        r["detecting_mutation"] for r in rows
                        if nm(r["mnemonic"]) == m),
                    "mutation_rejected": next(
                        r["mutation_rejected"] for r in rows
                        if nm(r["mnemonic"]) == m),
                    "open_questions": (
                        ((s1_doc or {}).get("per_mnemonic", {}) or {}).get(
                            next(r["mnemonic"] for r in rows
                                 if nm(r["mnemonic"]) == m), {}) or {}
                    ).get("open_questions"),
                    "disagreeing_vectors": [
                        {"name": v["name"], "diffs": v["diffs"],
                         "expect": v["expect"], "measured": v["measured"],
                         "alt": v["alt"],
                         "matches_alternate_reading":
                             v["matches_alternate_reading"],
                         "note": v["note"], "source": v["source"]}
                        for v in e["vectors"] if not v["agree"]],
                } for m, e in sorted(evid_s1.items())},
        },
        "defect_findings": (s1_doc or {}).get("defect_findings") or [],
        "negative_controls": {"NC1_classifier": nc1, "NC3_pair_readback": nc3,
                              "NC4_refuted_oracle": adj,
                              "NC_E_harness_s1": nc_e},
        "refuted_oracles": adj.get("refuted") or {},
        "write_scope": audit,
        "rows": rows,
        "what_is_measured_vs_inferred": {
            "MEASURED": [
                "every row column is read from a recorded artifact or measured "
                "in this run with the command recorded in `sources`",
                "the handler owner and the MRO definers of each row are "
                "resolved LIVE on the class the runner instantiates (BothCore)",
                "the per-mnemonic mutation columns come from a patch of the "
                "MRO-resolved handler with invocation counts and a before/after "
                "observation delta, or from the recorded J3/M2 mutation table",
                "the two 16L oracle suites are re-run by this tool",
                "NC1 shows the classifier changing a status under corrupted "
                "evidence, and refusing to be excused by the adjudication "
                "when evidence outside the refuted suite is corrupted; NC3 "
                "shows the pair read-back correction changing a recorded "
                "observation; NC4 shows the one disagreeing oracle computing "
                "the reading the ISA document refutes, on a vector measured "
                "to separate the two readings",
            ],
            "DESIGNED": [
                "the four-value status vocabulary is the brief's",
                "a mutation counts as a negative control only when it is "
                "observed to change at least one observation",
                "the nondiscriminating probe inside NC4 is constructed here "
                "to show a vector that cannot separate two readings cannot "
                "reject the known-bad between them; it is a demonstration, "
                "not an oracle vector",
            ],
            "INFERRED": [
                "that an instruction is NOT verified by its family's vectors is "
                "an inference about what an oracle vector observes, and is why "
                "family-only mnemonics are BLOCKED",
                "cone membership is treated as an upper bound: the cone is a "
                "lane-collapsed over-approximation, so a node does not prove "
                "the value reached a store",
            ],
            "NOT_CLAIMED": [
                "no GPU execution, no HIP call, no physical validation",
                "BLOCKED means no independent observation was found, NOT that "
                "the emulator is wrong",
                "the NC4 adjudication covers ONE mnemonic and says nothing "
                "about the emulator anywhere else; the other mnemonics on "
                "which the 16L scalar oracle computes a refuted reading "
                "(s_orn2_saveexec_b32, s_nand_b32, s_xnor_b32) are not on the "
                "J3 output cone, so they carry no status here either way",
            ],
        },
    }

    out_abs = os.path.join(ROOT, OUT_REL)
    with open(out_abs, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
    with open(out_abs, encoding="utf-8") as fh:
        back = json.load(fh)
    read_back = {
        "path": OUT_REL,
        "sha256": sha256_file(out_abs),
        "verdict_matches": back["verdict"] == verdict,
        "n_rows_matches": len(back["rows"]) == len(rows),
        "blocked_matches": back["J3_INSTRUCTION_SEMANTICS_BLOCKED"] == len(blocked),
        "statuses_are_permitted": all(r["status"] in STATUSES
                                      for r in back["rows"]),
        "unpermitted_statuses": sorted({r["status"] for r in back["rows"]}
                                       - set(STATUSES)),
        "every_row_has_a_status": all(r["status"] in STATUSES
                                      for r in back["rows"]),
    }
    P("9. artifact read back: %s" % json.dumps(read_back))
    P("")
    P("TOP-LEVEL VERDICT: %s" % verdict)
    P("J3_INSTRUCTION_SEMANTICS_BLOCKED = %d" % len(blocked))
    P("statuses: %s" % dict(counts))
    P("write intents outside phase16s/isa: %d, state-changing: %d"
      % (audit["n_write_intents_outside"], audit["n_state_changing_outside"]))
    P("wrote %s" % OUT_REL)

    with open(os.path.join(ROOT, LOG_REL), "w", encoding="utf-8") as fh:
        fh.write("\n".join(LOG) + "\n")
    return 0 if (read_back["verdict_matches"] and read_back["n_rows_matches"]
                 and read_back["blocked_matches"]
                 and read_back["statuses_are_permitted"]) else 1


# ---------------------------------------------------------------------------
# lookups
# ---------------------------------------------------------------------------
def _suite_mutation_index(j3c):
    """mnemonic -> a recorded-suite mutation it detects.

    Attributed only when at least one vector the mutation CHANGED is a vector
    of that mnemonic -- a recorded measurement, not a guess from the name.
    """
    vec_mnem = {v["name"]: nm(v["mnem"]) for v in j3c["vector_results"]}
    out = {}
    for mut in j3c.get("mutations") or []:
        if not mut.get("mutation_rejected"):
            continue
        for name in mut.get("first") or []:
            m = vec_mnem.get(name)
            if m and m not in out:
                out[m] = {"mutation": mut["name"],
                          "mutation_effect_observed":
                              bool(mut.get("mutation_effect_observed")),
                          "mutation_rejected": bool(mut.get("mutation_rejected"))}
    return out


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:                                            # noqa: BLE001
        traceback.print_exc()
        sys.exit(2)
