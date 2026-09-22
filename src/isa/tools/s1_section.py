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


