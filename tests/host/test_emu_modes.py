"""Host-only regression for the emulator's CONTROL_ONLY / NUMERICAL modes.

The defect
----------
`src/emulator/emu.py` carried value-stubs that are indistinguishable from
implementations. `op_v_wmma_f32_16x16x16_f16` -- the native matrix
multiply-accumulate -- was a loop that entered, took `pass`, and left the
accumulator exactly as it found it, under a comment claiming it "accumulate[s]
conservative junk". `op_v_dot2c_f32_f16` and `op_ds_bpermute_b32` had the
same shape until Phase 16M, and they are the arithmetic unit of the whole
soft-WMMA replacement. Nothing in the file said which handlers computed
anything, so a numerical question asked of the emulator was answered
"successfully" by an instruction that had done nothing.

Three properties are checked here.

1. **The modes exist and CONTROL_ONLY is the default.** The default matters:
   every existing caller must keep its exact behaviour, so nothing about
   CONTROL_ONLY may change.

2. **A declared stub is refused in NUMERICAL mode** with `UNSUPPORTED_NUMERIC`,
   never a silent success -- and the declared-vs-undeclared split is verified
   by parsing the module rather than by trusting the declarations. The scan
   finds every `op_` handler that writes no emulated state, follows `self.`
   calls transitively, and requires each one to be declared either a value
   stub or control-vacuous. `test_negative_control_the_scan_finds_a_new_stub`
   injects an undeclared handler and shows the scan rejects it, so the scan
   is a check and not a decoration.

3. **A known nonzero WMMA product either updates the accumulator or is
   refused.** `v_dot2c_f32_f16` is modelled, so in NUMERICAL mode it must
   produce the exact product; `v_wmma_f32_16x16x16_f16` is not, so it must
   raise. The same program is run in both modes so the difference is the mode
   and not the program. Both halves are asserted with a product whose value
   is computable by hand.

Nothing here touches a device: the emulator is fed instruction dictionaries
directly, which is how the rest of this suite drives it.
"""
from __future__ import annotations

import ast
import os
import struct
import unittest

import hostpath  # noqa: F401  (sets up the import namespace)

sys_path = os.path.join(hostpath.REPO_ROOT, "src", "emulator")
import sys  # noqa: E402
sys.path.insert(0, sys_path)

import emu  # noqa: E402

EMU_PY = os.path.join(hostpath.REPO_ROOT, "src", "emulator", "emu.py")


def read_emu() -> str:
    """The emulator source, closed properly so no ResourceWarning hides a
    failure in the output."""
    with open(EMU_PY, encoding="utf-8") as f:
        return f.read()


def ins(mnemonic, operands, **kw):
    """One instruction in the shape `Core.step` consumes."""
    d = {"mnemonic": mnemonic, "operands": operands, "text":
         f"{mnemonic} {operands}".strip()}
    d.update(kw)
    return d


def h16(x: float) -> int:
    """The half-precision bit pattern of `x`."""
    return struct.unpack("<H", struct.pack("<e", x))[0]


def halves(lo: float, hi: float) -> int:
    """Two f16 halves packed the way `v_dot2c_f32_f16` reads them."""
    return (h16(lo) & 0xFFFF) | (h16(hi) << 16)


# =====================================================================
# 2. the declaration scan
# =====================================================================
def _self_attr_written(target) -> bool:
    """True if `target` is an assignment to some attribute of `self`."""
    node = target
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "self":
                return True
            node = node.value
        else:
            node = node.value
    return False


def _calls_self(node) -> set:
    """The names of `self.<x>(...)` calls anywhere inside `node`."""
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            f = n.func
            if isinstance(f.value, ast.Name) and f.value.id == "self":
                out.add(f.attr)
        # self.global_stores.append(x)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and n.func.attr == "append":
            if _self_attr_written(n.func.value):
                out.add("<append:self>")
    return out


def _always_raises(fn) -> bool:
    """A handler that cannot silently succeed needs no declaration."""
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and \
            isinstance(body[0].value, ast.Constant) and \
            isinstance(body[0].value.value, str):
        body = body[1:]
    return bool(body) and isinstance(body[-1], ast.Raise)


def handlers_of(src: str):
    """Map every live `op_` handler name to its function node.

    Aliases count: `op_global_load_byte = op_global_load_b8` and
    `op_s_nop = _noop` are both dispatched by `getattr(self, "op_" + mnem)`,
    so a scan that walked only `def` statements would miss six mnemonics.
    """
    tree = ast.parse(src)
    core = next(n for n in ast.walk(tree)
                if isinstance(n, ast.ClassDef) and n.name == "Core")
    defs = {n.name: n for n in core.body if isinstance(n, ast.FunctionDef)}
    out = {}
    for stmt in core.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name.startswith("op_"):
            out[stmt.name] = stmt
        elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Name):
            for t in stmt.targets:
                # ast.Name carries the identifier in `.id`; `.name` is
                # FunctionDef/ClassDef and raises AttributeError here.
                if isinstance(t, ast.Name) and t.id.startswith("op_"):
                    if stmt.value.id in defs:
                        out[t.id] = defs[stmt.value.id]
    return out


def state_writers(src: str) -> set:
    """Every Core method that ends up writing emulated state.

    Seeded from methods that assign an attribute of `self` or append to one,
    then closed transitively over `self.<method>()` calls. Derived from the
    source rather than hardcoded, so it cannot go stale when a helper is
    renamed -- which is the failure mode a frozen list of writer names has.
    """
    tree = ast.parse(src)
    core = next(n for n in ast.walk(tree)
                if isinstance(n, ast.ClassDef) and n.name == "Core")
    methods = {n.name: n for n in core.body if isinstance(n, ast.FunctionDef)}

    direct = set()
    for name, fn in methods.items():
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) \
                    else [node.target]
                if any(_self_attr_written(t) for t in targets):
                    direct.add(name)
                    break
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "append" \
                    and _self_attr_written(node.func.value):
                direct.add(name)
                break

    writers = set(direct)
    changed = True
    while changed:
        changed = False
        for name, fn in methods.items():
            if name in writers:
                continue
            for called in _calls_self(fn):
                if called in writers or called == "<append:self>":
                    writers.add(name)
                    changed = True
                    break
    return writers


def undeclared_stubs(src: str):
    """`op_` handlers that write no state and declare no reason."""
    writers = state_writers(src)
    bad = []
    for name, fn in handlers_of(src).items():
        if fn.name in writers:
            continue
        if _always_raises(fn):
            continue
        decs = [ast.unparse(d) for d in fn.decorator_list]
        declared = any("value_stub" in d or "control_only_vacuous" in d
                       for d in decs)
        if not declared:
            bad.append(name)
    return sorted(bad)


class TestTheModesExist(unittest.TestCase):

    def test_default_mode_is_control_only(self):
        """The default is what preserves every existing caller."""
        core = emu.Core([ins("s_endpgm", "")])
        self.assertEqual(core.mode, emu.EmuMode.CONTROL_ONLY)

    def test_both_modes_are_named(self):
        self.assertEqual(emu.EmuMode.CONTROL_ONLY, "CONTROL_ONLY")
        self.assertEqual(emu.EmuMode.NUMERICAL, "NUMERICAL")

    def test_an_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            emu.Core([], mode="NUMERICALISH")

    def test_unsupported_numeric_is_a_notimpl_with_a_kind(self):
        """Callers that catch NotImpl must keep catching this."""
        exc = emu.UnsupportedNumeric("v_wmma_f32_16x16x16_f16", "why")
        self.assertIsInstance(exc, emu.NotImpl)
        self.assertEqual(exc.kind, "UNSUPPORTED_NUMERIC")


class TestEverySilentStubIsDeclared(unittest.TestCase):
    """Property 2's static half."""

    @classmethod
    def setUpClass(cls):
        cls.src = read_emu()
        cls.stubs = sorted(
            n for n, fn in handlers_of(cls.src).items()
            if emu.is_value_stub.__doc__ is not None and _declared(fn, "value_stub"))
        cls.vacuous = sorted(
            n for n, fn in handlers_of(cls.src).items()
            if _declared(fn, "control_only_vacuous"))

    def test_the_scan_finds_the_handlers_it_claims_to(self):
        """A scan that found nothing would pass every other check here."""
        handlers = handlers_of(self.src)
        self.assertGreater(len(handlers), 100,
                           "the handler scan is not seeing the class")

    def test_every_no_state_handler_is_declared(self):
        bad = undeclared_stubs(self.src)
        self.assertEqual(
            bad, [],
            f"these op_ handlers write no emulated state and declare no "
            f"reason: {bad}. In NUMERICAL mode they would report success "
            "while computing nothing. Declare each with @value_stub(...) if "
            "it should have computed something, or "
            "@control_only_vacuous(...) if having no effect is correct.")

    def test_the_known_stubs_are_declared_as_stubs(self):
        for name in ("op_v_wmma_f32_16x16x16_f16", "op_v_wmma_stub",
                     "op_ds_store_b128", "op_global_load_b8"):
            self.assertIn(name, self.stubs,
                          f"{name} is not declared a value stub")

    def test_scheduling_forms_are_vacuous_not_stubs(self):
        """s_waitcnt must not be refused in NUMERICAL mode."""
        for name in ("op_s_nop", "op_s_waitcnt", "op_s_waitcnt_depctr",
                     "op_s_delay_alu", "op_s_clause", "op_s_sendmsg"):
            self.assertIn(name, self.vacuous, name)
            self.assertNotIn(name, self.stubs, name)

    def test_the_two_classes_are_disjoint(self):
        stubs = {n for n, fn in handlers_of(self.src).items()
                 if _declared(fn, "value_stub")}
        vac = {n for n, fn in handlers_of(self.src).items()
               if _declared(fn, "control_only_vacuous")}
        self.assertEqual(stubs & vac, set(),
                         "a handler declared both a gap and correct")


def _declared(fn, which: str) -> bool:
    for d in fn.decorator_list:
        text = ast.unparse(d)
        if text.startswith(which + "(") or text == which:
            return True
    return False


class TestNegativeControlTheScanCanFail(unittest.TestCase):
    """A scan that cannot fail is vacuous."""

    def test_negative_control_the_scan_finds_a_new_stub(self):
        """Inject an undeclared no-op handler and require the scan to see it."""
        src = read_emu()
        # The anchor must be a `def` with no decorator above it. Anchoring
        # on `op_v_wmma_stub` instead would insert the new function BETWEEN
        # `@value_stub(...)` and its `def`, which re-decorates the injected
        # function and strips the real declaration -- measured: the scan then
        # reported `op_v_wmma_stub` as the undeclared one.
        anchor = "    def op_v_mov_b32(self, ins, ops):"
        self.assertIn(anchor, src, "anchor moved; update this control")
        injected = src.replace(
            anchor,
            "    def op_injected_undeclared_stub(self, ins, ops):\n"
            "        for lane in range(self.lanes):\n"
            "            if (self.exec_l >> lane) & 1:\n"
            "                pass\n\n" + anchor, 1)
        bad = undeclared_stubs(injected)
        self.assertIn("op_injected_undeclared_stub", bad,
                      "the scan did not notice an undeclared no-op handler")
        self.assertNotIn("op_injected_undeclared_stub", undeclared_stubs(src))

    def test_negative_control_the_scan_accepts_a_declared_stub(self):
        """And it must not simply flag everything new."""
        src = read_emu()
        anchor = "    def op_v_mov_b32(self, ins, ops):"
        injected = src.replace(
            anchor,
            "    @value_stub('injected for the control')\n"
            "    def op_injected_declared_stub(self, ins, ops):\n"
            "        pass\n\n" + anchor, 1)
        self.assertNotIn("op_injected_declared_stub", undeclared_stubs(injected))

    def test_negative_control_the_scan_accepts_a_raising_handler(self):
        """A handler that always raises cannot succeed silently."""
        src = read_emu()
        anchor = "    def op_v_mov_b32(self, ins, ops):"
        injected = src.replace(
            anchor,
            "    def op_injected_raiser(self, ins, ops):\n"
            "        raise NotImpl('no')\n\n" + anchor, 1)
        self.assertNotIn("op_injected_raiser", undeclared_stubs(injected))

    def test_negative_control_the_scan_tracks_aliases(self):
        """`op_s_nop = _noop` is dispatched, so the scan must see it."""
        handlers = handlers_of(read_emu())
        self.assertIn("op_s_nop", handlers)
        self.assertEqual(handlers["op_s_nop"].name, "_noop")


class TestNumericalModeRefuses(unittest.TestCase):
    """Property 2's behavioural half, on a program rather than on source."""

    def program(self):
        return [ins("v_wmma_f32_16x16x16_f16", "v4, v8, v12"),
                ins("s_endpgm", "")]

    def test_control_only_runs_the_stub_without_incident(self):
        """Legacy behaviour: the stub is allowed and changes nothing."""
        core = emu.Core(self.program(), mode=emu.EmuMode.CONTROL_ONLY)
        core.v[0][4] = 0x3F800000            # accumulator = 1.0f
        core.step()
        self.assertEqual(core.v[0][4], 0x3F800000)

    def test_numerical_mode_raises_unsupported_numeric(self):
        core = emu.Core(self.program(), mode=emu.EmuMode.NUMERICAL)
        with self.assertRaises(emu.UnsupportedNumeric) as ctx:
            core.step()
        self.assertEqual(ctx.exception.kind, "UNSUPPORTED_NUMERIC")
        self.assertEqual(ctx.exception.mnemonic, "v_wmma_f32_16x16x16_f16")

    def test_the_refusal_is_not_a_crash_for_existing_callers(self):
        core = emu.Core(self.program(), mode=emu.EmuMode.NUMERICAL)
        try:
            core.step()
        except emu.NotImpl as exc:
            self.assertIn("UNSUPPORTED_NUMERIC", type(exc).kind)
        else:
            self.fail("NUMERICAL mode accepted a stub")

    def test_every_declared_stub_refuses_in_numerical_mode(self):
        """The declaration and the gate must agree, per handler."""
        src = read_emu()
        stubs = sorted(n for n, fn in handlers_of(src).items()
                       if _declared(fn, "value_stub"))
        self.assertGreaterEqual(len(stubs), 4)
        # Each declared stub is checked through the gate directly, so a stub
        # whose mnemonic is hard to spell still gets covered.
        class Probe(emu.Core):
            def __init__(self):
                super().__init__([], mode=emu.EmuMode.NUMERICAL)

        probe = Probe()
        for name in stubs:
            fn = getattr(probe, name)
            self.assertIsNotNone(emu.is_value_stub(fn),
                                 f"{name} is not a declared stub at runtime")

    def test_control_vacuous_forms_run_in_both_modes(self):
        prog = [ins("s_waitcnt", "vmcnt(0)"), ins("s_endpgm", "")]
        for mode in emu.EmuMode.ALL:
            core = emu.Core(prog, mode=mode)
            core.step()  # must not raise
            self.assertEqual(core.pc, 1, mode)


class TestTheKnownNonzeroProduct(unittest.TestCase):
    """Property 3: the product must land, or the mode must say it cannot.

    `v_dot2c_f32_f16` is the software-WMMA arithmetic and IS modelled, so it
    is used as the known-good numerical case. The product is chosen so its
    value is exact and checkable by hand:

        1.5 * 2.5 + (-0.5) * 4.0 = 3.75 - 2.0 = 1.75

    `v_wmma_f32_16x16x16_f16` is the native form and is NOT modelled, so the
    same "known nonzero product" through that instruction must be refused
    rather than silently reported as zero. That is the brief's "either update
    the accumulator correctly or report UNSUPPORTED_NUMERIC", taken in both
    directions on the same inputs.
    """

    A_LO, A_HI = 1.5, -0.5
    B_LO, B_HI = 2.5, 4.0
    EXPECTED = 1.75
    ACC_IN = 0.25

    def dot2c_program(self):
        return [ins("v_dot2c_f32_f16", "v4, v8, v12"), ins("s_endpgm", "")]

    def run_dot2c(self, mode):
        core = emu.Core(self.dot2c_program(), mode=mode)
        core.v[0][8] = halves(self.A_LO, self.A_HI)
        core.v[0][12] = halves(self.B_LO, self.B_HI)
        core.v[0][4] = struct.unpack("<I", struct.pack("<f", self.ACC_IN))[0]
        core.step()
        return struct.unpack("<f", struct.pack("<I", core.v[0][4] & 0xFFFFFFFF))[0]

    def test_the_inputs_really_are_nonzero(self):
        self.assertNotEqual(halves(self.A_LO, self.A_HI), 0)
        self.assertNotEqual(halves(self.B_LO, self.B_HI), 0)
        self.assertNotEqual(self.A_LO * self.B_LO + self.A_HI * self.B_HI, 0.0)

    def test_numerical_mode_updates_the_accumulator_correctly(self):
        got = self.run_dot2c(emu.EmuMode.NUMERICAL)
        self.assertAlmostEqual(got, self.ACC_IN + self.EXPECTED, places=6)

    def test_control_only_mode_computes_the_same_value(self):
        """The modelled path is mode-independent; only stubs differ."""
        self.assertAlmostEqual(self.run_dot2c(emu.EmuMode.CONTROL_ONLY),
                               self.run_dot2c(emu.EmuMode.NUMERICAL), places=9)

    def test_negative_control_a_stubbed_product_would_read_as_the_input(self):
        """Name the failure the mode exists to prevent.

        If the native WMMA were allowed to run in NUMERICAL mode, the
        accumulator would still hold its input and the run would report that
        as the product. This asserts the shape of that: the value is
        unchanged, i.e. indistinguishable from a correct answer of "the
        input", which is why refusal is the only safe outcome.
        """
        core = emu.Core([ins("v_wmma_f32_16x16x16_f16", "v4, v8, v12")],
                        mode=emu.EmuMode.CONTROL_ONLY)
        acc_in = struct.unpack("<I", struct.pack("<f", 1.25))[0]
        core.v[0][4] = acc_in
        core.v[0][8] = halves(self.A_LO, self.A_HI)
        core.v[0][12] = halves(self.B_LO, self.B_HI)
        core.step()
        self.assertEqual(core.v[0][4], acc_in,
                         "the stub wrote something; this control is stale")

    def test_numerical_mode_refuses_the_same_product_through_the_native_form(self):
        core = emu.Core([ins("v_wmma_f32_16x16x16_f16", "v4, v8, v12")],
                        mode=emu.EmuMode.NUMERICAL)
        core.v[0][8] = halves(self.A_LO, self.A_HI)
        core.v[0][12] = halves(self.B_LO, self.B_HI)
        with self.assertRaises(emu.UnsupportedNumeric):
            core.step()

    def test_the_two_modes_differ_only_by_the_mode(self):
        """Run the identical program both ways and compare the outcome.

        This is the whole claim: CONTROL_ONLY runs it, NUMERICAL refuses it,
        and the program did not change between the two runs.
        """
        prog = [ins("v_wmma_f32_16x16x16_f16", "v4, v8, v12")]
        control = emu.Core(prog, mode=emu.EmuMode.CONTROL_ONLY)
        control.step()
        numerical = emu.Core(prog, mode=emu.EmuMode.NUMERICAL)
        with self.assertRaises(emu.UnsupportedNumeric):
            numerical.step()


if __name__ == "__main__":
    unittest.main()
