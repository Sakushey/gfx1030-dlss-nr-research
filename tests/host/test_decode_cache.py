"""Semantic-regression guards for the issue #5 emulator decode/recorder caches.

The optimization pre-computes mnemonic/operand tokens onto each instruction
and memoizes ``ds_form``.  These tests keep it honest: every cached read is
compared against the uncached computation, and the invalidation path that
rewrites operands after the first decode is pinned so a stale cache cannot
silently change execution.
"""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the import namespace)

import emu
import p14e_emu
import p14eh
from p16k_recorder import AccessRecorder


def _uncached_decode(ins):
    """The pre-optimization decode, recomputed independently here."""
    mnem = ins["mnemonic"].replace("_e32", "").replace("_e64", "")
    operands = ins.get("operands") or ""
    ops = [o.strip() for o in operands.split(",")] if operands else []
    if mnem.startswith("v_dual_"):
        mnem = "v_" + mnem[len("v_dual_"):]
    return mnem, ops


class TestInstructionDecodeCache(unittest.TestCase):
    def test_cached_tokens_match_uncached_for_plain_instruction(self):
        ins = {"mnemonic": "v_mov_b32", "operands": "v1, v2"}
        expected_mnem, expected_ops = _uncached_decode(ins)

        emu.prep_instruction_decode(ins)

        self.assertEqual(ins["_mnem"], expected_mnem)
        self.assertEqual(ins["_ops"], expected_ops)

    def test_cached_tokens_match_uncached_for_e32_and_e64_suffixes(self):
        for mnemonic in ("v_mov_e32", "v_mov_e64", "v_add_f32_e32"):
            with self.subTest(mnemonic=mnemonic):
                ins = {"mnemonic": mnemonic, "operands": "v1, v2"}
                expected_mnem, expected_ops = _uncached_decode(ins)

                emu.prep_instruction_decode(ins)

                self.assertEqual(ins["_mnem"], expected_mnem)
                self.assertEqual(ins["_ops"], expected_ops)

    def test_v_dual_is_normalized_once(self):
        ins = {"mnemonic": "v_dual_add_f32", "operands": "v1, v2"}
        expected_mnem, expected_ops = _uncached_decode(ins)
        self.assertEqual(expected_mnem, "v_add_f32")

        emu.prep_instruction_decode(ins)

        self.assertEqual(ins["_mnem"], "v_add_f32")
        self.assertEqual(ins["_ops"], expected_ops)
        # Re-prepping must not strip the prefix twice.
        emu.prep_instruction_decode(ins)
        self.assertEqual(ins["_mnem"], "v_add_f32")

    def test_operand_tokens_match_uncached_whitespace_normalization(self):
        ins = {"mnemonic": "v_mov_b32", "operands": "  v1 ,  v2 , v3  "}
        expected_mnem, expected_ops = _uncached_decode(ins)

        emu.prep_instruction_decode(ins)

        self.assertEqual(ins["_ops"], expected_ops)
        self.assertEqual(ins["_ops"], ["v1", "v2", "v3"])

    def test_empty_operands_tokenize_to_an_empty_list(self):
        ins = {"mnemonic": "s_endpgm", "operands": ""}
        expected_mnem, expected_ops = _uncached_decode(ins)

        emu.prep_instruction_decode(ins)

        self.assertEqual(ins["_ops"], expected_ops)
        self.assertEqual(ins["_ops"], [])

    def test_build_orig_program_prepares_every_instruction(self):
        rows = [
            {"address": 0x100, "mnemonic": "v_dual_add_f32", "operands": "v1, v2"},
            {"address": 0x104, "mnemonic": "v_mov_b32_e32", "operands": "v3, v4"},
        ]

        prog = emu.build_orig_program(rows)

        for ins in prog:
            self.assertIn("_mnem", ins)
            self.assertIn("_ops", ins)
            self.assertEqual(ins["_mnem"], _uncached_decode(ins)[0])
            self.assertEqual(ins["_ops"], _uncached_decode(ins)[1])


class TestFloatNormInvalidation(unittest.TestCase):
    def test_norm_float_ops_reecodes_operand_tokens(self):
        prog = [{"mnemonic": "v_add_f32", "operands": "v1, 0.5"}]
        emu.prep_program_decode(prog)
        self.assertEqual(prog[0]["_ops"], ["v1", "0.5"])

        changed = p14e_emu._norm_float_ops(prog)

        self.assertTrue(changed)
        self.assertEqual(prog[0]["operands"], "v1, 0x3f000000")
        # The cached tokens must be the rewritten ones, not the stale first decode.
        self.assertEqual(prog[0]["_ops"], ["v1", "0x3f000000"])
        self.assertIn("_mnem", prog[0])
        self.assertEqual(prog[0]["_mnem"], "v_add_f32")

    def test_norm_float_ops_leaves_ordinary_instructions_alone(self):
        prog = [{"mnemonic": "v_mov_b32", "operands": "v1, v2"}]
        emu.prep_program_decode(prog)

        changed = p14e_emu._norm_float_ops(prog)

        self.assertFalse(changed)
        self.assertEqual(prog[0]["_ops"], ["v1", "v2"])
        self.assertEqual(prog[0]["_mnem"], "v_mov_b32")


class TestDsFormCache(unittest.TestCase):
    def test_repeated_calls_return_an_identical_descriptor(self):
        first = p14eh.ds_form("ds_read_b32", "v1, v2 offset:4")
        second = p14eh.ds_form("ds_read_b32", "v1, v2 offset:4")

        self.assertEqual(first, second)
        self.assertGreaterEqual(p14eh.ds_form.cache_info().hits, 1)

    def test_distinct_operands_stay_distinct(self):
        first = p14eh.ds_form("ds_read_b32", "v1, v2 offset:4")
        second = p14eh.ds_form("ds_read_b32", "v1, v2 offset:8")

        self.assertNotEqual(first, second)


class TestRecorderSummaryCompat(unittest.TestCase):
    def test_summary_formats_by_pc_keys_like_before_the_cache(self):
        rec = AccessRecorder()
        rec.append((False, 0x1000, 4, 0xAB), opcode="ds_read_b32")
        rec.append((True, 0x1004, 4, 0xAB), opcode="ds_write_b32")
        rec.append((False, 0x1008, 4, 0xAB), opcode="ds_read_b32")

        summary = rec.summary()

        self.assertEqual(summary["by_pc"], {"0x000000AB": 3})
        self.assertEqual(summary["by_opcode"], {"ds_read_b32": 2, "ds_write_b32": 1})
        self.assertEqual(summary["n_distinct_pcs"], 1)
        self.assertEqual(summary["n"], 3)

    def test_missing_site_still_uses_the_zero_key(self):
        rec = AccessRecorder()
        rec.append((False, 0x2000, 4, None))

        self.assertEqual(rec.summary()["by_pc"], {"0x00000000": 1})


if __name__ == "__main__":
    unittest.main()
