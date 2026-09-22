# S3 / criterion 6 — the compiler sequence is independently shown to be
# intended to implement correctly-rounded binary32 division

**Host-only evidence collection.** No GPU, no HIP, no game, nothing armed.
Retrieved 2026-09-19 from the public LLVM repository. The file is stored
byte-exact under `phase16s/div/ref/`.

## Source

| field | value |
|---|---|
| project | LLVM (`llvm-project`) |
| file | `llvm/lib/Target/AMDGPU/AMDGPULegalizerInfo.cpp` |
| branch | `main` |
| URL | `https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/lib/Target/AMDGPU/AMDGPULegalizerInfo.cpp` |
| bytes | 332,153 |
| sha256 | `29e375e16f6857b9860d10c9afde48fd7602cc51b968d3b0655e3e5f3ce72b10` |
| local copy | `phase16s/div/ref/llvm_AMDGPULegalizerInfo.cpp` |
| excerpt | `phase16s/div/ref/legalizeFDIV32_excerpt.txt` (lines 5758–5840) |
| independence | **independent of the AMD ISA manual prose.** It is compiler source, not a manual restatement. It is a *second* artefact in the same toolchain lineage as the kernel being analysed — that limit is stated below. |

## The function, verbatim

`AMDGPULegalizerInfo::legalizeFDIV32` lowers the *generic* `G_FDIV` for f32.
Its signature is `legalizeFDIV32(MachineInstr &MI, ...)`, and the body takes
`Res = MI.getOperand(0)`, `LHS = MI.getOperand(1)`, `RHS = MI.getOperand(2)` —
so in `fdiv LHS, RHS` the **`LHS` register holds the numerator and `RHS` holds
the denominator**. The body then builds, in order:

```
DenominatorScaled = amdgcn_div_scale(LHS, RHS, 0)
NumeratorScaled   = amdgcn_div_scale(LHS, RHS, 1)
ApproxRcp         = amdgcn_rcp(DenominatorScaled[0])
NegDivScale0      = fneg(DenominatorScaled)
Fma0 = fma(NegDivScale0, ApproxRcp, 1.0)
Fma1 = fma(Fma0,          ApproxRcp, ApproxRcp)
Mul  = fmul(NumeratorScaled, Fma1)
Fma2 = fma(NegDivScale0, Mul,   NumeratorScaled)
Fma3 = fma(Fma2,          Fma1, Mul)
Fma4 = fma(NegDivScale0, Fma3,  NumeratorScaled)
Fmas = amdgcn_div_fmas(Fma4, Fma1, Fma3, NumeratorScaled[1])
        amdgcn_div_fixup(Fmas, RHS, LHS)              // -> Res
```

### The intrinsic's operand contract, from LLVM's own tablegen

`llvm/include/llvm/IR/IntrinsicsAMDGPU.td` (fetched 2026-09-19, same branch):

```
def int_amdgcn_div_scale : PureIntrinsic<
  // 1st parameter: Numerator
  // 2nd parameter: Denominator
  // 3rd parameter: Select quotient. Must equal Numerator or Denominator.
  //                (0 = Denominator, 1 = Numerator).
  [llvm_anyfloat_ty, llvm_i1_ty],
  [LLVMMatchType<0>, LLVMMatchType<0>, llvm_i1_ty],
  [ImmArg<ArgIndex<2>>]
>;
```

So the **1st argument is the numerator and the 2nd the denominator** — which
maps onto the ISA's `S1 = Denominator`, `S2 = Numerator` with the two swapped,
and the 3rd argument (`0 = Denominator`, `1 = Numerator`) selects **which of
the two is returned scaled**, i.e. which one takes the `S0` role:

| LLVM call | numerator arg | denominator arg | 3rd arg | returns | ISA reading | Candidate F |
|---|---|---|---|---|---|---|
| `div_scale(LHS, RHS, 0)` | `LHS` | `RHS` | `0` = Denominator | scaled **denominator** | `S0 = Y`, `S1 = Y`, `S2 = X` | `v_div_scale_f32 v6, null, v5, v5, v3` |
| `div_scale(LHS, RHS, 1)` | `LHS` | `RHS` | `1` = Numerator | scaled **numerator** | `S0 = X`, `S1 = Y`, `S2 = X` | `v_div_scale_f32 v9, vcc_lo, v3, v5, v3` |

**A naming trap worth recording, because it nearly produced a wrong claim
here:** LLVM's local variable names are `DenominatorScaled` for the `addImm(0)`
call and `NumeratorScaled` for the `addImm(1)` call, but the variable named
`NumeratorScaled` is the one built from the **3rd** argument of the intrinsic —
and `_1`/`_0` in `NumeratorScaled.getReg(1)` / `DenominatorScaled.getReg(0)`
are the **result indices** (the value and the condition bit), not operand
indices. Reading the variable names as "LHS is the numerator" would have
inverted the mapping. The tablegen comment is the authority, and the two
assembly lines above are consistent with it.

## The correspondence with Candidate F, instruction for instruction

Candidate F's kernel contains this sequence at e.g. `0x00000000C7AC`
(`phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt` lines 619–630),
where the source-level `LHS`/`RHS` are the registers holding the denominator
(`v5`) and the numerator (`v3`):

| LLVM IR built by `legalizeFDIV32` | Candidate F instruction | LLVM argument → register |
|---|---|---|
| `div_scale(LHS, RHS, 0)` — scale the **denominator** | `v_div_scale_f32 v6, null, v5, v5, v3` | `LHS = v3` = the numerator → `S2 = v3`; `RHS = v5` = the denominator → `S1 = v5`; the returned-scaled operand is the denominator → `S0 = v5` |
| `div_scale(LHS, RHS, 1)` — scale the **numerator** | `v_div_scale_f32 v9, vcc_lo, v3, v5, v3` | same `S1 = v5`, `S2 = v3`; the returned-scaled operand is the numerator → `S0 = v3` |
| `rcp(DenominatorScaled)` | `v_rcp_f32_e32 v7, v6` | — |
| `fma(fneg(DenominatorScaled), ApproxRcp, 1.0)` | `v_fma_f32 v8, -v6, v7, 1.0` | — |
| `fma(Fma0, ApproxRcp, ApproxRcp)` | `v_fmac_f32_e32 v7, v8, v7` | — |
| `fmul(NumeratorScaled, Fma1)` | `v_mul_f32_e32 v8, v9, v7` | — |
| `fma(fneg(DenominatorScaled), Mul, NumeratorScaled)` | `v_fma_f32 v10, -v6, v8, v9` | — |
| `fma(Fma2, Fma1, Mul)` | `v_fmac_f32_e32 v8, v10, v7` | — |
| `fma(fneg(DenominatorScaled), Fma3, NumeratorScaled)` | `v_fma_f32 v6, -v6, v8, v9` | — |
| `div_fmas(Fma4, Fma1, Fma3, NumeratorScaled[1])` | `v_div_fmas_f32 v6, v6, v7, v8` | — |
| `div_fixup(Fmas, RHS /*denominator*/, LHS /*numerator*/)` | `v_div_fixup_f32 v3, v6, v5, v3` | `S1 = RHS = v5` (denominator), `S2 = LHS = v3` (numerator) |

**Every instruction matches, in order, with the same operand roles.** This is
not a family resemblance; it is the same lowering, 11 instructions long,
including the `null`-destination spelling of the dead first `div_scale` Sdst
that LLVM emits when the condition output is unused.

**Three facts fall out of the correspondence, and they are the ones the J3
ambiguity turned on:**

1. **`S0 = Denominator` for the first scale and `S0 = Numerator` for the
   second.** This is the "S0 must be the same value as either S1 or S2"
   contract, satisfied by construction. The ISA text's missing `else` is
   therefore reached for the `<S0 = Y>` copy whenever the denominator needs no
   rescaling — and in that case `D` must be `Y`.
2. **`S1 = Denominator` and `S2 = Numerator` in both copies**, so the
   `exponent(S2.f) <= 23` clause examines the **numerator** in both.
3. **The quotient is `Mul` = `fmul(NumeratorScaled, Fma1)`**, i.e. `X * rcp(Y)`
   refined — *unless* `V_DIV_FMAS_F32` post-scales by `2**32`, in which case
   `Fmas` is the scaled quotient and `div_fixup` rescales it. This is why the
   value of `D` on the unassigned path is load-bearing: it selects which of the
   two the final answer comes from.

## What this establishes, and what it does not

**Establishes (criterion 6).** The instruction sequence in Candidate F *is* the
LLVM AMDGPU lowering for `G_FDIV` f32, under the same toolchain lineage that
compiled the module. `legalizeFDIV32` is the compiler's answer to "implement
IEEE f32 division", and the sequence it builds is byte-for-byte the sequence
Candidate F executes. A reading of `V_DIV_SCALE_F32` that makes this lowering
produce something *other than* the quotient is therefore refuted by the
compiler's own intent, not merely by intuition.

**Does NOT establish.**
* It is not a hardware observation. Nothing here says what gfx1030 silicon
  does on the unassigned path; it says what the compiler *needs* it to do for
  the lowering to be correct.
* LLVM source and the AMD manual are **not two independent sources for the
  manual's prose** — `legalizeFDIV32` was written against the same
  documentation. Its value here is different in kind: it is an *operational*
  artefact (code that must produce a correct quotient), where the manual is a
  *descriptive* one (prose that leaves a branch unassigned).
* It does not by itself satisfy criteria 1–5, 7, 9 or 10 of the closure test.
  Those are measured in `phase16s/div/SEQUENCE_ORACLE.json`.

## Second source file

| field | value |
|---|---|
| file | `llvm/include/llvm/IR/IntrinsicsAMDGPU.td` |
| URL | `https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/include/llvm/IR/IntrinsicsAMDGPU.td` |
| sha256 | `0a675c32782a9e3b8ac8113f3dedeb718273f36841bbfd54404f4e3b6b4f3593` |
| local copy | `phase16s/div/ref/llvm_IntrinsicsAMDGPU.td` |
| excerpt | `int_amdgcn_div_scale`, `int_amdgcn_div_fmas`, `int_amdgcn_div_fixup` |

## Corroborating sources (not used as authority)

* LLVM review **D20557** ("Lowering floating point division for 32-bit using
  IEEE 754") and **D71293** ("AMDGPU: Generate the correct sequence of code for
  FDIV32 when correctly-rounded-divide-sqrt is set") describe the same
  sequence and the requirement that a correctly-lowered FDIV32 contain **two**
  `v_div_scale`, **two** `v_fma` before `v_mul`, **three** `v_fma` after it,
  and `v_div_fmas` before `v_div_fixup` — which is exactly what Candidate F
  contains.
* These are recorded as corroboration of the *shape*, not as a second
  independent semantic source for the *unassigned branch*.
