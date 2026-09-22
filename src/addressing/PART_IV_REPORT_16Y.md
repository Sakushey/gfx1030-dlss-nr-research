# Phase 16Y PART IV -- address metamorphic audit of the frozen J3 run

**Host-only.** No GPU code was run, no harness executable was started, nothing was installed and no clock, voltage, power limit, firmware, BIOS, registry entry or driver was touched. `kernel_launch_count: 0`, `gpu_execution_performed: false`.

## The question

Does the frozen Candidate-F J3 emulator run depend on the **absolute** device virtual addresses of its regions, or only on the **relative** layout? A base-address-dependent result would be a Candidate-F defect and would block a physical launch.

## The answer

NO.  Across the control plus 15 rebased layouts (16 distinct base sets), the frozen J3 run produced the byte-identical output image, the same 13,699 ticks, the same 10 barrier epochs, the same per-wave step and barrier counts, the same region-relative 6,144-byte store set and the same region-relative store digest as the control, with no faults. The only observable that moved is the ABSOLUTE address digest, which is expected to move because it is taken over the module image's and kernarg segment's own device addresses. No base-address-dependent behaviour was found, so this audit does not block a physical launch.

## 1. Did the control reproduce?

Yes, exactly. Re-run with this part's own script from the known-good recipe in `phase16y/liveness/p16y_barrier_trace.py::run()`:

| quantity | required (frozen record) | measured | match |
|---|---|---|---|
| image sha256 | `5ab70916b9c284dd24a1878afcd7b984928145442623909a275b0035743979e4` | `5ab70916b9c284dd24a1878afcd7b984928145442623909a275b0035743979e4` | yes |
| ticks | 13699 | 13699 | yes |
| natural_end | True | True | yes |
| faults | [] | [] | yes |
| barrier epochs | `[710468, 735828, 744332, 751628, 758660, 763660, 769568, 769828, 777052, 788208]` | `[710468, 735828, 744332, 751628, 758660, 763660, 769568, 769828, 777052, 788208]` | yes |

The image was also compared byte for byte against the frozen `ctrl_frozen.bin` (9365817 bytes). The D1 gate script reports 21 gates, 0 failed, verdict **PASS**.

## 2. How the pointer relation is represented (and what a rebase has to move)

the region->address relation is written in the input document TWICE, and a rebase must move both together: (1) regions[*].base / base_va / guard_start / pointer_field_value, and (2) the encoded pointer VALUE the kernel actually reads, at varparams.field_values[regions[*].pointer_field_offset] (the same 168-byte kernarg blob as vals[off] in the runner). Nothing else in the document carries an address.

- **Region images carry no base.** measured: no region payload in J3_V2_INPUT.bin contains any region base, so no image byte needs rebasing. The input rule was verified: every one of the 9,365,817 image bytes equals pattern_at(offset) for its region (0 mismatches), and image bytes are a pure function of the region's own offset -- see input_rule_check in layouts_comparison.json.
- **Rebasing applied:** bases[i] -> bases[i] + D, and simultaneously vals[pointer_field_offset_i] -> bases[i] + D, then the guarded pointer spelling re-encoded; the region payload offsets, extents, sizes, the bin and the kernarg scalars are untouched.
- **Proof the pointer rebasing is load-bearing:** negative control N3 leaves the encoded pointers at their control values while the region bases move; it is REQUIRED to fail, and it does (see negative_controls.run_level). If it passed, the pointer rebasing would be doing nothing and the whole family would be vacuous.

## 3. The layout family

every layout is base_i -> base_i + D with ONE D for all regions. That preserves the relative gap between every pair of regions bit-exactly and the alignment class of every region bit-exactly, so any difference a layout produces is attributable to the ABSOLUTE base alone and not to a changed relative layout. A per-region rebase would confound the two.

| # | layout | D (decimal) | D (hex) | slot_0x00 base | slot_0x08 base | slot_0x10 base | slot_0xA0 base | verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | `a_shift_2p32` | 4294967296 | `0x100000000` | `0x00000005224A0000`<br/>22050111488 | `0x0000000523580000`<br/>22067806208 | `0x00000005040054DC`<br/>21541967068 | `0x000000052B870000`<br/>22205104128 | **PASS** |
| 2 | `a_shift_3x2p32` | 12884901888 | `0x300000000` | `0x00000007224A0000`<br/>30640046080 | `0x0000000723580000`<br/>30657740800 | `0x00000007040054DC`<br/>30131901660 | `0x000000072B870000`<br/>30795038720 | **PASS** |
| 3 | `b_lowword_carry_mixed` | 7996964864 | `0x1DCA80000` | `0x00000005FEF20000`<br/>25752109056 | `0x0000000600000000`<br/>25769803776 | `0x00000005E0A854DC`<br/>25243964636 | `0x00000006082F0000`<br/>25907101696 | **PASS** |
| 4 | `b_highdword_diff` | 12817793024 | `0x2FC000000` | `0x000000071E4A0000`<br/>30572937216 | `0x000000071F580000`<br/>30590631936 | `0x00000007000054DC`<br/>30064792796 | `0x0000000727870000`<br/>30727929856 | **PASS** |
| 5 | `c_wrap_slot_0x00` | 8014594048 | `0x1DDB50000` | `0x00000005FFFF0000`<br/>25769738240 | `0x00000006010D0000`<br/>25787432960 | `0x00000005E1B554DC`<br/>25261593820 | `0x00000006093C0000`<br/>25924730880 | **PASS** |
| 6 | `c_wrap_slot_0x08` | 7996899328 | `0x1DCA70000` | `0x00000005FEF10000`<br/>25752043520 | `0x00000005FFFF0000`<br/>25769738240 | `0x00000005E0A754DC`<br/>25243899100 | `0x00000006082E0000`<br/>25907036160 | **PASS** |
| 7 | `c_wrap_slot_0x10` | 8522760192 | `0x1FBFF0000` | `0x000000061E490000`<br/>26277904384 | `0x000000061F570000`<br/>26295599104 | `0x00000005FFFF54DC`<br/>25769759964 | `0x0000000627860000`<br/>26432897024 | **PASS** |
| 8 | `c_wrap_slot_0xA0` | 7859601408 | `0x1D4780000` | `0x00000005F6C20000`<br/>25614745600 | `0x00000005F7D00000`<br/>25632440320 | `0x00000005D87854DC`<br/>25106601180 | `0x00000005FFFF0000`<br/>25769738240 | **PASS** |
| 9 | `d_hip_7ff_style` | 8774042910720 | `0x7FADDB60000` | `0x000007FF00000000`<br/>8791798054912 | `0x000007FF010E0000`<br/>8791815749632 | `0x000007FEE1B654DC`<br/>8791289910492 | `0x000007FF093D0000`<br/>8791953047552 | **PASS** |
| 10 | `d_hip_A00000000_style` | 25194528768 | `0x5DDB60000` | `0x0000000A00000000`<br/>42949672960 | `0x0000000A010E0000`<br/>42967367680 | `0x00000009E1B654DC`<br/>42441528540 | `0x0000000A093D0000`<br/>43104665600 | **PASS** |
| 11 | `e_random_seed1601` | 7250919243263377408 | `0x64A070A27DC20000` | `0x64A070A6A00C0000`<br/>7250919261018521600 | `0x64A070A6A11A0000`<br/>7250919261036216320 | `0x64A070A681C254DC`<br/>7250919260510377180 | `0x64A070A6A9490000`<br/>7250919261173514240 | **PASS** |
| 12 | `e_random_seed1602` | 14902279252497793024 | `0xCECF880644CE0000` | `0xCECF880A67180000`<br/>14902279270252937216 | `0xCECF880A68260000`<br/>14902279270270631936 | `0xCECF880A48CE54DC`<br/>14902279269744792796 | `0xCECF880A70550000`<br/>14902279270407929856 | **PASS** |
| 13 | `e_random_seed1603` | 9527415944920760320 | `0x84382E52D0650000` | `0x84382E56F2AF0000`<br/>9527415962675904512 | `0x84382E56F3BD0000`<br/>9527415962693599232 | `0x84382E56D46554DC`<br/>9527415962167760092 | `0x84382E56FBEC0000`<br/>9527415962830897152 | **PASS** |
| 14 | `e_random_seed1604` | 445605396480917504 | `0x62F1BBF473E0000` | `0x062F1BC369880000`<br/>445605414236061696 | `0x062F1BC36A960000`<br/>445605414253756416 | `0x062F1BC34B3E54DC`<br/>445605413727917276 | `0x062F1BC372C50000`<br/>445605414391054336 | **PASS** |
| 15 | `e_random_seed1605` | 2493721607992836096 | `0x229B7A9715210000` | `0x229B7A9B376B0000`<br/>2493721625747980288 | `0x229B7A9B38790000`<br/>2493721625765675008 | `0x229B7A9B192154DC`<br/>2493721625239835868 | `0x229B7A9B40A80000`<br/>2493721625902972928 | **PASS** |

Each base cell shows the hex value and, below it, the exact decimal value. The control's own bases, for reference: `slot_0x00` = `0x4224A0000` (17755144192), `slot_0x08` = `0x423580000` (17772838912), `slot_0x10` = `0x4040054DC` (17246999772), `slot_0xA0` = `0x42B870000` (17910136832).

Every layout was checked **legal before it was run**: base > 0, base+extent within 2^64, each region's alignment class preserved (64 KiB for the three big regions, 4-byte for `slot_0x10`), every pairwise relative gap bit-identical to the control, and no two regions overlapping. Legality problems found: [].

## 4. What matched (region-relative), per layout

| layout | whole-image sha256 vs frozen | ticks | epochs | per-wave steps/barriers | rel. store set | rel. store digest | faults | checks passed | comparisons |
|---|---|---|---|---|---|---|---|---|---|
| `a_shift_2p32` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `a_shift_3x2p32` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `b_lowword_carry_mixed` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `b_highdword_diff` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `c_wrap_slot_0x00` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `c_wrap_slot_0x08` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `c_wrap_slot_0x10` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `c_wrap_slot_0xA0` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `d_hip_7ff_style` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `d_hip_A00000000_style` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `e_random_seed1601` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `e_random_seed1602` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `e_random_seed1603` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `e_random_seed1604` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |
| `e_random_seed1605` | frozen | 13699 | same | [13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052] / [10, 10, 10, 10, 10, 10, 10, 10] | 6144 addrs | same | none | 35/35 | 9634773 |

The control's own values, for reference: image `5ab70916b9c284dd24a1878afcd7b984928145442623909a275b0035743979e4`, ticks 13699, epochs `[710468, 735828, 744332, 751628, 758660, 763660, 769568, 769828, 777052, 788208]`, per-wave steps `[13697, 13697, 13697, 13697, 13697, 13052, 13052, 13052]`, per-wave barriers `[10, 10, 10, 10, 10, 10, 10, 10]`, region-relative store set 6144 addresses, digest `38309375536bbb8b06946f674ed6fec5ae46d1bbed983da8571349fad92048eb`, faults none.

### The one observable that moves, and why it is not a failure

the frozen record's `store_addresses_sha256` is computed over the ABSOLUTE addresses of every key in the memory image -- 1,215,811 keys, the sum of 1,209,630 in the mapped module image (0x30009F40..0x301324BB), 6,144 in the declared data regions and 37 in the kernarg segment (0x10000..0x100E8). It is therefore EXPECTED to change under a rebase and is NOT an invariance observable; the region-relative store set and its digest replace it.

Layouts whose **absolute** store digest moved: 15 of 15. Layouts whose **region-relative** store digest moved: 0.

The first number is a **non-vacuity measurement**, not a curiosity: it is the proof that each layout's rebase actually reached the store addresses. A layout whose absolute digest had *not* moved would have compared a run against itself, and its PASS would mean nothing. Layouts where it did not move: none -- all 15 moved it.

### Checks that compared nothing

None. Every one of the 35 checks performed at least one comparison in every layout (525 checks evaluated, 144521595 comparisons in total).

### The barrier epochs in wave order (D3's other half)

The converged epoch list above is ten entries for the whole workgroup, and the per-wave column is a **count**. Neither can see two waves trading barrier PCs, or a wave reaching its barriers at different step indices. So every layout was re-run with the per-wave instrument from `phase16y/liveness/p16y_barrier_trace.py` (loaded as a module, **subclassed**, not edited) and the whole per-wave table compared.

**Instrument:** `..\liveness\p16y_barrier_trace.py`, sha256 `0a3d06039a27396274e32e6ee27be24f7b64ec2fd32e537343f59ad56180934d`, 18 barrier sites, in-loop barrier `0xBBE20`. the recorder is a SUBCLASS of the core class (the established pattern), the liveness module is imported read-only and neither it nor the emulator source is edited

The control's per-wave table (module-relative PC, and the wave's own step index at that barrier):

| wave | barriers | ordinal 1..10 (PC) | step indices |
|---|---|---|---|
| 0 | 10 | `0xAD744` `0xB3A54` `0xB5B8C` `0xB780C` `0xB9384` `0xBA70C` `0xBBE20` `0xBBF24` `0xBDB5C` `0xC06F0` | 325 3547 4708 7264 7793 9541 10522 10571 12266 13677 |
| 1 | 10 | `0xAD744` `0xB3A54` `0xB5B8C` `0xB780C` `0xB9384` `0xBA70C` `0xBBE20` `0xBBF24` `0xBDB5C` `0xC06F0` | 325 3547 4708 7264 7793 9541 10522 10571 12266 13677 |
| 2 | 10 | `0xAD744` `0xB3A54` `0xB5B8C` `0xB780C` `0xB9384` `0xBA70C` `0xBBE20` `0xBBF24` `0xBDB5C` `0xC06F0` | 325 3547 4708 7264 7793 9541 10522 10571 12266 13677 |
| 3 | 10 | `0xAD744` `0xB3A54` `0xB5B8C` `0xB780C` `0xB9384` `0xBA70C` `0xBBE20` `0xBBF24` `0xBDB5C` `0xC06F0` | 325 3547 4708 7264 7793 9541 10522 10571 12266 13677 |
| 4 | 10 | `0xAD744` `0xB3A54` `0xB5B8C` `0xB780C` `0xB9384` `0xBA70C` `0xBBE20` `0xBBF24` `0xBDB5C` `0xC06F0` | 325 3547 4708 7264 7793 9541 10522 10571 12266 13677 |
| 5 | 10 | `0xAD744` `0xB3A54` `0xB5B8C` `0xB780C` `0xB9384` `0xBA70C` `0xBBE20` `0xBBF24` `0xBDB5C` `0xC06F0` | 325 3547 4708 7264 7793 9541 9877 9926 11621 13032 |
| 6 | 10 | `0xAD744` `0xB3A54` `0xB5B8C` `0xB780C` `0xB9384` `0xBA70C` `0xBBE20` `0xBBF24` `0xBDB5C` `0xC06F0` | 325 3547 4708 7264 7793 9541 9877 9926 11621 13032 |
| 7 | 10 | `0xAD744` `0xB3A54` `0xB5B8C` `0xB780C` `0xB9384` `0xBA70C` `0xBBE20` `0xBBF24` `0xBDB5C` `0xC06F0` | 325 3547 4708 7264 7793 9541 9877 9926 11621 13032 |

Measured: all eight waves reach the **same ten PCs in the same order** (`all_eight_waves_share_one_pc_sequence` = **True**), so the PC table is wave-order-INSENSITIVE on this workload and rotating the wave order is a **no-op** on it -- reported as `wave_rotation_is_a_MEASURED_no_op_on_the_pc_table` rather than used as a control. The PC table's rejection controls are instead the +2^32 bias, a swapped barrier order and a dropped barrier. The **step-index table** is where the wave-order signal lives: the eight waves' step sequences are **not** all the same (`all_eight_waves_share_one_step_sequence` = **False**), so rotating the wave order there is rejected.

| layout | per-wave counts | PC table identical | step-index table identical | checks passed | verdict |
|---|---|---|---|---|---|
| `a_shift_2p32` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `a_shift_3x2p32` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `b_lowword_carry_mixed` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `b_highdword_diff` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `c_wrap_slot_0x00` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `c_wrap_slot_0x08` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `c_wrap_slot_0x10` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `c_wrap_slot_0xA0` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `d_hip_7ff_style` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `d_hip_A00000000_style` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `e_random_seed1601` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `e_random_seed1602` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `e_random_seed1603` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `e_random_seed1604` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |
| `e_random_seed1605` | [10, 10, 10, 10, 10, 10, 10, 10] | True | True | 15/15 | **PASS** |

The instrument is shown **not to perturb the run**: with the recorder attached, every layout still produced the frozen image sha256 and the same tick count as the instrument-free first pass (`non_perturbation__*` checks in each row).

The discriminating measurement, in one line: on this workload all eight waves reach the SAME ten barrier PCs in the SAME order, so the PC table is wave-order-insensitive by measurement, and rotating the wave order is a NO-OP on it (that is reported as wave_rotation_is_a_MEASURED_no_op_on_the_pc_table rather than used as a control). The step-index table DOES differ between waves 0-4 and 5-7, so it is the observable that carries the wave-order signal, and rotating the wave order is rejected there. The PC-table rejection controls are the +2^32 bias, a swapped barrier order and a dropped barrier.

Wave-order leg verdict: **PASS** (15 layouts, 0 failed, no check compared nothing).

## 5. Carry boundaries (independent of the run)

The run above only exercises the carry arithmetic on the addresses it happens to reach. This section exercises the same instructions **deliberately** at the low-dword and high-dword boundaries.

- **Assembler probe**: the six mnemonics were assembled from source by `<ROCM_ROOT>\6.4\bin\llvm-mc.exe` (`--triple=amdgcn-amd-amdhsa --mcpu=gfx1030 --filetype=obj`) and disassembled back with `llvm-objdump -d`: **6 instructions, round trip OK**. It is an ENCODING probe, run entirely offline; it is never executed on a device and it does not drive the emulator. The arithmetic cross-check is the battery below, which drives the handlers the run itself instantiates.
- **Static census** of the frozen kernel: **500 carry-instruction sites**; **Executed census** (the instances the frozen run actually executed): **1563**.

| mnemonic | static sites | executed |
|---|---|---|
| `s_add_u32` | 34 | 192 |
| `s_addc_u32` | 34 | 192 |
| `v_add_co_u32` | 117 | 528 |
| `v_add_co_ci_u32` | 0 | 0 |
| `v_add_co_ci_u32_e64` | 231 | 603 |
| `v_mad_u64_u32` | 84 | 48 |

- **Battery**: 319 cases, **0 mismatches** against an independent Python 64-bit reference.

Carry-out FLAGS, aggregated separately from the 64-bit results: a 64-bit result can be right while its carry flag is wrong, and a wrong carry flag is what a dropped carry looks like one instruction later. Each row is counted over its OWN domain -- the two `v_mad_u64_u32` rows are meaningless outside the carry-out-destination they name, so they are counted over that domain only. Per-case records are in `meas/carry_cases.json`; they are not reproduced here.

| flag | correct / measured | counted over |
|---|---|---|
| `scc_correct` | **196 / 196** | every case that reads SCC |
| `vcc_low_correct` | **49 / 49** | every case that reads the low VCC word |
| `vcc_high_correct` | **49 / 49** | every case that reads the high VCC word |
| `sgpr_carry_correct` | **49 / 49** | every case that reads an SGPR carry-out |
| `vcc_untouched_when_sdst_is_null` | **8 / 8** | ONLY the v_mad_u64_u32 cases whose carry-out destination is `null` (VCC must then be left alone) |
| `vcc_equals_the_isa_carry_out` | **6 / 8** | ONLY the v_mad_u64_u32 cases whose carry-out destination IS VCC |

Non-vacuity of the batteries: with the low-word carry dropped from the **reference**, 114 of 319 synthetic cases mismatch and 5 of 96 (base, offset) layout-address pairs mismatch. A battery that could not fail would be measuring nothing.

### The one measured deviation found here

**V_MAD_U64_U32's carry-out (bit 63 of S0.u32*S1.u32 + S2.u64) is not delivered to the destination the ISA names. When the destination IS VCC the handler writes VCC = 0 instead of the carry-out; when the destination is `null` the handler leaves VCC untouched.** -- in `the frozen `op_v_mad_u64_u32` (resolved on class ['Core8'])`.

Status **MEASURED**. The measured numbers, each one the value the artifact carries:

| quantity | value |
|---|---|
| `n_cases` | 19 |
| `n_cases_with_sdst_null` | 8 |
| `vcc_untouched_in_every_sdst_null_case` | **True** |
| `n_cases_with_sdst_vcc_lo` | 8 |
| `n_sdst_vcc_lo_cases_where_vcc_equals_the_isa_carry_out` | 6 |
| `n_sdst_vcc_lo_cases_where_the_isa_carry_out_is_0` | 6 |
| `reading` | `VCC comes back 0, so it agrees with the ISA carry-out exactly in the cases where the ISA carry-out is itself 0 -- which is what a hard-coded 0 looks like.` |

**Why it does not gate this part:**

- *dormant in the audited run:* all 84 static instances of v_mad_u64_u32 in the frozen kernel, and all 48 the run executes, name `null` as the carry-out destination (see s1_static_census.static_carry_out_destination_token_per_mnemonic), so the wrong write never happens in the J3 run.
- *base address independent:* the deviation is a property of the multiply's carry-out, not of any operand address; it cannot be produced or suppressed by rebasing, so it is not an address-dependence finding.
- *carried forward:* it belongs to the phase16s `BLOCKED_J3_INSTRUCTION_SEMANTICS` list (`v_add_co_ci_u32_e64` and friends) and should be resolved there, not silently absorbed into THIS part's verdict.

the deviation is a FLAG fact. The 319-case battery's 64-bit RESULTS are compared separately and are all correct; a case is never failed for this.

## 6. Negative controls (intended vs actual)

A checker that rejects nothing is not a checker. Each of these is handed a mutation it is **required** to reject, or in the trivial case required to accept.

`as intended` compares the **verdict word** the control was required to return against the verdict it returned -- the same rule the D5 gate uses, and the same rule both D5 artifacts record. Each control's full requirement is printed under the table.

| control | intended | actual | as intended | what was measured |
|---|---|---|---|---|
| `N1_carry_dropped_on_a_wrapping_layout` | **FAIL** | **FAIL** | yes | 2 of 35 checks failed |
| `N2_carry_dropped_on_the_control_layout` | **FAIL** | **FAIL** | yes | 2 of 35 checks failed |
| `N3_bases_rebased_but_encoded_pointers_left_stale` | **FAIL** | **FAIL** | yes | 14 of 35 checks failed |
| `N6_control_against_itself` | **PASS** | **PASS** | yes | **PASS required and returned** -- the control compared against itself |
| `N4_one_store_byte_corrupted` | **FAIL** | **FAIL** | yes | caught by ["store_set_region_relative", "store_set_region_relative_digest"] |
| `N5_one_store_address_truncated` | **FAIL** | **FAIL** | yes | caught by ["store_set_region_relative", "store_set_region_relative_digest"] |

The full requirement of each control that asks for more than its verdict word (the `as intended` column compares only the word):

- `N2_carry_dropped_on_the_control_layout` -- intended **FAIL if the control's own addresses need the carry; a PASS here means the defect is DORMANT on this layout and proves nothing about the wrap cases**
- `N4_one_store_byte_corrupted` -- intended **FAIL on the region-relative store comparison**
- `N5_one_store_address_truncated` -- intended **FAIL on the region-relative store set and its digest**

**The N1/N2 pair does not isolate the rebase, and is not claimed to.** N1 and N2 both drop the carry-in from EVERY `s_addc_u32` / `v_add_co_ci_u32` the run executes, not only from the address form `base + offset`. Both therefore fail, and the failing check lists below show it: they are the same two checks in both controls (["unmapped_read_relative_digest", "unmapped_read_address_census"] in N1, ["unmapped_read_relative_digest", "unmapped_read_address_census"] in N2). So the N1/N2 pair is evidence that the invariance checker is sensitive to a broken 64-bit add -- it is NOT an isolation of the rebased low-word wrap, and no such isolation is claimed. The control that DOES isolate the rebase machinery is N3 (bases moved, encoded pointers left stale), which fails 14 of 35 checks.

N1 and N2 were caught by the same checks: N1 ["unmapped_read_relative_digest", "unmapped_read_address_census"], N2 ["unmapped_read_relative_digest", "unmapped_read_address_census"] — identical: **True**.

**Vacuity note (N2):** N2 (the control layout) failed, but ONLY on the unmapped-read checks (["unmapped_read_address_census", "unmapped_read_relative_digest"]). The image sha, the region-relative store set and its digest, the ticks, the barrier epochs and the mapped read counts are all UNCHANGED, so the defect is dormant for every MAPPED observable of this workload: dropping the low-word carry moves garbage-read addresses only. This control therefore demonstrates the checker's sensitivity in the unmapped-read dimension; it does NOT demonstrate a live carry path in address formation. The carry question is answered by the arithmetic battery and the static/executed census (D4), and the load-bearing control for the REBASE machinery is N3.

**The first attempt at this battery is preserved, FAIL and all**, at `meas/negative_controls_first_attempt.json`: its N5 mutation was a literal no-op (`slot_0xA0@0 -> slot_0xA0@0`), N5 returned its intended verdict's opposite, and the D5 verdict was **FAIL**. The recorded artifacts are from the corrected re-run. See section 7(d).

## 7. Defects found in this part's own checkers (and fixed)

These are recorded because each one produced a **plausible-looking number that was wrong**, and each was caught by reading one case by hand rather than by trusting a count.

**(a) The epoch check compared in the wrong address space.** `barrier_epochs_decode_into_module_text` first tested the barrier epochs against the **TEXT_BASE-mapped** module range (`0x3000BA00..0x301324BC`) while the epochs the emulator reports are **module-section** addresses (`0xAD744..0xC06F0`). It therefore rejected the control layout itself -- it rejected everything and proved nothing. It is now computed in the correct space (`0xBA00..0x1324BC`) and is paired with its own rejection control: an epoch sequence biased by +2^32 -- exactly what “the epochs moved with the bases” would look like -- must be and is rejected. The first two rebased layouts were measured with the broken form, which is why they were re-run; the numbers above come from the corrected run only.

**(b) The carry reference model had the wrong modulus.** `ref_add64` called `ref_add(a, b, M64)`, but `M64` is the 64-bit **mask** (`2^64-1`), not the modulus (`2^64`), so the reference returned `(a+b) & 0xFFFF...FE` -- bit 0 cleared -- and the battery reported **148 “mismatches” in which the emulator was right and the reference was wrong** (the giveaway was the single case `a=0, b=1`: emulator 1, reference 0). Fixed, and the case is recorded in `ref_add64`'s own docstring.

**(c) The carry-in cases did not carry in.** `add64_sgpr(a, b, cin=1)` preset SCC and then executed `s_add_u32` first, which **overwrites** SCC with its own carry-out -- so the preset carry-in was silently dropped and the four carry-in cases measured a plain add while the reference expected `a+b+1`. All four “failed” for that reason. The carry-in is now expressed with two `s_addc_u32`, which is a legitimate spelling, and the other two idioms now **raise** rather than silently ignore a `cin` they cannot honour.

**(d) The first N5 “truncated address” mutation was a no-op, and its own gate caught it.** N5 truncated `sorted(_rel_store)[n//3]` to its low 16 bits. The store set is 2,048 addresses in `slot_0x08` (offsets 0..123,903) followed by 4,096 in `slot_0xA0` (offsets 0..4,095), so index `6144/3 = 2048` is `slot_0xA0`'s **smallest** offset -- **0** -- and `0 & 0xFFFF == 0`. The mutation changed nothing, N5 reported PASS instead of its intended FAIL, and the D5 verdict went to FAIL. This is the same failure mode as (a)-(c): a plausible number that was not a measurement of anything. The mutation now picks the largest offset with nonzero high bits (123,903 → 58,367) and **raises** if no offset exceeds `0xFFFF`, so it cannot silently become vacuous again; the gate now additionally requires the mutation to have changed the relative-store digest and to have been caught by the **named** relative-store checks, because “some check failed” is not the same claim as “the relative-store comparison caught it”.

**(e) The carry-flag aggregate counted two predicates outside their domain.** Two carry-out predicates were attached to EVERY `v_mad_u64_u32` case although each is a statement about only one carry-out-destination domain: `vcc_untouched_when_sdst_is_null` is meaningless when the destination IS VCC (writing VCC there is the ISA's own behaviour, not a defect) and `vcc_equals_the_isa_carry_out` is meaningless when the destination is `null` (VCC is then REQUIRED to be left alone). The generic aggregator counts every case carrying the key, so it mixed 8 in-domain with 8 out-of-domain cases and reported **8/16 and 6/16**, which this report first rendered as if eight cases had failed. It was caught by reading the two counts against their own case list: the listed “failing” cases had the **other** destination. Each predicate is now emitted only on its own domain and every aggregate names the domain it was counted over, so the same two aggregates read **8/8 and 6/8**. This is an aggregation defect, not a measurement defect, and that is asserted rather than claimed: the re-run is byte-identical to the pre-fix artifact at every case-level measurement -- 319 of 319 cases, the deviation numbers, both censuses, the assembler probe and the non-vacuity counters -- and the pre-fix artifact is preserved at `meas/carry_cases_BEFORE_flagfix.json`.

Two of the five defect entries above ((d) and (e)) were found by **rendering the deliverable and reading it back**, not by the checks themselves: (d) by its own gate, (e) only by reading a number against the case list it was supposed to summarise. Neither was visible in the verdicts, which were PASS before and after.

## 8. Measured vs inferred

| claim | status | evidence |
|---|---|---|
| the frozen run is invariant under a rigid rebase of the four region bases | **MEASURED** | 15 layouts x 35 checks, 144521595 comparisons; every layout produced the frozen image sha 5ab70916b9c284dd |
| the per-wave barrier table is identical in wave order, not merely in its converged form and its counts | **MEASURED** | 15 layouts re-run with the per-wave instrument: each wave's ordered barrier PCs and its own step index at each barrier are identical to the control's, and the instrument is shown not to perturb the run (frozen image sha and ticks with the recorder attached). See d3_wave_order_leg. |
| the carry-drop negative control demonstrates a live carry path in address formation | **MEASURED as FALSE -- the control is narrower than designed** | N1 and N2 both fail, but ONLY on the unmapped-read checks; the image sha, the region-relative store set and its digest, the ticks, the barrier epochs and the mapped read counts are all unchanged. The defect is dormant for every MAPPED observable of this workload. The load-bearing negative control for the rebase machinery is N3 (bases moved, encoded pointers stale), which fails 14 of 35 checks. |
| the barrier epochs are module-section addresses, not TEXT_BASE-mapped ones | **MEASURED** | the epochs (0xAD744..0xC06F0) fall inside the module-relative .text (0xBA00..0x1324BC) and OUTSIDE the mapped range (0x3000BA00..0x301324BC); the first version of this check used the mapped range and rejected the control itself, which is how the error was found |
| the frozen emulator's 64-bit address arithmetic is correct across the low-dword boundary and the high-dword carry | **MEASURED** | see carry_boundaries: 319 battery cases against an independent Python reference, 0 mismatches |
| a rigid shift can wrap at most one region's low word at a time | **MEASURED** | the smallest inter-region gap is 0x10E0000 and no region's allocation extent exceeds it, so two low words with the same addend cannot both land within one extent of 2^32; the four (c) layouts therefore cover the wraparound one region at a time |
| the carry-flag counts measure the domain they name | **MEASURED, after a fix (see section 7(e))** | each of the six aggregate rows in carry_boundaries.carry_out_flags carries a `counted_over` field; the two v_mad_u64_u32 rows are counted over their own carry-out-destination domain and read 8/8 and 6/8. Before the fix they were counted over the union of both domains and read 8/16 and 6/16, while every other number in the artifact stayed identical |
| the frozen emulator's every carry-instruction handler is the one the run actually executes | **MEASURED** | handler provenance in carry_cases.json: the five handlers are resolved through the MRO of the class the run INSTANTIATES (GateCore), and s_add_u32 / s_addc_u32 / v_add_co_u32 / v_add_co_ci_u32 resolve on Core while v_mad_u64_u32 resolves on Core8 -- looking them up on emu.Core reports v_mad_u64_u32 as 'not inherited', which is false. The battery drives GateCore.<handler> itself. |
| V_MAD_U64_U32's carry-out is delivered to the ISA's destination register | **MEASURED as FALSE (a real emulator deviation), DORMANT in this run** | see carry_boundaries.measured_deviation: with the carry-out destination set to VCC the handler writes VCC = 0 rather than bit 63 of the product; it agrees with the ISA exactly in the cases where that carry-out is itself 0. All 84 static and all 48 executed instances in the frozen kernel name `null`, so the wrong write never fires. It is address-independent. |

## 9. What is NOT established

- the DEVICE's own address arithmetic was not exercised: this part ran no GPU code at all (kernel_launch_count 0). Every carry case drives the emulator's handler or the assembler's encoding, so the finding is about the frozen EMULATOR, which is the artifact under audit.
- no claim is made that a rebase is observed by real hardware to be equivalent; the claim is that the emulator's result does not depend on the bases over the family measured here.

## 10. Blockers

None. No base-address-dependent behaviour was found.

## 11. Files

| artifact | path |
|---|---|
| control_rerun | `<PROJECT_ROOT>\phase16y\addressing\part4_scratch\meas\ctrl_measured.json` |
| control_d1_gates | `<PROJECT_ROOT>\phase16y\addressing\part4_scratch\meas\ctrl_frozen_reproduced.json` |
| layouts | `<PROJECT_ROOT>\phase16y\addressing\part4_scratch\meas\layouts_comparison.json` |
| wave_order_leg | `<PROJECT_ROOT>\phase16y\addressing\part4_scratch\meas\wave_barriers.json` |
| carry | `<PROJECT_ROOT>\phase16y\addressing\part4_scratch\meas\carry_cases.json` |
| negative_controls | `<PROJECT_ROOT>\phase16y\addressing\part4_scratch\meas\negative_controls.json` |
| negative_controls_archived_first_attempt | `<PROJECT_ROOT>\phase16y\addressing\part4_scratch\meas\negative_controls_first_attempt.json` |
| frozen_control_record | `<PROJECT_ROOT>\phase16y\addressing\out\ctrl_frozen.json` |
| frozen_control_image | `<PROJECT_ROOT>\phase16y\addressing\out\ctrl_frozen.bin` |

Everything this part wrote is under `phase16y/addressing/`. The intermediate measurement dumps are in `phase16y/addressing/part4_scratch/meas/` and the exploratory scripts in `phase16y/addressing/part4_scratch/`; raw dumps live in those and in the JSON, not in this file.

**One file was created outside `phase16y/addressing/`**, and it is not a source file: importing the per-wave instrument read-only wrote its bytecode cache, `phase16y/liveness/__pycache__/p16y_barrier_trace.cpython-314.pyc`. The instrument's **source** is byte-unmodified (sha256 `0a3d06039a27396274e32e6ee27be24f7b64ec2fd32e537343f59ad56180934d`, mtime 2026-09-20 14:50, both predating this part's work). No file under `phase16t/`, `phase16h_candidate_f/`, `phase16r/`, `phase16w/` or `phase16x/` was written: the newest mtime in those five trees is 2026-09-20 13:02:59, before this part began.

## Verdict

**PASS**
