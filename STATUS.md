# Status — Phase 16BK

**Research remains active. No end-to-end DLSS-NR frame has been demonstrated.**

| Area | Current evidence |
| --- | --- |
| Host instruction and tensor checks | Active; host evidence is the primary execution path |
| Source-built decoder-transition operation | Narrow gfx1030 validation only |
| M0 authentic execution | Not established |
| Cold output (G8) | Blocked; cold-start semantics unresolved |
| G4 selection | Five-way ambiguity remains; no candidate is selected |
| Graph coverage | 91 of 94 entries remain placeholders |
| Candidate-F | Historical and frozen |
| Full neural network, game frame, temporal sequence, D3D12/HIP presentation | Not demonstrated |

The current recorded physical-launch authorization is 5 authorized, 5 spent,
and 0 remaining. A new authorization is required before any further
project-local GPU launch.

These labels distinguish observed results from unresolved hypotheses. A
passing host check does not establish physical execution, and a narrow physical
operation does not establish a complete workload.
