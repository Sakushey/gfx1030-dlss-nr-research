// The wave32 16x16x16 fragment-ownership contract, as one place.
//
// Host- and device-compilable, no dependencies. Every fixture that claims to
// exercise fragment ownership includes this header, so the map is stated once
// and a fixture cannot quietly use a different one.
//
// The contract
// ------------
// A 16x16x16 fragment operation distributes three operand matrices and one
// accumulator over 32 lanes:
//
//   A       16x16, one row per lane, in lanes 0..15 only. Lane `sl` holds
//           row `sl`, packed as 8 dwords: A_reg[j] = { A[sl][2j], A[sl][2j+1] }.
//   B       16x16, one COLUMN per lane. Lane l holds column (l & 15), packed
//           the same way: B_reg[j] = { B[2j][c], B[2j+1][c] } with c = l & 15.
//   C/D     16x16 f32, 8 registers per lane. Lane l owns column (l & 15) and
//           the eight rows 2r + p for r = 0..7, where p = l >> 4. Register r
//           of lane l is the element at (row = 2r + p, col = l & 15).
//
// Register r of lane l therefore holds row 2r + p. The two halves of the wave
// interleave rows: lanes 0..15 own the even rows and lanes 16..31 the odd
// rows, and the A row a lane needs for register r is fetched from lane
// `2r + p` -- which is the same number as the output row, which is exactly
// why an implementation can gather A with `__shfl(A[k/2], row, 32)`.
//
// Where this comes from
// ---------------------
// `src/harness/p14ei_b_host.cpp` (`soft_wmma_fragment_no_lds`, Phase 7C) is
// the project's validated statement of this procedure: 64 `ds_bpermute_b32`
// plus 64 `v_dot2c_f32_f16` per fragment, no barriers, no LDS. Its CPU mirror
// uses the same lane/source rule. Phase 14EI Probe B ran eight waves of it
// physically on gfx1030 and the mirror matched bit-exactly.
//
// This is NOT the map the dense arithmetic fixture uses
// -------------------------------------------------------------------------
// `tests/soft_wmma_test.cpp` stages the whole tile through shared memory and
// gives lane l rows `(l >> 4) * 8 .. + 7`, all sixteen columns of each row
// via a k-loop over shared memory. That is a legitimate dense-arithmetic
// decomposition and it is a *different* decomposition from this one. The two
// must not be conflated: passing the dense fixture says nothing about the
// ownership contract below, and `test_fragment_ownership.py` contains a
// negative control that measures exactly how differently they land.
#ifndef WMMA_FRAGMENT_OWNERSHIP_H
#define WMMA_FRAGMENT_OWNERSHIP_H

namespace wmma_fragment {

// Geometry of one fragment operation.
constexpr int kRows = 16;
constexpr int kCols = 16;
constexpr int kLanes = 32;
constexpr int kRegs = 8;   // per-lane f32 accumulator registers
constexpr int kPairs = 8;  // per-lane packed fp16 dwords (16 halves)

// Rows of A live one per lane, in lanes 0..15.
constexpr int kARowLanes = 16;

// ---- the map ------------------------------------------------------------

// Which lane owns dense element (row, col) of C/D.
constexpr int lane_of(int row, int col) { return ((row & 1) << 4) | col; }

// Which accumulator register of that lane owns it.
constexpr int reg_of(int row) { return row >> 1; }

// Inverse direction.
constexpr int parity_of(int lane) { return lane >> 4; }
constexpr int col_of(int lane) { return lane & 15; }
constexpr int row_of(int lane, int r) { return 2 * r + parity_of(lane); }

// The A row that register r of a lane with parity p needs, and the lane that
// holds it. They are the same number because A row i lives in lane i.
constexpr int a_source_lane(int r, int p) { return 2 * r + p; }
constexpr int a_row_source_lane(int row) { return row; }

// Interleave two fp16 halves into the packed dword form the fragments use.
// `constexpr`, not `inline`: a constexpr function is implicitly available to
// both host and device code, so this header stays compilable by a plain host
// C++ compiler (which has no __host__/__device__) and by HIP clang alike.
constexpr unsigned int pack_half_pair(unsigned int lo, unsigned int hi)
{
    return (lo & 0xFFFFu) | ((hi & 0xFFFFu) << 16);
}

}  // namespace wmma_fragment

#endif  // WMMA_FRAGMENT_OWNERSHIP_H
