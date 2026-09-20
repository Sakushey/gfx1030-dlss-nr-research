// gfx1030 wave32 FRAGMENT-OWNERSHIP fixture.
//
// This is NOT the dense arithmetic fixture. `tests/soft_wmma_test.cpp` proves
// that the gfx1030 arithmetic path reproduces a dense 16x16x16 product; it
// says nothing about which lane owns which output element, because it stages
// the whole tile through shared memory and lets every lane read every operand
// it needs. This fixture is the one that grades the ownership contract stated
// in tests/wmma_fragment_ownership.h:
//
//   register r of lane l owns dense element (row = 2r + (l >> 4), col = l & 15)
//
// The kernel below loads its operand fragments from DENSE matrices strictly
// according to that map and writes its accumulator registers back through it.
// A wrong map therefore produces a wrong dense result, which is what makes
// the four cases below grade anything at all:
//
//   identity            A = I16, C = 0        -> D must equal B exactly
//   one_hot             A = e(3,5), C = 0     -> D row 3 must equal B row 5, all else 0
//   signed_asymmetric   A, B signed, C = 0    -> dense product, signs and magnitudes distinct
//   nonzero_accumulator same operands, C != 0 -> D == A*B + C
//
// Every input is a small dyadic value, so every fp16 product is exact in fp32
// and every sum of sixteen of them is exact too: the CPU reference must match
// bit-exactly, and the comparator's tolerance is not doing any of the work.
//
// Four guards are appended after the 256 graded outputs. They are outside the
// graded region and must still hold the pre-launch sentinel afterwards; a
// nonzero guard means the kernel wrote past the end of its tile.
#include <hip/hip_runtime.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "wmma_fragment_ownership.h"
#include "wmma_numeric_compare.h"

using wmma_fragment::kCols;
using wmma_fragment::kLanes;
using wmma_fragment::kPairs;
using wmma_fragment::kRegs;
using wmma_fragment::kRows;

#define HIP_CHECK(call)                                                        \
    do {                                                                       \
        hipError_t _e = (call);                                                \
        if (_e != hipSuccess) {                                                \
            std::cerr << "HIP error: " << hipGetErrorString(_e)                \
                      << " (" << static_cast<int>(_e) << ")"                    \
                      << " at " << __FILE__ << ":" << __LINE__ << "\n";         \
            std::exit(2);                                                      \
        }                                                                      \
    } while (0)

typedef _Float16 half2v __attribute__((ext_vector_type(2)));

__device__ __forceinline__
float rdna2_dot2(_Float16 a0, _Float16 a1,
                 _Float16 b0, _Float16 b1,
                 float acc)
{
    half2v a = {a0, a1};
    half2v b = {b0, b1};
    return __builtin_amdgcn_fdot2(a, b, acc, false);
}

__device__ __forceinline__
_Float16 half_from_bits(uint16_t bits)
{
    union { uint16_t b; _Float16 v; } h{};
    h.b = bits;
    return h.v;
}

__device__ __forceinline__
float dot2_packed(unsigned int a, unsigned int b, float acc)
{
    return rdna2_dot2(half_from_bits(static_cast<uint16_t>(a & 0xFFFFu)),
                      half_from_bits(static_cast<uint16_t>(a >> 16)),
                      half_from_bits(static_cast<uint16_t>(b & 0xFFFFu)),
                      half_from_bits(static_cast<uint16_t>(b >> 16)),
                      acc);
}

// The validated phase-7C fragment procedure, unchanged in shape: one
// ds_bpermute_b32 plus one v_dot2c_f32_f16 per (register, k-pair).
__device__ __forceinline__
void wmma_fragment_accumulate(const unsigned int A[kPairs],
                              const unsigned int B[kPairs],
                              const float C[kRegs],
                              float D[kRegs])
{
    const int lane = static_cast<int>(threadIdx.x) & 31;
    const int parity = wmma_fragment::parity_of(lane);
    #pragma unroll
    for (int r = 0; r < kRegs; ++r) {
        const int a_lane = wmma_fragment::a_source_lane(r, parity);
        float acc = C[r];
        #pragma unroll
        for (int j = 0; j < kPairs; ++j) {
            const unsigned int a = __shfl(A[j], a_lane, 32);
            acc = dot2_packed(a, B[j], acc);
        }
        D[r] = acc;
    }
}

// Loads fragments from dense operands strictly through the ownership map.
// inA, inB: 16x16 fp16, row-major, in the low half of each u16.
// inC:      16x16 f32, row-major.
// outD:     16x16 f32, row-major.
__global__ void fragment_ownership_kernel(
    const uint16_t* __restrict__ inA,
    const uint16_t* __restrict__ inB,
    const float* __restrict__ inC,
    float* __restrict__ outD)
{
    const int lane = static_cast<int>(threadIdx.x) & 31;
    const int parity = wmma_fragment::parity_of(lane);
    const int col = wmma_fragment::col_of(lane);

    unsigned int a[kPairs] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned int b[kPairs] = {0, 0, 0, 0, 0, 0, 0, 0};
    float c[kRegs] = {0, 0, 0, 0, 0, 0, 0, 0};
    float d[kRegs] = {0, 0, 0, 0, 0, 0, 0, 0};

    // B: this lane's own column.
    #pragma unroll
    for (int j = 0; j < kPairs; ++j) {
        b[j] = wmma_fragment::pack_half_pair(
            inB[(2 * j) * kCols + col], inB[(2 * j + 1) * kCols + col]);
    }
    // A: rows live one per lane in lanes 0..15; lane `sl` holds row `sl`.
    if (lane < wmma_fragment::kARowLanes) {
        #pragma unroll
        for (int j = 0; j < kPairs; ++j) {
            a[j] = wmma_fragment::pack_half_pair(
                inA[lane * kCols + 2 * j], inA[lane * kCols + 2 * j + 1]);
        }
    }
    // C: register r of this lane holds row 2r + parity.
    #pragma unroll
    for (int r = 0; r < kRegs; ++r) {
        c[r] = inC[wmma_fragment::row_of(lane, r) * kCols + col];
    }

    wmma_fragment_accumulate(a, b, c, d);

    #pragma unroll
    for (int r = 0; r < kRegs; ++r) {
        outD[wmma_fragment::row_of(lane, r) * kCols + col] = d[r];
    }
}

// ---------------------------------------------------------------------------
// Independent CPU reference: plain dense row-major multiply in double.
// It shares no code with the kernel and knows nothing about lanes.
// ---------------------------------------------------------------------------
static void dense_reference(const std::vector<double>& A,
                            const std::vector<double>& B,
                            const std::vector<double>& C,
                            std::vector<float>& out)
{
    out.assign(kRows * kCols, 0.0f);
    for (int r = 0; r < kRows; ++r) {
        for (int c = 0; c < kCols; ++c) {
            double s = C[r * kCols + c];
            for (int k = 0; k < kCols; ++k) {
                s += A[r * kCols + k] * B[k * kCols + c];
            }
            out[r * kCols + c] = static_cast<float>(s);
        }
    }
}

// Small integers -> exact in fp16, exact products, exact sums.
static uint16_t half_bits_of_int(int v)
{
    union { uint16_t b; _Float16 v; } h{};
    h.v = static_cast<_Float16>(v);
    return h.b;
}

namespace {

struct Case {
    std::string name;
    std::vector<double> A, B, C;
};

std::vector<double> zeros()
{
    return std::vector<double>(kRows * kCols, 0.0);
}

// Deterministic signed pattern with distinct magnitudes and both signs.
std::vector<double> signed_pattern(int salt)
{
    std::vector<double> m(kRows * kCols, 0.0);
    for (int r = 0; r < kRows; ++r) {
        for (int c = 0; c < kCols; ++c) {
            int v = ((r * 7 + c * 5 + salt * 3) % 17) - 8;   // -8..8
            m[r * kCols + c] = static_cast<double>(v);
        }
    }
    return m;
}

std::vector<Case> build_cases()
{
    std::vector<Case> cases;

    {
        Case k;
        k.name = "identity";
        k.A = zeros();
        for (int i = 0; i < kRows; ++i) {
            k.A[i * kCols + i] = 1.0;
        }
        k.B = signed_pattern(1);
        k.C = zeros();
        cases.push_back(k);
    }
    {
        Case k;
        k.name = "one_hot";
        k.A = zeros();
        k.A[3 * kCols + 5] = 1.0;          // A = e(3,5): D row 3 == B row 5
        k.B = signed_pattern(2);
        k.C = zeros();
        cases.push_back(k);
    }
    {
        Case k;
        k.name = "signed_asymmetric";
        k.A = signed_pattern(3);
        k.B = signed_pattern(4);
        k.C = zeros();
        cases.push_back(k);
    }
    {
        Case k;
        k.name = "nonzero_accumulator";
        k.A = signed_pattern(5);
        k.B = signed_pattern(6);
        k.C = zeros();
        for (int r = 0; r < kRows; ++r) {
            for (int c = 0; c < kCols; ++c) {
                // multi-16ths, both signs: exact in fp32
                int v = ((r * 3 + c * 11 + 7) % 33) - 16;   // -16..16
                k.C[r * kCols + c] = static_cast<double>(v) / 16.0;
            }
        }
        cases.push_back(k);
    }
    return cases;
}

}  // namespace

int main()
{
    constexpr std::size_t kGraded = kRows * kCols;   // 256
    constexpr std::size_t kGuards = 4;
    constexpr std::size_t kTotal = kGraded + kGuards;
    constexpr float kTolerance = 1.0e-3f;

    std::cout << "gfx1030 wave32 fragment-ownership fixture\n";
    std::cout << "-----------------------------------------\n";
    std::cout << "contract: register r of lane l owns (row = 2r + (l>>4), col = l & 15)\n";

    int count = 0;
    HIP_CHECK(hipGetDeviceCount(&count));
    if (count < 1) {
        std::cerr << "No HIP device detected.\n";
        return 2;
    }
    hipDeviceProp_t prop{};
    HIP_CHECK(hipGetDeviceProperties(&prop, 0));
    std::cout << "GPU:       " << prop.name << "\n";
    std::cout << "warpSize:  " << prop.warpSize << "\n";
    if (prop.warpSize != 32) {
        std::cerr << "STOP: fragment ownership is wave32-specific; this device "
                     "is not wave32. Nothing was graded.\n";
        return 4;
    }

    uint16_t *dA = nullptr, *dB = nullptr;
    float *dC = nullptr, *dD = nullptr;
    HIP_CHECK(hipMalloc(&dA, kGraded * sizeof(uint16_t)));
    HIP_CHECK(hipMalloc(&dB, kGraded * sizeof(uint16_t)));
    HIP_CHECK(hipMalloc(&dC, kGraded * sizeof(float)));
    HIP_CHECK(hipMalloc(&dD, kTotal * sizeof(float)));

    std::vector<float> got(kTotal);
    int failures = 0;

    for (const Case& tc : build_cases()) {
        std::vector<uint16_t> hA(kGraded), hB(kGraded);
        std::vector<float> hC(kGraded);
        for (std::size_t i = 0; i < kGraded; ++i) {
            hA[i] = half_bits_of_int(static_cast<int>(tc.A[i]));
            hB[i] = half_bits_of_int(static_cast<int>(tc.B[i]));
            hC[i] = static_cast<float>(tc.C[i]);
        }

        std::vector<float> ref;
        dense_reference(tc.A, tc.B, tc.C, ref);

        HIP_CHECK(hipMemcpy(dA, hA.data(), kGraded * sizeof(uint16_t),
                            hipMemcpyHostToDevice));
        HIP_CHECK(hipMemcpy(dB, hB.data(), kGraded * sizeof(uint16_t),
                            hipMemcpyHostToDevice));
        HIP_CHECK(hipMemcpy(dC, hC.data(), kGraded * sizeof(float),
                            hipMemcpyHostToDevice));

        // Pre-fill the whole output buffer, guards included, so an element the
        // kernel never wrote is visible as an untouched sentinel rather than
        // as whatever happened to be in the allocation.
        wmma_check::fill_sentinel(got.data(), kTotal);
        HIP_CHECK(hipMemcpy(dD, got.data(), kTotal * sizeof(float),
                            hipMemcpyHostToDevice));

        hipLaunchKernelGGL(fragment_ownership_kernel, dim3(1), dim3(kLanes), 0, 0,
                           dA, dB, dC, dD);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipDeviceSynchronize());

        HIP_CHECK(hipMemcpy(got.data(), dD, kTotal * sizeof(float),
                            hipMemcpyDeviceToHost));

        const wmma_check::Config cfg(kTolerance, kGraded, kGuards);
        const wmma_check::Result r =
            wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(), cfg);

        const bool pass = (r.verdict == wmma_check::Verdict::PASS);
        if (!pass) {
            ++failures;
        }
        std::cout << "\ncase " << tc.name << ": "
                  << (pass ? "PASS" : "FAIL") << "\n";
        std::cout << "  verdict      = " << wmma_check::verdict_name(r.verdict)
                  << "\n";
        std::cout << "  first bad    = " << r.index;
        if (r.index < kGraded) {
            std::cout << "  (row " << (r.index / kCols) << ", col "
                      << (r.index % kCols) << ")";
        }
        std::cout << "\n";
        std::cout << "  max abs err  = " << std::scientific << r.max_abs << "\n"
                  << std::defaultfloat;
        std::cout << "  compared     = " << r.n_compared << " of " << kGraded
                  << "\n";
        if (!pass && r.index < kGraded) {
            std::cout << "  got          = " << got[r.index]
                      << "  ref = " << ref[r.index] << "\n";
        }
    }

    HIP_CHECK(hipFree(dA));
    HIP_CHECK(hipFree(dB));
    HIP_CHECK(hipFree(dC));
    HIP_CHECK(hipFree(dD));

    std::cout << "\nResult: " << (failures == 0 ? "PASS" : "FAIL")
              << "  (" << failures << " of 4 cases failed)\n";
    if (failures == 0) {
        std::cout << "The wave32 fragment-ownership map is reproduced on gfx1030.\n"
                  << "This says nothing about the dense fixture's decomposition,\n"
                  << "and the dense fixture's result says nothing about this map.\n";
    }
    return failures == 0 ? 0 : 3;
}
