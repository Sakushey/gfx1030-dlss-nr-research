// DENSE SOFTWARE-MATRIX ARITHMETIC FIXTURE.
//
// What this grades: that the gfx1030 `v_dot2` path reproduces the arithmetic
// of a 16x16x16 fp16->fp32 matrix product, computed densely. One wave stages
// the whole 16x16 A and B tiles through shared memory, so every lane can read
// every operand it needs, and the k-loop walks all sixteen columns directly.
//
// What this does NOT grade, and must never be described as grading: native
// WMMA fragment OWNERSHIP. This kernel has no fragment fragments -- it has a
// shared-memory tile and a per-lane set of eight output rows. The lane-to-row
// assignment below (`(lane >> 4) * 8 + r`) is a property of THIS dense
// decomposition, and it is a different assignment from the wave32
// fragment-ownership contract, under which register r of lane l owns row
// `2r + (l >> 4)`. Passing here therefore says nothing about that contract.
// The contract has its own fixture: tests/soft_wmma_fragment_test.cpp, with
// the map stated once in tests/wmma_fragment_ownership.h.
//
// See docs/proof-model.md: "passing one rung of the ladder never implies the
// next", and a matching aggregate is not equivalence.
#include <hip/hip_runtime.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <vector>

#include "wmma_numeric_compare.h"

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

// One 32-thread wave computes one complete 16x16 output tile.
//
// The lane-to-row assignment below is a property of the DENSE decomposition
// this fixture uses: lane l takes rows (l >> 4) * 8 .. + 7 and every column,
// reading A and B out of shared memory. It is NOT the wave32 WMMA fragment
// ownership map -- see the header comment, and
// tests/wmma_fragment_ownership.h for the contract that actually is.
//   lane  0..15 -> columns 0..15, rows 0..7
//   lane 16..31 -> columns 0..15, rows 8..15
//
// This is a bounded proof that gfx1030 can reproduce the dense matrix
// arithmetic using v_dot2. It is not a drop-in replacement for v_wmma.
__global__ void soft_wmma_16x16x16(
    const float* __restrict__ A,
    const float* __restrict__ B,
    float* __restrict__ C)
{
    __shared__ _Float16 As[16 * 16];
    __shared__ _Float16 Bs[16 * 16];

    const int lane = static_cast<int>(threadIdx.x);

    // Cooperative conversion/staging.  Test values are chosen to be exactly
    // representable in fp16, so conversion does not complicate validation.
    for (int i = lane; i < 256; i += 32) {
        As[i] = static_cast<_Float16>(A[i]);
        Bs[i] = static_cast<_Float16>(B[i]);
    }
    __syncthreads();

    const int col = lane & 15;
    const int row_base = (lane >> 4) * 8;

    float acc[8] = {0.0f, 0.0f, 0.0f, 0.0f,
                    0.0f, 0.0f, 0.0f, 0.0f};

    #pragma unroll
    for (int r = 0; r < 8; ++r) {
        const int row = row_base + r;

        #pragma unroll
        for (int k = 0; k < 16; k += 2) {
            const _Float16 a0 = As[row * 16 + k + 0];
            const _Float16 a1 = As[row * 16 + k + 1];
            const _Float16 b0 = Bs[(k + 0) * 16 + col];
            const _Float16 b1 = Bs[(k + 1) * 16 + col];

            acc[r] = rdna2_dot2(a0, a1, b0, b1, acc[r]);
        }
    }

    #pragma unroll
    for (int r = 0; r < 8; ++r) {
        const int row = row_base + r;
        C[row * 16 + col] = acc[r];
    }
}

static void cpu_reference(const std::vector<float>& A,
                          const std::vector<float>& B,
                          std::vector<float>& C)
{
    for (int r = 0; r < 16; ++r) {
        for (int c = 0; c < 16; ++c) {
            float s = 0.0f;
            for (int k = 0; k < 16; ++k) {
                s += A[r * 16 + k] * B[k * 16 + c];
            }
            C[r * 16 + c] = s;
        }
    }
}

int main()
{
    // Absolute tolerance for the dense fixture. Every input is a binary
    // fraction exactly representable in fp16, so a correct v_dot2 chain lands
    // on the reference exactly; the tolerance exists to bound the comparison,
    // not to absorb a defect.
    constexpr float kTolerance = 1.0e-3f;
    // Out-of-range guards appended after the 256 graded outputs. They must
    // still hold the sentinel when the kernel returns.
    constexpr std::size_t kGuards = 4;

    std::cout << "gfx1030 dense software-matrix arithmetic fixture\n";
    std::cout << "------------------------------------------------\n";
    std::cout << "Grades: dense 16x16x16 fp16->fp32 arithmetic on the v_dot2 path.\n";
    std::cout << "Does NOT grade: wave32 WMMA fragment ownership "
                 "(tests/soft_wmma_fragment_test.cpp).\n";

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
    std::cout << "VRAM:      "
              << std::fixed << std::setprecision(2)
              << (static_cast<double>(prop.totalGlobalMem) / (1024.0 * 1024.0 * 1024.0))
              << " GiB\n";

    if (prop.warpSize != 32) {
        std::cerr << "STOP: this test expects wave32. Nothing was benchmarked.\n";
        return 4;
    }

    std::vector<float> A(256), B(256), ref(256);
    std::vector<float> got(256 + kGuards, wmma_check::sentinel_value());

    // Binary fractions -> exactly representable in fp16.
    for (int r = 0; r < 16; ++r) {
        for (int k = 0; k < 16; ++k) {
            A[r * 16 + k] = static_cast<float>(((r * 3 + k * 5) % 17) - 8) / 8.0f;
        }
    }
    for (int k = 0; k < 16; ++k) {
        for (int c = 0; c < 16; ++c) {
            B[k * 16 + c] = static_cast<float>(((k * 7 + c * 2) % 19) - 9) / 8.0f;
        }
    }

    cpu_reference(A, B, ref);

    float *dA = nullptr, *dB = nullptr, *dC = nullptr;
    HIP_CHECK(hipMalloc(&dA, 256 * sizeof(float)));
    HIP_CHECK(hipMalloc(&dB, 256 * sizeof(float)));
    HIP_CHECK(hipMalloc(&dC, (256 + kGuards) * sizeof(float)));

    HIP_CHECK(hipMemcpy(dA, A.data(), 256 * sizeof(float), hipMemcpyHostToDevice));
    HIP_CHECK(hipMemcpy(dB, B.data(), 256 * sizeof(float), hipMemcpyHostToDevice));
    // Pre-fill the graded region AND the guards with the sentinel, so an
    // element the kernel never wrote and a write past the end of the tile are
    // both visible as themselves rather than as plausible numbers.
    HIP_CHECK(hipMemcpy(dC, got.data(), (256 + kGuards) * sizeof(float),
                        hipMemcpyHostToDevice));

    // Deliberately tiny bounded launch: one block, one wave, one matrix tile.
    hipLaunchKernelGGL(soft_wmma_16x16x16,
                       dim3(1), dim3(32), 0, 0,
                       dA, dB, dC);
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipDeviceSynchronize());

    HIP_CHECK(hipMemcpy(got.data(), dC, (256 + kGuards) * sizeof(float),
                        hipMemcpyDeviceToHost));

    const wmma_check::Config cfg(kTolerance, 256, kGuards);
    const wmma_check::Result r =
        wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(), cfg);
    const bool pass = (r.verdict == wmma_check::Verdict::PASS);

    std::cout << "\nVerdict: " << wmma_check::verdict_name(r.verdict) << "\n";
    std::cout << "  first bad element = " << r.index;
    if (r.index < 256) {
        std::cout << "  [" << (r.index / 16) << "," << (r.index % 16) << "]";
    }
    std::cout << "\n";
    std::cout << "  max abs error     = " << std::scientific << r.max_abs << "\n"
              << std::defaultfloat;
    std::cout << "  compared          = " << r.n_compared << " of 256\n";
    std::cout << "  guards            = " << kGuards << " (must remain untouched)\n";
    if (!pass && r.index < 256) {
        std::cout << "  GPU=" << got[r.index] << "  CPU=" << ref[r.index] << "\n";
    }
    std::cout << "\nResult: " << (pass ? "PASS" : "FAIL") << "\n";

    if (pass) {
        std::cout
            << "gfx1030 reproduced the dense 16x16x16 fp16->fp32 matrix\n"
            << "arithmetic using the RDNA2 v_dot2 path. No long stress test was\n"
            << "run. This is the dense arithmetic fixture; it does not speak to\n"
            << "fragment ownership.\n";
    }

    HIP_CHECK(hipFree(dA));
    HIP_CHECK(hipFree(dB));
    HIP_CHECK(hipFree(dC));

    return pass ? 0 : 3;
}
