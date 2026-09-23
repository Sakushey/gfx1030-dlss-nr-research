#include <hip/hip_runtime.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#ifndef EXPECTED_GFX
#error EXPECTED_GFX must be defined explicitly (for example -DEXPECTED_GFX=\"gfx1031\")
#endif

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
// Lane mapping intentionally mirrors the GFX11 wave32 WMMA C ownership:
//   lane  0..15 -> columns 0..15, rows 0..7
//   lane 16..31 -> columns 0..15, rows 8..15
//
// This is NOT yet a drop-in replacement for v_wmma. It is a bounded
// source-level proof of the arithmetic on the explicitly compiled RDNA2 target.
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
    std::cout << "RDNA2 soft-WMMA phase-1 smoke test\n";
    std::cout << "------------------------------------\n";

    int count = 0;
    HIP_CHECK(hipGetDeviceCount(&count));
    if (count < 1) {
        std::cerr << "No HIP device detected.\n";
        return 2;
    }

    hipDeviceProp_t prop{};
    HIP_CHECK(hipGetDeviceProperties(&prop, 0));

    std::string detected_arch = prop.gcnArchName;
    const std::size_t feature_sep = detected_arch.find(':');
    if (feature_sep != std::string::npos) {
        detected_arch.resize(feature_sep);
    }

    std::cout << "GPU:       " << prop.name << "\n";
    std::cout << "GCN Arch:  " << prop.gcnArchName << "\n";
    std::cout << "Expected:  " << EXPECTED_GFX << "\n";
    std::cout << "warpSize:  " << prop.warpSize << "\n";
    std::cout << "VRAM:      "
              << std::fixed << std::setprecision(2)
              << (static_cast<double>(prop.totalGlobalMem) / (1024.0 * 1024.0 * 1024.0))
              << " GiB\n";

    if (detected_arch != EXPECTED_GFX) {
        std::cerr << "STOP: detected architecture " << detected_arch
                  << " does not match compile target " << EXPECTED_GFX << ".\n";
        return 4;
    }

    if (prop.warpSize != 32) {
        std::cerr << "STOP: this test expects wave32. Nothing was benchmarked.\n";
        return 5;
    }

    constexpr float kSentinel = 12345.25f;
    std::vector<float> A(256), B(256), ref(256), got(256, kSentinel);
    std::vector<float> initial_output(256, kSentinel);

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
    HIP_CHECK(hipMalloc(&dC, 256 * sizeof(float)));

    HIP_CHECK(hipMemcpy(dA, A.data(), 256 * sizeof(float), hipMemcpyHostToDevice));
    HIP_CHECK(hipMemcpy(dB, B.data(), 256 * sizeof(float), hipMemcpyHostToDevice));
    HIP_CHECK(hipMemcpy(dC, initial_output.data(), 256 * sizeof(float), hipMemcpyHostToDevice));

    // Deliberately tiny bounded launch: one block, one wave, one matrix tile.
    hipLaunchKernelGGL(soft_wmma_16x16x16,
                       dim3(1), dim3(32), 0, 0,
                       dA, dB, dC);
    HIP_CHECK(hipGetLastError());
    HIP_CHECK(hipDeviceSynchronize());

    HIP_CHECK(hipMemcpy(got.data(), dC, 256 * sizeof(float), hipMemcpyDeviceToHost));

    double max_abs = 0.0;
    int worst = -1;
    int untouched = 0;
    bool finite = true;
    for (int i = 0; i < 256; ++i) {
        if (got[i] == kSentinel) {
            ++untouched;
        }
        if (!std::isfinite(got[i])) {
            finite = false;
            continue;
        }
        const double e = std::abs(static_cast<double>(got[i]) -
                                  static_cast<double>(ref[i]));
        if (e > max_abs) {
            max_abs = e;
            worst = i;
        }
    }

    std::cout << "\nCorrectness:\n";
    std::cout << "  max abs error = " << std::scientific << max_abs << "\n";
    std::cout << "  untouched sentinel elements = " << untouched << "\n";
    std::cout << "  all outputs finite = " << (finite ? "yes" : "no") << "\n";
    if (worst >= 0) {
        std::cout << "  worst element = [" << (worst / 16) << "," << (worst % 16)
                  << "]  GPU=" << got[worst] << "  CPU=" << ref[worst] << "\n";
    }

    const bool pass = finite && untouched == 0 && max_abs <= 1.0e-3;

    std::cout << "\nResult: " << (pass ? "PASS" : "FAIL") << "\n";

    if (pass) {
        std::cout
            << EXPECTED_GFX << " reproduced the 16x16x16 fp16->fp32 matrix arithmetic\n"
            << "using the RDNA2 v_dot2 path. No long stress test was run.\n";
    }

    HIP_CHECK(hipFree(dA));
    HIP_CHECK(hipFree(dB));
    HIP_CHECK(hipFree(dC));

    return pass ? 0 : 3;
}
