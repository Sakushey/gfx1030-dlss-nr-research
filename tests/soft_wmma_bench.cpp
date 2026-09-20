#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <vector>

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

// One wave computes one 16x16 output tile. Each block is one bounded logical
// operation; all blocks reuse the same input tile and write a distinct output.
__global__ void soft_wmma_16x16x16_batch(
    const float* __restrict__ A,
    const float* __restrict__ B,
    float* __restrict__ C)
{
    __shared__ _Float16 As[16 * 16];
    __shared__ _Float16 Bs[16 * 16];

    const int lane = static_cast<int>(threadIdx.x);
    const int tile = static_cast<int>(blockIdx.x);

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

    float* tile_c = C + tile * 256;
    #pragma unroll
    for (int r = 0; r < 8; ++r) {
        tile_c[(row_base + r) * 16 + col] = acc[r];
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

static double max_abs_error(const std::vector<float>& got,
                            const std::vector<float>& ref,
                            int tiles)
{
    double max_abs = 0.0;
    const std::size_t elements = static_cast<std::size_t>(tiles) * 256;
    for (std::size_t i = 0; i < elements; ++i) {
        max_abs = std::max(max_abs,
                           std::abs(static_cast<double>(got[i]) -
                                    static_cast<double>(ref[i % 256])));
    }
    return max_abs;
}

int main()
{
    constexpr int kMaxIterations = 10000;
    constexpr float kAbortMs = 2000.0f;
    constexpr double kTolerance = 1.0e-3;
    constexpr int kBatches[] = {10, 100, 1000, 10000};

    std::cout << "gfx1030 soft-WMMA bounded benchmark\n";
    std::cout << "----------------------------------\n";
    std::cout << "Hard limits: max iterations=" << kMaxIterations
              << ", per-batch abort=" << kAbortMs << " ms\n";

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
    std::cout << "VRAM:      " << std::fixed << std::setprecision(2)
              << (static_cast<double>(prop.totalGlobalMem) /
                  (1024.0 * 1024.0 * 1024.0))
              << " GiB\n";
    if (prop.warpSize != 32) {
        std::cerr << "STOP: benchmark expects wave32.\n";
        return 4;
    }

    std::vector<float> A(256), B(256), ref(256);
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
    const std::size_t c_bytes = static_cast<std::size_t>(kMaxIterations) *
                                256 * sizeof(float);
    HIP_CHECK(hipMalloc(&dA, 256 * sizeof(float)));
    HIP_CHECK(hipMalloc(&dB, 256 * sizeof(float)));
    HIP_CHECK(hipMalloc(&dC, c_bytes));
    std::vector<float> got(static_cast<std::size_t>(kMaxIterations) * 256);

    HIP_CHECK(hipMemcpy(dA, A.data(), 256 * sizeof(float), hipMemcpyHostToDevice));
    HIP_CHECK(hipMemcpy(dB, B.data(), 256 * sizeof(float), hipMemcpyHostToDevice));

    hipStream_t stream{};
    HIP_CHECK(hipStreamCreate(&stream));

    hipEvent_t start{}, stop{};
    HIP_CHECK(hipEventCreate(&start));
    HIP_CHECK(hipEventCreate(&stop));

    bool all_passed = true;
    for (const int iterations : kBatches) {
        if (iterations > kMaxIterations) {
            std::cerr << "STOP: internal batch exceeds hard limit.\n";
            all_passed = false;
            break;
        }

        const std::size_t batch_bytes = static_cast<std::size_t>(iterations) *
                                        256 * sizeof(float);
        HIP_CHECK(hipMemsetAsync(dC, 0, batch_bytes, stream));
        HIP_CHECK(hipStreamSynchronize(stream));
        const auto host_start = std::chrono::steady_clock::now();
        HIP_CHECK(hipEventRecord(start, stream));

        hipLaunchKernelGGL(soft_wmma_16x16x16_batch,
                           dim3(static_cast<unsigned>(iterations)), dim3(32),
                           0, stream, dA, dB, dC);
        HIP_CHECK(hipGetLastError());
        HIP_CHECK(hipEventRecord(stop, stream));
        HIP_CHECK(hipEventSynchronize(stop));
        HIP_CHECK(hipStreamSynchronize(stream));
        const auto host_end = std::chrono::steady_clock::now();

        float elapsed_ms = 0.0f;
        HIP_CHECK(hipEventElapsedTime(&elapsed_ms, start, stop));
        HIP_CHECK(hipMemcpy(got.data(), dC, batch_bytes, hipMemcpyDeviceToHost));

        const double host_ms = std::chrono::duration<double, std::milli>(
                                   host_end - host_start)
                                   .count();
        const double max_abs = max_abs_error(got, ref, iterations);
        const bool pass = max_abs <= kTolerance;
        const double us_per_tile =
            (static_cast<double>(elapsed_ms) * 1000.0) / iterations;

        std::cout << "batch iterations=" << iterations
                  << " elapsed GPU ms=" << std::setprecision(6) << elapsed_ms
                  << " host wait ms=" << host_ms
                  << " avg us/tile=" << us_per_tile
                  << " max abs error=" << std::scientific << max_abs
                  << " correctness=" << (pass ? "PASS" : "FAIL")
                  << " HIP errors=none\n" << std::defaultfloat;

        if (!pass || elapsed_ms > kAbortMs) {
            if (!pass) {
                std::cout << "STOP: correctness failed; no further escalation.\n";
            } else {
                std::cout << "STOP: batch exceeded the hard time guard; no further escalation.\n";
            }
            all_passed = false;
            break;
        }
    }

    HIP_CHECK(hipEventDestroy(start));
    HIP_CHECK(hipEventDestroy(stop));
    HIP_CHECK(hipStreamDestroy(stream));
    HIP_CHECK(hipFree(dA));
    HIP_CHECK(hipFree(dB));
    HIP_CHECK(hipFree(dC));

    std::cout << "Benchmark result: " << (all_passed ? "PASS" : "STOP/FAIL") << "\n";
    return all_passed ? 0 : 3;
}
