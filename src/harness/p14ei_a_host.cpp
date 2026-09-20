// Phase 14EI Probe A — STOCK EIGHT-WAVE BARRIER + LDS.
// Authorized (phase plan §11): ONLY if C2/C0/C1 all completed cleanly.
// Goal: physically exonerate the combination {8-wave workgroup, LDS
// near SWIN scale, ~14 repeated workgroup barriers} with STOCK HIP6
// codegen (no inline asm, no bpermute, no WMMA, no neural code).
//
// Configuration mirrors the failed SWIN launch where it matters:
//   block 256 = 8 wave32 waves, grid 1, group segment 15,632 B
//   (authentic k_swin_var<32,false> request), ~14 deterministic
//   phases, all-wave barriers (__syncthreads) between LDS phases.
// The LDS USAGE region stays far below the measured C0 boundary
// (15,872): 8 wave windows x 256 dwords = 8 KiB of the 15,632-B
// segment.  Clarity first; no artificial register pressure.
#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

typedef unsigned int u32;

// 15,632 B static group segment (authentic SWIN group_segment_fixed_size).
__shared__ u32 buf[3908];   // 3908 * 4 = 15,632 B

constexpr u32 kPhases = 14;
constexpr u32 kWaves = 8;
constexpr u32 kLanes = 32;
constexpr u32 kWinDwords = 256;              // 1 KiB per wave window
constexpr u32 kTotalWin = kWaves * kWinDwords;  // 8 KiB, << 15,872

__device__ __forceinline__ u32 pat(u32 phase, u32 wave, u32 lane, u32 j)
{
    // Deterministic, wave/lane/phase-specific, nonzero, exactly
    // representable in u32.  Distinct per (phase,wave) so stale data
    // from any earlier phase cannot pass as current.
    return 0xE0000000u | (phase << 20) | (wave << 16) | (lane << 8) | j;
}

__global__ void a_probe_kernel(u32* res)
{
    const u32 tid = threadIdx.x;            // 0..255
    const u32 wave = tid / kLanes;          // 0..7
    const u32 lane = tid % kLanes;          // 0..31
    u32 mismatch = 0;

    for (u32 phase = 0; phase < kPhases; ++phase) {
        // phase 1: every lane writes its own 8-dword slice of its wave's window
        const u32 myBase = wave * kWinDwords + lane * 8;
        #pragma unroll
        for (u32 j = 0; j < 8; ++j) buf[myBase + j] = pat(phase, wave, lane, j);
        __syncthreads();                    // epoch barrier (all 8 waves)

        // phase 2: every lane verifies the NEXT wave's window slice
        const u32 nbWave = (wave + 1) & (kWaves - 1);
        const u32 nbBase = nbWave * kWinDwords + lane * 8;
        #pragma unroll
        for (u32 j = 0; j < 8; ++j) {
            if (buf[nbBase + j] != pat(phase, nbWave, lane, j)) ++mismatch;
        }
        __syncthreads();                    // next phase's writes must wait
    }

    res[wave * 2 + 0] = mismatch;
    res[wave * 2 + 1] = kPhases;
}

static int failures = 0;
#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) printf("PASS: %s\n", what);                               \
        else { printf("FAIL: %s\n", what); ++failures; }                    \
    } while (0)

int main()
{
    hipDeviceProp_t prop;
    CHECK(hipSetDevice(0) == hipSuccess, "hipSetDevice(0)");
    CHECK(hipGetDeviceProperties(&prop, 0) == hipSuccess, "device props");
    printf("device: %s  gcnArchName=%s  warpSize=%u\n", prop.name,
           prop.gcnArchName, prop.warpSize);

    const size_t kGuard = 0x1000, kPayload = 0x100;
    const size_t kTotal = kGuard + kPayload + kGuard;
    std::vector<uint8_t> host(kTotal, 0x5A);
    std::fill(host.begin() + kGuard, host.begin() + kGuard + kPayload, 0);
    uint8_t* devb = nullptr;
    CHECK(hipMalloc((void**)&devb, kTotal) == hipSuccess, "hipMalloc");
    CHECK(hipMemset(devb, 0x5A, kGuard) == hipSuccess, "guard1");
    CHECK(hipMemset(devb + kGuard, 0, kPayload) == hipSuccess, "payload");
    CHECK(hipMemset(devb + kGuard + kPayload, 0x5A, kGuard) == hipSuccess,
          "guard2");

    auto t0 = std::chrono::steady_clock::now();
    hipLaunchKernelGGL(a_probe_kernel, dim3(1), dim3(256), 0u, 0,
                       (u32*)(devb + kGuard));
    CHECK(hipGetLastError() == hipSuccess, "launch");
    hipError_t se = hipDeviceSynchronize();
    double ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();
    CHECK(se == hipSuccess, "sync");
    printf("SYNC_ELAPSED_MS=%.3f (5 s boundary; HANG if beyond)\n", ms);
    CHECK(ms < 5000.0, "completion under the 5-s hang boundary");
    CHECK(hipMemcpy(host.data(), devb, kTotal, hipMemcpyDeviceToHost)
              == hipSuccess, "copy back");
    size_t g1 = 0, g2 = 0;
    for (size_t i = 0; i < kGuard; ++i) g1 += (host[i] != 0x5A);
    for (size_t i = kGuard + kPayload; i < kTotal; ++i) g2 += (host[i] != 0x5A);
    CHECK(g1 == 0 && g2 == 0, "canaries");

    const u32* r = (const u32*)(host.data() + kGuard);
    int bad = 0;
    for (u32 w = 0; w < kWaves; ++w) {
        printf("wave%u: mismatches=%u phases=%u\n", w, r[w * 2], r[w * 2 + 1]);
        if (r[w * 2] != 0 || r[w * 2 + 1] != kPhases) ++bad;
    }
    CHECK(bad == 0, "all 8 waves: zero LDS mismatches over 14 phases");
    if (bad == 0)
        printf("A_VERDICT: PASS — physical 8-wave workgroup barrier/LDS "
               "coordination is exonerated at SWIN scale (block 256, "
               "14 phases, 28 workgroup barriers, 15,632-B request, "
               "8-KiB active LDS)\n");
    else
        printf("A_VERDICT: FAIL\n");
    hipFree(devb);
    printf("EXIT failures=%d\n", failures);
    return failures ? 1 : 0;
}
