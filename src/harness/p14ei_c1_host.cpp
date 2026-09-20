// Phase 14EI Probe C1 — 0x0000 vs 0x4000 DISTINCTNESS.
// Authorized (phase plan §9): ONLY if C0 completed cleanly. ONE launch.
// Allocation >= 32 KiB (32,768 B request).  Sentinel A @0x0000,
// sentinel B @0x4000, plus 0x0100 vs 0x4100; self-check point 0x7FFC
// near the 32-KiB top.  Distinct A/B => the old "addr & 0x3FFF"
// 14-bit-wrap hardware model is REFUTED.  No access >= 0x8000.
#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

typedef unsigned int u32;

__device__ __forceinline__ u32 c1_ld_b32(u32 a)
{
    u32 v;
    __asm__ volatile("ds_read_b32 %0, %1" : "=v"(v) : "v"(a) : "memory");
    return v;
}
__device__ __forceinline__ void c1_st_b32(u32 a, u32 d)
{
    __asm__ volatile("ds_write_b32 %1, %0" : : "v"(d), "v"(a) : "memory");
}
__device__ __forceinline__ void c1_wait()
{
    __asm__ volatile("s_waitcnt lgkmcnt(0)" : : : "memory");
}

// A-pair @ 0x0000/0x0100, B-pair @ 0x4000/0x4100, self-check @ 0x7FFC.
static constexpr u32 kPoints[] = { 0x0000, 0x4000, 0x0100, 0x4100, 0x7FFC };
static constexpr u32 kN = sizeof(kPoints) / sizeof(kPoints[0]);
static constexpr u32 sent(u32 dw) { return 0xB0000000u | (dw & 0xFFFFu); }

__global__ void c1_probe_kernel(u32* res)
{
    if (threadIdx.x != 0) return;
    for (u32 i = 0; i < kN; ++i) c1_st_b32(kPoints[i], sent(kPoints[i]));
    c1_wait();
    u32 t[8];
    for (u32 i = 0; i < kN; ++i) t[i] = c1_ld_b32(kPoints[i]);
    c1_wait();
    res[0] = 0xC1C1C1C1u;
    res[1] = kN;
    for (u32 i = 0; i < kN; ++i) res[2 + i] = t[i];
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
    printf("device: %s  gcnArchName=%s\n", prop.name, prop.gcnArchName);

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
    hipLaunchKernelGGL(c1_probe_kernel, dim3(1), dim3(32), 32768u, 0,
                       (u32*)(devb + kGuard));
    CHECK(hipGetLastError() == hipSuccess, "launch");
    hipError_t se = hipDeviceSynchronize();
    double ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();
    CHECK(se == hipSuccess, "sync");
    printf("SYNC_ELAPSED_MS=%.3f\n", ms);
    CHECK(hipMemcpy(host.data(), devb, kTotal, hipMemcpyDeviceToHost)
              == hipSuccess, "copy back");
    size_t g1 = 0, g2 = 0;
    for (size_t i = 0; i < kGuard; ++i) g1 += (host[i] != 0x5A);
    for (size_t i = kGuard + kPayload; i < kTotal; ++i) g2 += (host[i] != 0x5A);
    CHECK(g1 == 0 && g2 == 0, "canaries");

    const u32* r = (const u32*)(host.data() + kGuard);
    CHECK(r[0] == 0xC1C1C1C1u && r[1] == kN, "header");
    for (u32 i = 0; i < kN; ++i) {
        u32 a = kPoints[i], v = r[2 + i];
        printf("0x%04X: %s\n", a,
               v == sent(a) ? "sentinel SURVIVES" : (v == 0 ? "ZERO" : "OTHER"));
        CHECK(v == sent(a), "point returned its own sentinel");
    }
    u32 a0 = r[2 + 0], a1 = r[2 + 1];   // 0x0000 vs 0x4000
    u32 b0 = r[2 + 2], b1 = r[2 + 3];   // 0x0100 vs 0x4100
    if (a0 == sent(0x0000) && a1 == sent(0x4000) && a0 != a1)
        printf("C1_VERDICT: DISTINCT — 0x0000 and 0x4000 hold different "
               "sentinels under a 32-KiB allocation; the old 'addr & 0x3FFF' "
               "14-bit-wrap hardware model is REFUTED\n");
    else if (a0 == sent(0x0000) && a1 == sent(0x0000))
        printf("C1_VERDICT: ALIAS — 0x4000 aliases 0x0000 (unexpected 16-KiB "
               "ring behavior under a 32-KiB allocation)\n");
    else
        printf("C1_VERDICT: OTHER (a0=0x%08X a1=0x%08X)\n", a0, a1);
    if (b0 == sent(0x0100) && b1 == sent(0x4100) && b0 != b1)
        printf("C1_B_PAIR: DISTINCT (0x0100 vs 0x4100)\n");
    hipFree(devb);
    printf("EXIT failures=%d\n", failures);
    return failures ? 1 : 0;
}
