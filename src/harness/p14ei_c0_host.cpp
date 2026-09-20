// Phase 14EI Probe C0 — TOP-512 ACCESSIBILITY AT THE REAL REQUEST SIZE.
// Authorized (phase plan §8): ONLY if C2 completed cleanly. ONE launch.
// Question: with a workgroup REQUESTING 15,632 B (authentic SWIN
// k_swin_var<32,false> group_segment_fixed_size, kd d0 = 0x3D10), which
// addresses can the physical allocator actually serve?
//   [0, 0x3D10)     in logical request
//   [0x3D10,0x3E00) in CP LDS_SIZE representation (31x512 B = 15,872)
//   [0x3E00,0x4000) above CP rep, below 16-KiB block boundary
// Classification: LOGICAL_LIMIT / CP_LIMIT / PHYSICAL_16K_ACCESS /
// OTHER.  Never touch >= 0x4000.
#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

typedef unsigned int u32;

__device__ __forceinline__ u32 c0_ld_b32(u32 a)
{
    u32 v;
    __asm__ volatile("ds_read_b32 %0, %1" : "=v"(v) : "v"(a) : "memory");
    return v;
}
__device__ __forceinline__ void c0_st_b32(u32 a, u32 d)
{
    __asm__ volatile("ds_write_b32 %1, %0" : : "v"(d), "v"(a) : "memory");
}
__device__ __forceinline__ void c0_wait()
{
    __asm__ volatile("s_waitcnt lgkmcnt(0)" : : : "memory");
}

// Points to test (dword addresses; all < 0x4000).
// Sentinel value self-describing: 0xA5000000 | low-12 bits of address.
static constexpr u32 kPoints[] = {
    0x0000, 0x1000, 0x2000, 0x3C00,       // deep inside the request
    0x3D00, 0x3D0C,                        // in request, near top
    0x3D10,                                // request byte boundary (15,632)
    0x3DFC,                                // in CP span, above request
    0x3E00, 0x3E08,                        // CP nominal end boundary
    0x3F00, 0x3FFC,                        // top region of 16-KiB block
};
static constexpr u32 kN = sizeof(kPoints) / sizeof(kPoints[0]);
static constexpr u32 sent(u32 dw) { return 0xA5000000u | (dw & 0xFFFu); }

__global__ void c0_probe_kernel(u32* res)
{
    if (threadIdx.x != 0) return;
    // write phase (all low addresses < 0x4000, within any plausible alloc)
    for (u32 i = 0; i < kN; ++i) c0_st_b32(kPoints[i], sent(kPoints[i]));
    c0_wait();
    // read phase, drain before storing
    u32 t[12];
    for (u32 i = 0; i < kN; ++i) t[i] = c0_ld_b32(kPoints[i]);
    c0_wait();
    res[0] = 0xC0C0C0C0u;
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
    printf("device: %s  gcnArchName=%s  wave32=%u\n", prop.name,
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
    // Authentic SWIN group-segment request: 15,632 bytes, dynamic 0.
    hipLaunchKernelGGL(c0_probe_kernel, dim3(1), dim3(32), 15632u, 0,
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
    CHECK(r[0] == 0xC0C0C0C0u && r[1] == kN, "header");
    printf("addr      band                          result\n");
    int okIn = 0, okInN = 0, okCp = 0, okAb = 0;
    for (u32 i = 0; i < kN; ++i) {
        u32 a = kPoints[i], v = r[2 + i], e = sent(a);
        const char* band;
        if (a < 0x3D10) { band = "in-request"; okInN++; okIn += (v == e); }
        else if (a < 0x3E00) { band = "cp-span"; okCp += (v == e); }
        else { band = "above-cp"; okAb += (v == e); }
        printf("0x%04X  %-12s sentinel=%s\n", a, band,
               v == e ? "SURVIVES" : (v == 0 ? "ZERO" : "OTHER"));
        CHECK(v == e || v == 0, "clean sentinel-or-zero per point");
    }
    printf("in-request survives %d/%d; cp-span survives %d/3; "
           "above-cp survives %d/4\n", okIn, okInN, okCp, okAb);
    if (okIn == okInN) {
        if (okCp == 3 && okAb == 4)
            printf("C0_VERDICT: PHYSICAL_16K_ACCESS (sentinels at 0x3FFC "
                   "survive under a 15,632-B request)\n");
        else if (okCp == 3 && okAb == 0)
            printf("C0_VERDICT: CP_LIMIT (usable to 15,872 = CP LDS_SIZE "
                   "span; 16-KiB block top NOT served)\n");
        else if (okCp == 0 && okAb == 0)
            printf("C0_VERDICT: LOGICAL_LIMIT (only the exact 15,632-B "
                   "request served)\n");
        else
            printf("C0_VERDICT: OTHER (mixed pattern: cp=%d/3 above=%d/4)\n",
                   okCp, okAb);
    } else {
        printf("C0_VERDICT: OTHER (in-request reads failed %d/%d)\n",
               okIn, okInN);
    }
    hipFree(devb);
    printf("EXIT failures=%d\n", failures);
    return failures ? 1 : 0;
}
