// Phase 14D11 — FIRST REAL TRANSLATED DLSS-NR KERNEL on RX 6950 XT (gfx1030).
// Authorized: EXACTLY ONE launch of _Z13k_conv_splitk12ConvParams1d with the
// entry-fixed module.  NO retry.  NO warmup.  NO second case.
//
// Test design (host-emulated first — phase14d11_static/out/p14d11_preflight.json):
//   grid(1,1,1) block(32,1,1) shared=0, split_count=1 (slice-0 conv body)
//   - emulator: END @ 5258 steps; stores ONLY into slot2 payload offsets
//     [0x0, 0x800) (2048 x 1-byte, every byte of [0,2048) once); ds traffic
//     within LDS [0,4096); no global loads; no OOB; no UNDEF reads.
//   - the WMMA-replacement fragment cluster is NOT entered on this config
//     (identical on the ORIGINAL gfx1100 under the same config); slice-0
//     conv body + quantized byte-store epilogue ARE exercised.
//   - output VALUES derive from hardware LDS state (kernel reads its own
//     staging LDS; slice 0 has no input loads on this geometry), so the
//     expected result class is EXECUTION_PASS_NUMERIC_UNVERIFIED unless a
//     deterministic pattern emerges.
//
// Slot contract (visible 48-byte by-value arg, derived from module metadata
// + original gfx1100 .note + code census):
//   +0x00 u64 slot0  device allocation (no observed slice-0 access)
//   +0x08 u64 slot1  device allocation (no observed slice-0 access)
//   +0x10 u64 slot2  OUTPUT window base (stores [base+0, base+2048))
//   +0x18 u64 slot3  device allocation (no observed slice-0 access)
//   +0x20 i64 slot4  scalar 256 (signed count/offset semantics; hi=0)
//   +0x28 i32 split_count = 1
//   +0x2C u32 pad = 0 (struct is zero-initialized)
//
// Memory discipline per used slot: [guard-before 0x1000 =0x5A][payload
// 0x1000 =0xA5][guard-after 0x1000 =0x5A].  Guard bytes compared byte-exact
// after the run; any violation = FAIL/STOP (no retry).
#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <vector>

static int failures = 0;
#define CHECK(cond, what)                                                 \
    do {                                                                  \
        if (cond) {                                                       \
            printf("PASS: %s\n", what);                                   \
        } else {                                                          \
            printf("FAIL: %s\n", what);                                   \
            ++failures;                                                   \
        }                                                                 \
    } while (0)

struct ConvParams1d {          // 48-byte visible by-value arg block
    uint64_t slot0;            // +0x00
    uint64_t slot1;            // +0x08
    uint64_t slot2;            // +0x10  (output window base)
    uint64_t slot3;            // +0x18
    int64_t  slot4;            // +0x20  (=256; scalar)
    int32_t  split_count;      // +0x28  (=1)
    uint32_t pad;              // +0x2C  (=0)
};

static const size_t kGuard = 0x1000;
static const size_t kPayload = 0x1000;
static const size_t kBufTotal = kGuard + kPayload + kGuard;   // 12 KiB
static const uint8_t kCanary = 0x5A;
static const uint8_t kFill = 0xA5;
static const int kDeviceIndex = 0;

static uint8_t* g_dev[4] = {nullptr, nullptr, nullptr, nullptr};
static std::vector<uint8_t> g_host[4];

// Verify one 12-KiB guarded allocation copied back.  Report per window.
// mode 2 = output slot: payload [0x0,0x800) expected written (values from
// hardware LDS), [0x800,0x1000) expected untouched.
static void check_buffer(int idx, bool expect_written_low)
{
    const uint8_t* b = g_host[idx].data();
    size_t g1 = 0, g2 = 0, payload_changed = 0, payload_low_changed = 0;
    for (size_t i = 0; i < kGuard; ++i) {
        g1 += (b[i] != kCanary);
    }
    for (size_t i = kGuard + kPayload; i < kBufTotal; ++i) {
        g2 += (b[i] != kCanary);
    }
    for (size_t i = kGuard; i < kGuard + kPayload; ++i) {
        payload_changed += (b[i] != kFill);
    }
    for (size_t i = kGuard; i < kGuard + 0x800; ++i) {
        payload_low_changed += (b[i] != kFill);
    }
    char msg[160];
    std::snprintf(msg, sizeof msg,
                  "slot%zu guards before=%zu after=%zu payload_changed=%zu",
                  (size_t)idx, g1, g2, payload_changed);
    CHECK(g1 == 0 && g2 == 0, msg);
    if (expect_written_low) {
        std::snprintf(msg, sizeof msg,
                      "slot%zu low half [0,2048): bytes changed from 0xA5 = %zu "
                      "(expect >= 1024: kernel store pass ran)",
                      (size_t)idx, payload_low_changed);
        CHECK(payload_low_changed >= 1024, msg);
        size_t high_untouched = 0;
        for (size_t i = kGuard + 0x800; i < kGuard + kPayload; ++i) {
            high_untouched += (b[i] == kFill);
        }
        std::snprintf(msg, sizeof msg,
                      "slot%zu high half [2048,4096): untouched bytes = %zu/2048",
                      (size_t)idx, high_untouched);
        CHECK(high_untouched == 2048, msg);
    } else {
        std::snprintf(msg, sizeof msg,
                      "slot%zu payload fully untouched = %s (%zu changed)",
                      (size_t)idx, payload_changed == 0 ? "yes" : "NO",
                      payload_changed);
        CHECK(payload_changed == 0, msg);
    }
}

static double ms_since(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: p14d11_conv_splitk_host.exe code_object.co\n";
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<char> image((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
    if (image.empty()) {
        std::cerr << "cannot read code object: " << argv[1] << "\n";
        return 2;
    }
    printf("code_object=%s bytes=%zu\n", argv[1], image.size());

    auto t_wall0 = std::chrono::steady_clock::now();
    hipError_t error = hipInit(0);
    printf("hipInit=%d (%.3f ms)\n", (int)error, ms_since(t_wall0));
    if (error != hipSuccess) { return 3; }

    int dev = -1;
    error = hipGetDevice(&dev);
    printf("hipGetDevice=%d current=%d\n", (int)error, dev);
    hipDeviceProp_t props{};
    error = hipGetDeviceProperties(&props, kDeviceIndex);
    printf("hipGetDeviceProperties(%d)=%d\n", kDeviceIndex, (int)error);
    if (error != hipSuccess) { return 3; }
    printf("device=%s arch=%s\n", props.name, props.gcnArchName);
    if (std::string(props.gcnArchName).find("gfx1030") == std::string::npos) {
        printf("FAIL: target device is not gfx1030\n");
        return 3;
    }

    hipModule_t module = nullptr;
    error = hipModuleLoadData(&module, image.data());
    printf("hipModuleLoadData=%d (%.3f ms)\n", (int)error, ms_since(t_wall0));
    if (error != hipSuccess) { return 4; }

    hipFunction_t function = nullptr;
    error = hipModuleGetFunction(&function, module,
                                 "_Z13k_conv_splitk12ConvParams1d");
    printf("hipModuleGetFunction(conv_splitk)=%d\n", (int)error);
    if (error != hipSuccess) { return 5; }

    // ---- guarded allocations ----
    for (int i = 0; i < 4; ++i) {
        error = hipMalloc(&g_dev[i], kBufTotal);
        printf("hipMalloc slot%zu=%d\n", (size_t)i, (int)error);
        if (error != hipSuccess) { return 6; }
        error = hipMemset(g_dev[i], kCanary, kBufTotal);
        printf("hipMemset slot%zu (0x5A)=%d\n", (size_t)i, (int)error);
        if (error != hipSuccess) { return 6; }
        error = hipMemset(g_dev[i] + kGuard, kFill, kPayload);
        printf("hipMemset slot%zu payload (0xA5)=%d\n", (size_t)i,
               (int)error);
        if (error != hipSuccess) { return 6; }
        g_host[i].resize(kBufTotal);
    }

    ConvParams1d args{};
    args.slot0 = reinterpret_cast<uint64_t>(g_dev[0] + kGuard);
    args.slot1 = reinterpret_cast<uint64_t>(g_dev[1] + kGuard);
    args.slot2 = reinterpret_cast<uint64_t>(g_dev[2] + kGuard);
    args.slot3 = reinterpret_cast<uint64_t>(g_dev[3] + kGuard);
    args.slot4 = 256;              // scalar count; hi word 0 (see header)
    args.split_count = 1;          // slice-0 conv body, positive workload
    void* kernel_params[] = {&args};
    printf("arg slots: 0=%p 1=%p 2=%p 3=%p 4=%lld split=%d\n",
           (void*)args.slot0, (void*)args.slot1, (void*)args.slot2,
           (void*)args.slot3, (long long)args.slot4, args.split_count);

    printf("launch_config=grid(1,1,1) block(32,1,1) shared=0\n");
    error = hipModuleLaunchKernel(function, 1, 1, 1, 32, 1, 1, 0, nullptr,
                                  kernel_params, nullptr);
    printf("hipModuleLaunchKernel=%d (%.3f ms)\n", (int)error,
           ms_since(t_wall0));
    error = hipGetLastError();
    printf("hipGetLastError=%d\n", (int)error);

    auto t_sync0 = std::chrono::steady_clock::now();
    hipError_t sync = hipDeviceSynchronize();
    double sync_ms = ms_since(t_sync0);
    printf("hipDeviceSynchronize=%d ms=%.4f\n", (int)sync, sync_ms);
    if (sync_ms >= 5000.0) {
        printf("HANG_SUSPECTED: sync took %.1f ms (>= 5000 ms threshold)\n",
               sync_ms);
        ++failures;
    }
    CHECK(sync_ms < 5000.0, "synchronization under the 5 s hang threshold");

    if (sync != hipSuccess) {
        printf("SYNC_ERROR: aborting verification; canary re-read only\n");
        ++failures;
    } else {
        for (int i = 0; i < 4; ++i) {
            error = hipMemcpy(g_host[i].data(), g_dev[i], kBufTotal,
                              hipMemcpyDeviceToHost);
            printf("hipMemcpy slot%zu=%d\n", (size_t)i, (int)error);
            CHECK(error == hipSuccess, "result memcpy");
        }
        printf("slot2 output stats: ");
        const uint8_t* out = g_host[2].data() + kGuard;
        size_t nz = 0;
        uint8_t mn = 0xFF, mx = 0;
        unsigned hist[16] = {0};
        for (size_t i = 0; i < 0x800; ++i) {
            uint8_t v = out[i];
            nz += (v != 0);
            mn = std::min(mn, v);
            mx = std::max(mx, v);
            hist[(v >> 4) & 0xF]++;
        }
        printf("nonzero=%zu min=%u max=%u nibble_hist=", nz, mn, mx);
        for (int h = 0; h < 16; ++h) { printf("%u,", hist[h]); }
        printf("\n");
        check_buffer(2, /*expect_written_low=*/true);
        check_buffer(0, false);
        check_buffer(1, false);
        check_buffer(3, false);
    }

    for (int i = 0; i < 4; ++i) {
        error = hipFree(g_dev[i]);
        printf("hipFree slot%zu=%d\n", (size_t)i, (int)error);
    }
    error = hipModuleUnload(module);
    printf("hipModuleUnload=%d\n", (int)error);
    printf("total_host_ms=%.3f\n", ms_since(t_wall0));

    if (failures == 0) {
        printf("\nPHASE 14D11 RESULT: EXECUTION PASS (numeric status: see "
               "output stats; structural checks all pass)\n");
        return 0;
    }
    printf("\nPHASE 14D11 RESULT: FAILURES=%d\n", failures);
    return 1;
}
