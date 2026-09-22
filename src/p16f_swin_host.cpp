// Phase 16F — authorized: EXACTLY ONE launch of
//   _Z10k_swin_varILi32ELb0EEv9VarParams  (k_swin_var<32,false>)
// with the candidate-E module (gfx1030_dlssnr_candidate_e.co) on
// RX 6950 XT (gfx1030), HIP 6.4 module API. No warmup, no retry, no
// second case, no other kernel.
//
// Config (mirror of phase16f_runtime preflight, host-emulated first):
//   grid(1,1,1) block(256,1,1) shared=0  — ONE workgroup, 8 waves.
//   VarParams (authentic cell-A decode, 168 B): X=576 Y=960 pair 0/0
//   flags=0x1 @ +0x18/+0x1C/+0x20/+0x24/+0x28; u64 pointer fields at
//   +0x00/+0x08/+0x10/+0x30/+0x38/+0x48/+0x78/+0x80/+0xA0 -> guarded
//   device buffers; all other fields 0 (+0x98 = 0). Hidden args are
//   HIP-filled from the launch (grid dims, group sizes).
//   Emulator (p16f_mirror_swin32f_A_g1.json): ALL_ENDED 16945 ticks,
//   14 barrier epochs, all 8 waves ENDED, 0 LDS memviol / 0 OOB DS.
//   Modeled global reach: canvas (+0xA0) loads to base+~31 MiB and
//   stores in [0,0xA01C0] x {+0, +0x50000, +0xA0000} families -> the
//   +0xA0 payload is 40 MiB; every other slot 1 MiB.
//
// Buffers: [guard 0x1000 =0x5A][payload =0x00][guard 0x1000 =0x5A].
// Guards compared byte-exact after the run. The canary fill is
// verified by a pre-launch device->host readback (the phase-14E
// post-TDR ambiguity cannot recur on a clean run).
// One attempt only; a >5 s synchronization is treated as a hang
// signature (the phase-14E watchdog fired at ~18 s); no relaunch.
#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static int failures = 0;
static int anomalies = 0;
#define CHECK(cond, what)                                                 \
    do {                                                                  \
        if (cond) {                                                       \
            printf("PASS: %s\n", what);                                   \
        } else {                                                          \
            printf("FAIL: %s\n", what);                                   \
            ++failures;                                                   \
        }                                                                 \
    } while (0)
#define ANOMALY(what)                                                     \
    do {                                                                  \
        printf("ANOMALY: %s\n", what);                                    \
        ++anomalies;                                                      \
    } while (0)

static const size_t kGuard = 0x1000;
static const size_t kPayloadSmall = 0x100000;       // 1 MiB
static const size_t kPayloadCanvas = 0x2800000;     // 40 MiB (canvas +0xA0)
static const size_t kNPtr = 9;
// field offsets of the nine u64 pointers inside VarParams
static const size_t kPtrOff[kNPtr] = {0x00, 0x08, 0x10, 0x30, 0x38, 0x48,
                                      0x78, 0x80, 0xA0};
static const uint8_t kCanary = 0x5A;
static const uint8_t kFill = 0x00;

static uint8_t* g_dev[kNPtr];
static size_t g_payload[kNPtr];
static std::vector<uint8_t> g_host[kNPtr];

static void put_u64(uint8_t* p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) { p[i] = (uint8_t)(v >> (8 * i)); }
}

static void put_u32(uint8_t* p, uint32_t v)
{
    for (int i = 0; i < 4; ++i) { p[i] = (uint8_t)(v >> (8 * i)); }
}

static double ms_since(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: p16f_swin_host.exe code_object.co\n";
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
    error = hipGetDeviceProperties(&props, 0);
    printf("hipGetDeviceProperties(0)=%d\n", (int)error);
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
                                 "_Z10k_swin_varILi32ELb0EEv9VarParams");
    printf("hipModuleGetFunction(swin_var<32,false>)=%d\n", (int)error);
    if (error != hipSuccess) { return 5; }

    // ---- guarded allocations ----
    for (size_t i = 0; i < kNPtr; ++i) {
        bool canvas = (kPtrOff[i] == 0xA0);
        g_payload[i] = canvas ? kPayloadCanvas : kPayloadSmall;
        error = hipMalloc(&g_dev[i], kGuard + g_payload[i] + kGuard);
        printf("hipMalloc f[%zu]@+0x%zx payload=0x%zx=%d\n", i, kPtrOff[i],
               g_payload[i], (int)error);
        if (error != hipSuccess) { return 6; }
        error = hipMemset(g_dev[i], kCanary, kGuard + g_payload[i] + kGuard);
        if (error != hipSuccess) { return 6; }
        error = hipMemset(g_dev[i] + kGuard, kFill, g_payload[i]);
        if (error != hipSuccess) { return 6; }
        g_host[i].resize(kGuard + g_payload[i] + kGuard);
    }
    // pre-launch canary self-check (device->host) so the guard signal is
    // meaningful before the launch (phase-14E lesson)
    {
        std::vector<uint8_t> probe(kGuard);
        error = hipMemcpy(probe.data(), g_dev[0], kGuard,
                          hipMemcpyDeviceToHost);
        printf("hipMemcpy canary probe=%d\n", (int)error);
        size_t bad = 0;
        for (size_t b = 0; b < kGuard; ++b) { bad += (probe[b] != kCanary); }
        if (error != hipSuccess || bad != 0) {
            printf("FAIL: pre-launch canary self-check (bad=%zu) - aborting "
                   "without launching\n", bad);
            return 7;
        }
        printf("PASS: pre-launch canary self-check (guards are 0x5A)\n");
    }

    // ---- 168-byte VarParams (authentic cell-A decode) ----
    std::vector<uint8_t> params(168, 0);
    for (size_t i = 0; i < kNPtr; ++i) {
        put_u64(&params[kPtrOff[i]],
                reinterpret_cast<uint64_t>(g_dev[i] + kGuard));
    }
    put_u32(&params[0x18], 576);   // X (authentic)
    put_u32(&params[0x1C], 960);   // Y (authentic)
    put_u32(&params[0x20], 0);     // pair.lo
    put_u32(&params[0x24], 0);     // pair.hi
    put_u32(&params[0x28], 0x1);   // flags (authentic cell A/B value)
    // +0x98 = 0 already; all other fields 0 already
    printf("VarParams ptr fields: ");
    for (size_t i = 0; i < kNPtr; ++i) {
        printf("+0x%zx=%p ", kPtrOff[i], (void*)(g_dev[i] + kGuard));
    }
    printf("\n");
    printf("dims=576,960,0,0 flags=0x1\n");
    void* kernel_params[] = {params.data()};

    printf("launch_config=grid(1,1,1) block(256,1,1) shared=0 "
           "(ONE workgroup)\n");
    error = hipModuleLaunchKernel(function, 1, 1, 1, 256, 1, 1, 0, nullptr,
                                  kernel_params, nullptr);
    printf("hipModuleLaunchKernel=%d (%.3f ms)\n", (int)error,
           ms_since(t_wall0));
    error = hipGetLastError();
    printf("hipGetLastError(after launch)=%d\n", (int)error);

    auto t_sync0 = std::chrono::steady_clock::now();
    hipError_t sync = hipDeviceSynchronize();
    double sync_ms = ms_since(t_sync0);
    printf("hipDeviceSynchronize=%d ms=%.4f\n", (int)sync, sync_ms);
    error = hipGetLastError();
    printf("hipGetLastError(after sync)=%d\n", (int)error);
    if (sync != hipSuccess || error != hipSuccess) {
        ANOMALY("synchronization or async error (illegal address / device "
                "loss signature)");
    }
    if (sync_ms >= 5000.0) {
        printf("HANG_SUSPECTED: sync took %.1f ms (>= 5000 ms threshold; "
               "14E watchdog fired ~18 s)\n", sync_ms);
        ANOMALY("sync >= 5 s");
    } else {
        printf("PASS: synchronization under the 5 s hang threshold\n");
    }

    // ---- readback (diagnostics even after an anomaly) ----
    if (sync != hipSuccess) {
        printf("SYNC_ERROR: readback proceeds as diagnostics only\n");
        ++failures;
    }
    for (size_t i = 0; i < kNPtr; ++i) {
        error = hipMemcpy(g_host[i].data(), g_dev[i],
                          kGuard + g_payload[i] + kGuard,
                          hipMemcpyDeviceToHost);
        printf("hipMemcpy f[%zu]=%d\n", i, (int)error);
        CHECK(error == hipSuccess, "result memcpy");
    }
    // guards (byte-exact canary; any difference = OOB write or scrub =
    // anomaly)
    for (size_t i = 0; i < kNPtr; ++i) {
        size_t g1 = 0, g2 = 0;
        for (size_t b = 0; b < kGuard; ++b) {
            g1 += (g_host[i][b] != kCanary);
            g2 += (g_host[i][kGuard + g_payload[i] + b] != kCanary);
        }
        char msg[140];
        std::snprintf(msg, sizeof msg,
                      "f[%zu](+0x%zx) guards before=%zu after=%zu",
                      i, kPtrOff[i], g1, g2);
        if (g1 == 0 && g2 == 0) {
            CHECK(true, msg);
        } else {
            ANOMALY(msg);
        }
    }
    // payload change census (per slot; expectations are informational:
    // the model shows writes only into the +0xA0 canvas families and
    // nothing else at this geometry)
    for (size_t i = 0; i < kNPtr; ++i) {
        const uint8_t* p = g_host[i].data() + kGuard;
        size_t nz = 0;
        size_t mn = g_payload[i], mx = 0;
        for (size_t b = 0; b < g_payload[i]; ++b) {
            if (p[b] != kFill) {
                ++nz;
                mn = std::min(mn, b);
                mx = std::max(mx, b);
            }
        }
        printf("payload f[%zu](+0x%zx): changed=%zu first=%zu last=%zu\n",
               i, kPtrOff[i], nz, mn == g_payload[i] ? 0 : mn, mx);
        if (i == 8) {   // canvas: model predicts writes - kernel ran signal
            CHECK(nz >= 1000,
                  "canvas(+0xA0) changed bytes in plausible band (>= 1000)");
        }
    }

    for (size_t i = 0; i < kNPtr; ++i) {
        error = hipFree(g_dev[i]);
        printf("hipFree f[%zu]=%d\n", i, (int)error);
    }
    error = hipModuleUnload(module);
    printf("hipModuleUnload=%d\n", (int)error);
    printf("total_host_ms=%.3f\n", ms_since(t_wall0));

    if (anomalies == 0 && failures == 0) {
        printf("\nPHASE 16F RESULT: PHYSICAL PASS (termination + guards + "
               "no GPU anomaly; numeric status above)\n");
        return 0;
    }
    if (anomalies == 0 && failures > 0) {
        printf("\nPHASE 16F RESULT: PHYSICAL FAIL (clean error, no GPU "
               "anomaly): failures=%d\n", failures);
        return 1;
    }
    printf("\nPHASE 16F RESULT: STOP-ANOMALY (failures=%d anomalies=%d)\n",
           failures, anomalies);
    return 2;
}
