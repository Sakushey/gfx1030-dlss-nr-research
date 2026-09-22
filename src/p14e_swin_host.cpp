// Phase 14E — authorized: EXACTLY ONE launch of
//   _Z10k_swin_varILi32ELb0EEv9VarParams  (k_swin_var<32,false>)
// with the entry-fixed module on RX 6950 XT (gfx1030), HIP 6.4 module API.
// No warmup, no retry, no second case.
//
// Config (host-emulated first — phase14e_emulator_preflight.md):
//   grid(1,1,1) block(256,1,1) shared=0
//   VarParams 168 B: dims 64 x4 @+0x18; flags 0 @+0x28; u64 pointer fields
//   at +0x00/+0x08/+0x10/+0x30/+0x38/+0x48/+0x78/+0x80/+0xA0 -> guarded
//   device buffers; all other fields 0. Hidden args HIP-filled.
//   Emulator: END both boundary waves; 768 soft-WMMA dot2 sites executed;
//   LDS fully inside the 16-KiB partition; only out-of-window events =
//   reads <= base+0xA0010 of the +0xA0 buffer; no out-of-window store.
//
// Buffers: [guard 0x1000 =0x5A][payload 0x100000 =0x00][guard 0x1000 =0x5A]
// for all nine u64 pointer fields (payload 1 MiB >= max modeled reach
// ~0xA0010 with >5x margin). Guards compared byte-exact after the run.
// All payloads are ZERO: the emulator ran with zeroed slot memory, so the
// deterministic control flow (and every address) is identical by
// construction; the kernel's +0xA0 buffer receives the output stores.
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

static const size_t kGuard = 0x1000;
static const size_t kPayload = 0x100000;          // 1 MiB per field
static const size_t kBufTotal = kGuard + kPayload + kGuard;
static const size_t kNPtr = 9;
static const size_t kPtrOff[kNPtr] = {0x00, 0x08, 0x10, 0x30, 0x38,
                                      0x48, 0x78, 0x80, 0xA0};
static const uint8_t kCanary = 0x5A;
static const uint8_t kFill = 0x00;

static uint8_t* g_dev[kNPtr];
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
        std::cerr << "usage: p14e_swin_host.exe code_object.co\n";
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
        error = hipMalloc(&g_dev[i], kBufTotal);
        printf("hipMalloc f[%zu]@+0x%zx=%d\n", i, kPtrOff[i], (int)error);
        if (error != hipSuccess) { return 6; }
        error = hipMemset(g_dev[i], kCanary, kBufTotal);
        if (error != hipSuccess) { return 6; }
        error = hipMemset(g_dev[i] + kGuard, kFill, kPayload);
        printf("hipMemset f[%zu] guards 0x5A payload 0x00=%d\n", i,
               (int)error);
        if (error != hipSuccess) { return 6; }
        g_host[i].resize(kBufTotal);
    }

    // ---- 168-byte VarParams ----
    std::vector<uint8_t> params(168, 0);
    for (size_t i = 0; i < kNPtr; ++i) {
        put_u64(&params[kPtrOff[i]],
                reinterpret_cast<uint64_t>(g_dev[i] + kGuard));
    }
    for (int o = 0x18; o <= 0x24; o += 4) { put_u32(&params[o], 64); }
    put_u32(&params[0x28], 0);    // mode flags: uniform-window path
    // +0x50..0x6f (fp scale/hash), +0x70, +0x88..0x97, +0x98 = 0
    printf("VarParams ptr fields: ");
    for (size_t i = 0; i < kNPtr; ++i) {
        printf("+0x%zx=%p ", kPtrOff[i], (void*)(g_dev[i] + kGuard));
    }
    printf("\n");
    printf("dims=64,64,64,64 flags=0\n");
    void* kernel_params[] = {params.data()};

    printf("launch_config=grid(1,1,1) block(256,1,1) shared=0\n");
    error = hipModuleLaunchKernel(function, 1, 1, 1, 256, 1, 1, 0, nullptr,
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
        for (size_t i = 0; i < kNPtr; ++i) {
            error = hipMemcpy(g_host[i].data(), g_dev[i], kBufTotal,
                              hipMemcpyDeviceToHost);
            printf("hipMemcpy f[%zu]=%d\n", i, (int)error);
            CHECK(error == hipSuccess, "result memcpy");
        }
        // guards
        for (size_t i = 0; i < kNPtr; ++i) {
            size_t g1 = 0, g2 = 0;
            for (size_t b = 0; b < kGuard; ++b) {
                g1 += (g_host[i][b] != kCanary);
                g2 += (g_host[i][kGuard + kPayload + b] != kCanary);
            }
            char msg[140];
            std::snprintf(msg, sizeof msg,
                          "f[%zu] guards before=%zu after=%zu",
                          i, g1, g2);
            CHECK(g1 == 0 && g2 == 0, msg);
        }
        // non-output fields (0..7) must stay all-zero
        for (size_t i = 0; i < kNPtr - 1; ++i) {
            size_t nz = 0;
            for (size_t b = 0; b < kPayload; ++b) {
                nz += (g_host[i][kGuard + b] != kFill);
            }
            char msg[140];
            std::snprintf(msg, sizeof msg,
                          "f[%zu](+0x%zx) payload unchanged: changed=%zu",
                          i, kPtrOff[i], nz);
            CHECK(nz == 0, msg);
        }
        // output field 8 (+0xA0): changed byte census
        const uint8_t* out = g_host[8].data() + kGuard;
        size_t nz = 0, nz_low = 0, nz_5x = 0;
        uint8_t mn = 0xFF, mx = 0;
        size_t hist16[16] = {0};
        for (size_t b = 0; b < kPayload; ++b) {
            uint8_t v = out[b];
            if (v != kFill) {
                ++nz;
                if (b < 0x8000) { ++nz_low; }
                if (b >= 0x50000 && b < 0x60000) { ++nz_5x; }
                mn = std::min(mn, v);
                mx = std::max(mx, v);
                hist16[(v >> 4) & 0xF]++;
            }
        }
        printf("field8(+0xA0) output: changed_total=%zu changed_lo[<32K]=%zu "
               "changed_5x[0x50000..0x60000)=%zu min=%u max=%u\n",
               nz, nz_low, nz_5x, mn, mx);
        printf("  nibble histogram:");
        for (int h = 0; h < 16; ++h) { printf(" %zu", hist16[h]); }
        printf("\n");
        CHECK(nz >= 500 && nz <= 200000,
              "field8 changed-byte count in plausible band (500..200000)");
        CHECK(nz_low >= 100, "field8 low region [0,32K) shows writes");
    }

    for (size_t i = 0; i < kNPtr; ++i) {
        error = hipFree(g_dev[i]);
        printf("hipFree f[%zu]=%d\n", i, (int)error);
    }
    error = hipModuleUnload(module);
    printf("hipModuleUnload=%d\n", (int)error);
    printf("total_host_ms=%.3f\n", ms_since(t_wall0));

    if (failures == 0) {
        printf("\nPHASE 14E RESULT: EXECUTION PASS (structural; numeric "
               "status in evidence file)\n");
        return 0;
    }
    printf("\nPHASE 14E RESULT: FAILURES=%d\n", failures);
    return 1;
}
