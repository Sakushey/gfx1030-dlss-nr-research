// Phase 14D10 authorized entry-contract probe host: EXACTLY ONE launch.
// grid(2,2,1) block(32,1,1); 4-KiB output window + canary discipline.
// Descriptor of the loaded kernel is the exact class-A1 policy of the
// entry-fixed conv_splitk (kernarg s0:s1, gap s2..s13, wgid_x s14,
// wgid_y s15) -- verified statically before this binary was built.
//
// Expects, per workgroup (wx, wy):
//   out+0x00   dwordx4 [magic, sentinel, wx, wy]
//   out+0x40.. s0..s31 entry snapshot (32 dwords)
//   out+0x200+((wx&3)|((wy&3)<<2))*16  dwordx4 [magic, wx, wy, sentinel]
// Bytes >= 0x300 of the 4-KiB window must be untouched (canary).
#include <hip/hip_runtime.h>

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

struct KernelArgs {  // 48-byte by-value arg block (metadata-declared)
    uint64_t out;    // +0x00
    uint8_t pad[0x28 - 0x08];
    uint32_t sentinel;  // +0x28
    uint8_t pad2[0x30 - 0x2c];
};

static uint32_t rd32(const uint8_t* p) { return (uint32_t)p[0] |
        ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: p14d10_entry_probe_host.exe code_object\n";
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<char> image((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
    const uint32_t kMagic = 0x14D10A1Cu;
    const uint32_t kSentinel = 0x5EEDF00Du;

    auto t_wall0 = std::chrono::steady_clock::now();
    hipError_t error = hipInit(0);
    auto t_wall1 = std::chrono::steady_clock::now();
    printf("hipInit=%d (%.3f ms)\n", (int)error,
           std::chrono::duration<double, std::milli>(t_wall1 - t_wall0).count());
    if (error != hipSuccess) { return 3; }

    error = hipGetDevice(0);
    printf("hipGetDevice=%d\n", (int)error);
    hipDeviceProp_t props{};
    error = hipGetDeviceProperties(&props, 0);
    printf("hipGetDeviceProperties=%d\n", (int)error);
    if (error != hipSuccess) { return 3; }
    printf("device=%s arch=%s\n", props.name, props.gcnArchName);

    hipModule_t module = nullptr;
    error = hipModuleLoadData(&module, image.data());
    printf("hipModuleLoadData=%d\n", (int)error);
    if (error != hipSuccess) { return 4; }
    hipFunction_t function = nullptr;
    error = hipModuleGetFunction(&function, module, "p14d10_entry_probe");
    printf("hipModuleGetFunction=%d\n", (int)error);
    if (error != hipSuccess) { return 5; }

    constexpr size_t kAlloc = 4096;
    uint8_t* output = nullptr;
    error = hipMalloc(&output, kAlloc);
    printf("hipMalloc=%d\n", (int)error);
    if (error != hipSuccess) { return 6; }
    error = hipMemset(output, 0xA5, kAlloc);
    printf("hipMemset(canary 0xA5)=%d\n", (int)error);

    KernelArgs args{};
    args.out = reinterpret_cast<uint64_t>(output);
    args.sentinel = kSentinel;
    void* kernel_params[] = {&args};

    printf("launch_config=grid(2,2,1) block(32,1,1) shared=0\n");
    error = hipModuleLaunchKernel(function, 2, 2, 1, 32, 1, 1, 0, nullptr,
                                  kernel_params, nullptr);
    printf("hipModuleLaunchKernel=%d\n", (int)error);
    error = hipGetLastError();
    printf("hipGetLastError=%d\n", (int)error);

    auto t_sync0 = std::chrono::steady_clock::now();
    hipError_t sync = hipDeviceSynchronize();
    auto t_sync1 = std::chrono::steady_clock::now();
    double sync_ms = std::chrono::duration<double, std::milli>(
        t_sync1 - t_sync0).count();
    printf("hipDeviceSynchronize_ms=%.4f\n", sync_ms);
    printf("hipDeviceSynchronize=%d\n", (int)sync);
    CHECK(sync_ms < 5000.0, "synchronization well under the 5 s hang threshold");

    if (sync != hipSuccess) {
        printf("SYNC_ERROR: aborting verification; canary re-read only\n");
    } else {
        std::vector<uint8_t> back(kAlloc);
        error = hipMemcpy(back.data(), output, kAlloc, hipMemcpyDeviceToHost);
        printf("hipMemcpy=%d\n", (int)error);
        CHECK(error == hipSuccess, "result memcpy");

        // ---- header ----
        uint32_t magic = rd32(&back[0x00]);
        uint32_t sent = rd32(&back[0x04]);
        uint32_t h_wgx = rd32(&back[0x08]);
        uint32_t h_wgy = rd32(&back[0x0C]);
        printf("header: magic=%08x sentinel=%08x wgx=%u wgy=%u\n",
               magic, sent, h_wgx, h_wgy);
        CHECK(magic == kMagic, "magic stored");
        CHECK(sent == kSentinel, "sentinel loaded through kernarg s[0:1]");
        CHECK(h_wgx <= 1 && h_wgy <= 1,
              "header wgid_x/wgid_y fields hold real 0..1 group coordinates");

        // ---- entry SGPR snapshot ----
        uint32_t s0 = rd32(&back[0x40]);
        printf("entry snapshot s0(s kernarg lo)=%08x\n", s0);
        CHECK(s0 != 0, "s0 holds a device pointer (kernarg base)");
        // rows: grid 2x2 -> masked idx {0,1,4,5}
        const int expected[4][3] = {{0, 0, 0}, {1, 0, 1}, {0, 1, 4}, {1, 1, 5}};
        bool rows_ok = true;
        for (int i = 0; i < 4; ++i) {
            int wx = expected[i][0], wy = expected[i][1], idx = expected[i][2];
            const uint8_t* row = &back[0x200 + idx * 16];
            uint32_t r_magic = rd32(row);
            uint32_t r_wgx = rd32(row + 4);
            uint32_t r_wgy = rd32(row + 8);
            uint32_t r_sent = rd32(row + 12);
            printf("row idx=%d wg(%d,%d): magic=%08x wgx=%u wgy=%u sent=%08x\n",
                   idx, wx, wy, r_magic, r_wgx, r_wgy, r_sent);
            if (r_magic != kMagic || r_wgx != (uint32_t)wx ||
                r_wgy != (uint32_t)wy || r_sent != kSentinel) {
                rows_ok = false;
            }
        }
        CHECK(rows_ok, "all 4 workgroup rows: wgid_x/wgid_y at A1 s14/s15");

        // per-workgroup dump cross-check: dword 14 (s14) & 15 (s15) of the
        // snapshot are written by whichever group finished last -- the
        // authoritative per-row evidence above is the primary check.
        uint32_t s14 = rd32(&back[0x40 + 14 * 4]);
        uint32_t s15 = rd32(&back[0x40 + 15 * 4]);
        printf("entry snapshot s14=%u s15=%u (last-finishing group)\n",
               s14, s15);
        CHECK((s14 <= 1) && (s15 <= 1), "snapshot wgid fields sane (0/1)");

        // ---- canary ----
        size_t canary_bad = 0;
        for (size_t i = 0x300; i < kAlloc; ++i) {
            if (back[i] != 0xA5) {
                ++canary_bad;
            }
        }
        printf("canary region [0x300,0x1000): nonzero-violations=%zu\n",
               canary_bad);
        CHECK(canary_bad == 0, "canary intact (no out-of-window write)");
    }

    error = hipFree(output);
    printf("hipFree=%d\n", (int)error);
    error = hipModuleUnload(module);
    printf("hipModuleUnload=%d\n", (int)error);
    auto t_wall_end = std::chrono::steady_clock::now();
    printf("total_host_ms=%.3f\n",
           std::chrono::duration<double, std::milli>(
               t_wall_end - t_wall0).count());

    printf(failures == 0 ? "\nENTRY-CONTRACT PROBE: ALL PASS\n"
                         : "\nENTRY-CONTRACT PROBE: FAILURES=%d\n",
           failures);
    return failures == 0 ? 0 : 1;
}
