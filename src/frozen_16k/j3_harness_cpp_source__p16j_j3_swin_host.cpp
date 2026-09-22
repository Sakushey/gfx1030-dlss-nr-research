// Phase 16J-J3 -- physical SWIN validation harness for CANDIDATE F.
//
// PREPARED, NOT AUTHORIZED.  This file builds an executable.  Running it
// performs ONE physical launch on the GPU, which is a separate, explicitly
// re-authorized act (see the Phase 16J brief's authorization boundary).
// Nothing here arms GTA, touches the game, or changes any driver setting.
//
// Kernel:   _Z10k_swin_varILi32ELb0EEv9VarParams   (k_swin_var<32,false>)
// Module:   phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co
// Dispatch: grid(1,1,1) block(256,1,1) shared=0 -- EXACTLY ONE launch.
//
// ORDER OF OPERATIONS (fixed; each step's failure aborts before the launch)
//    1  verify the device is the expected gfx1030 target
//    2  verify the code object's SHA-256 against the frozen Candidate F hash
//    3  allocate the exact required regions, each with guard bands
//    4  fill the deterministic nontrivial input pattern
//    5  verify the pre-launch guards
//    6  launch ONCE
//    7  synchronize ONCE
//    8  measure the duration
//    9  read the result back
//   10  verify the guards
//   11  collect the current Windows event state
//   12  exit
//
// There is no retry loop, no second launch, and no fallback path.  A
// synchronization that returns success after a long delay is NOT success:
// the pre-registered expectation is completion far below 1 s, and anything
// at or above 5 s is a FAIL regardless of the return code.
//
// ALLOCATION SIZING IS CONDITIONAL.  The emulator's residual global reads
// reach megabytes past the base of several pointer fields, and Phase 16J-J1
// is the job that decides whether those addresses are genuine kernel
// behaviour or a harness artifact.  Until J1 lands, `--tensor-mib` is the
// harness's stated assumption, not a fact about the game, and it is printed
// as an assumption on every run.
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
#define CHECK(cond, what)                                                 \
    do {                                                                  \
        if (cond) { printf("PASS: %s\n", what); }                         \
        else { printf("FAIL: %s\n", what); ++failures; }                  \
    } while (0)

#include "p16j_sha256.h"          // 2 -- SHA-256, shared
#include "p16j_pattern.h"         // 4 -- the input pattern, shared

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------
// The six pointer fields an authentic VarParams actually carries.  Offsets
// 0x48, 0x78 and 0x80 are authentically ZERO (proven in
// phase16i_varparams_proof.md: the host zeroes all 96 bytes of 0x40..0x9F on
// every launch path) and must NOT be given allocations here.
static const size_t kNPtr = 6;
static const size_t kPtrOff[kNPtr] = {0x00, 0x08, 0x10, 0x30, 0x38, 0xA0};

static const char* kKernel = "_Z10k_swin_varILi32ELb0EEv9VarParams";
static const char* kExpectSha =
    "47b5d1d11041b034ac30eebac090ee922f415d8f08a0111e69641d7e0557524b";

static const size_t kGuard = 0x1000;
static const uint8_t kCanary = 0x5A;
static const uint8_t kFill = 0x00;

// Authentic decode (phase16_authentic_decode_swin.csv, swin<32,false>):
static const uint32_t kX = 576, kY = 960;
static const uint32_t kPairLo = 0, kPairHi = 0, kFlags = 0x1;

static const double kExpectMs = 1000.0;    // pre-registered: far below 1 s
static const double kHardFailMs = 5000.0;  // "nowhere near 5 seconds"

static std::vector<uint8_t> g_host[kNPtr];
static uint8_t* g_dev[kNPtr];
static size_t g_payload[kNPtr];

static void put_u64(uint8_t* p, uint64_t v)
{ for (int i = 0; i < 8; ++i) { p[i] = (uint8_t)(v >> (8 * i)); } }
static void put_u32(uint8_t* p, uint32_t v)
{ for (int i = 0; i < 4; ++i) { p[i] = (uint8_t)(v >> (8 * i)); } }

static double ms_since(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
}

// 11 -- read-only Windows event state.  Queries the System log for the AMD
// display driver and the Application log for LiveKernelEvent reports, so a
// clean pre-flight and a clean post-run can both be stated from the machine
// rather than assumed.
static void event_state(const char* phase)
{
    printf("--- Windows event state (%s) ---\n", phase);
    const char* cmds[] = {
        "wevtutil qe System /q:\"*[System[Provider[@Name='amdkmdag']]]\" "
        "/c:3 /rd:true /f:text 2>&1",
        "wevtutil qe System /q:\"*[System[(Level=1 or Level=2)]]\" "
        "/c:5 /rd:true /f:text 2>&1",
        "wevtutil qe Application /q:\"*[System[Provider[@Name='Windows Error "
        "Reporting'] and (EventID=1001)]]\" /c:3 /rd:true /f:text 2>&1",
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); ++i) {
        FILE* f = _popen(cmds[i], "r");
        if (!f) { printf("  [query %zu unavailable]\n", i); continue; }
        char line[512];
        int n = 0;
        while (fgets(line, sizeof line, f) && n < 24) {
            printf("  %s", line);
            ++n;
        }
        if (n == 0) { printf("  [query %zu: no matching events]\n", i); }
        _pclose(f);
    }
}

int main(int argc, char** argv)
{
    const char* co_path = (argc > 1) ? argv[1] : nullptr;
    uint32_t tensor_mib = (argc > 2) ? (uint32_t)atoi(argv[2]) : 64;
    if (!co_path) {
        std::cerr << "usage: p16j_j3_swin_host.exe <candidate_f.co> "
                     "[tensor-mib=64]\n";
        return 2;
    }

    auto t_all = std::chrono::steady_clock::now();

    // ---- 2 -- verify the code object BEFORE anything touches the GPU ------
    std::ifstream in(co_path, std::ios::binary);
    std::vector<char> image((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
    if (image.empty()) {
        std::cerr << "cannot read code object: " << co_path << "\n";
        return 2;
    }
    std::string got = sha256::of(image.data(), image.size());
    printf("code_object=%s bytes=%zu\n", co_path, image.size());
    printf("sha256=%s\nexpected=%s\n", got.c_str(), kExpectSha);
    CHECK(got == kExpectSha, "code object SHA-256 is the frozen Candidate F");
    if (got != kExpectSha) {
        printf("ABORT: module hash mismatch; nothing was launched.\n");
        return 2;
    }

    // ---- 1 -- device identity --------------------------------------------
    hipError_t error = hipInit(0);
    if (error != hipSuccess) { printf("hipInit=%d\n", (int)error); return 3; }
    hipDeviceProp_t props{};
    error = hipGetDeviceProperties(&props, 0);
    if (error != hipSuccess) { printf("hipGetDeviceProperties=%d\n",
                                      (int)error); return 3; }
    printf("device=%s arch=%s\n", props.name, props.gcnArchName);
    CHECK(std::string(props.gcnArchName).find("gfx1030") != std::string::npos,
          "target device is gfx1030");
    if (failures) { printf("ABORT: wrong device; nothing was launched.\n");
                    return 3; }

    event_state("pre-launch");

    hipModule_t module = nullptr;
    error = hipModuleLoadData(&module, image.data());
    printf("hipModuleLoadData=%d\n", (int)error);
    if (error != hipSuccess) { return 4; }
    hipFunction_t function = nullptr;
    error = hipModuleGetFunction(&function, module, kKernel);
    printf("hipModuleGetFunction(%s)=%d\n", kKernel, (int)error);
    if (error != hipSuccess) { return 5; }

    // ---- 3 -- exact required regions, each with guard bands --------------
    // The canvas field is sized by the dispatcher's own formula; a single
    // workgroup at wgid (0,0,0) therefore needs 1*1*8192 bytes, not a MiB.
    const size_t canvas = 1u * 1u * 8192u;
    const size_t tensor = (size_t)tensor_mib * 1024u * 1024u;
    printf("allocation assumption: canvas(+0xA0)=%zu B  tensors=%u MiB each "
           "(STATED, not measured -- see J1)\n", canvas, tensor_mib);

    for (size_t i = 0; i < kNPtr; ++i) {
        g_payload[i] = (kPtrOff[i] == 0xA0) ? canvas : tensor;
        size_t total = kGuard + g_payload[i] + kGuard;
        error = hipMalloc(&g_dev[i], total);
        if (error != hipSuccess) {
            printf("hipMalloc f[%zu]@+0x%zx=%d ABORT\n", i, kPtrOff[i],
                   (int)error);
            return 6;
        }
        // Every one of these is checked: a fill that silently failed would
        // leave the guards and the input pattern wrong, and the run would
        // then "pass" against memory that was never set up.
        error = hipMemset(g_dev[i], kCanary, total);
        if (error != hipSuccess) {
            printf("hipMemset canary f[%zu]=%d ABORT\n", i, (int)error);
            return 6;
        }
        error = hipMemset(g_dev[i] + kGuard, kFill, g_payload[i]);
        if (error != hipSuccess) {
            printf("hipMemset payload f[%zu]=%d ABORT\n", i, (int)error);
            return 6;
        }
        g_host[i].assign(total, 0);
        printf("alloc f[%zu]@+0x%02zx payload=%zu guard=0x%zx\n",
               i, kPtrOff[i], g_payload[i], kGuard);
    }

    // ---- 4 -- deterministic nontrivial input -----------------------------
    for (size_t i = 0; i < kNPtr; ++i) {
        std::vector<uint8_t> pat(g_payload[i]);
        for (size_t b = 0; b < g_payload[i]; ++b) { pat[b] = pattern_at(b); }
        error = hipMemcpy(g_dev[i] + kGuard, pat.data(), g_payload[i],
                          hipMemcpyHostToDevice);
        if (error != hipSuccess) {
            printf("input hipMemcpy f[%zu]=%d ABORT\n", i, (int)error);
            return 6;
        }
    }
    printf("input pattern: LCG(offset) low byte, never zero; first 8 bytes=");
    for (int b = 0; b < 8; ++b) { printf("%02X", pattern_at(b)); }
    printf("\n");

    // ---- 5 -- pre-launch guards ------------------------------------------
    for (size_t i = 0; i < kNPtr; ++i) {
        size_t total = kGuard + g_payload[i] + kGuard;
        error = hipMemcpy(g_host[i].data(), g_dev[i], total,
                          hipMemcpyDeviceToHost);
        if (error != hipSuccess) {
            printf("pre-guard hipMemcpy f[%zu]=%d ABORT\n", i, (int)error);
            return 6;
        }
        size_t bad = 0;
        for (size_t b = 0; b < kGuard; ++b) {
            if (g_host[i][b] != kCanary) ++bad;
            if (g_host[i][kGuard + g_payload[i] + b] != kCanary) ++bad;
        }
        char msg[140];
        std::snprintf(msg, sizeof msg, "pre-guard f[%zu] intact", i);
        CHECK(bad == 0, msg);
    }
    if (failures) { printf("ABORT: pre-guards not intact; nothing launched.\n");
                    return 6; }

    // ---- 6 -- the single launch ------------------------------------------
    std::vector<uint8_t> params(168, 0);
    for (size_t i = 0; i < kNPtr; ++i) {
        put_u64(&params[kPtrOff[i]],
                reinterpret_cast<uint64_t>(g_dev[i] + kGuard));
    }
    put_u32(&params[0x18], kX);
    put_u32(&params[0x1C], kY);
    put_u32(&params[0x20], kPairLo);
    put_u32(&params[0x24], kPairHi);
    put_u32(&params[0x28], kFlags);
    // 0x40..0x9F stay zero: 0x48/0x78/0x80 are authentically zero.
    void* kernel_params[] = {params.data()};

    printf("launch_config=grid(1,1,1) block(256,1,1) shared=0 "
           "VarParams=168B dims=%u,%u pair=%u,%u flags=0x%X\n",
           kX, kY, kPairLo, kPairHi, kFlags);
    printf("pre-registered expectation: completion far below %.0f ms; "
           "%.0f ms or more is a FAIL even if the return code is 0\n",
           kExpectMs, kHardFailMs);

    auto t_launch = std::chrono::steady_clock::now();
    error = hipModuleLaunchKernel(function, 1, 1, 1, 256, 1, 1, 0, nullptr,
                                  kernel_params, nullptr);
    printf("hipModuleLaunchKernel=%d (%.3f ms)\n", (int)error,
           ms_since(t_launch));
    if (error != hipSuccess) {
        printf("ABORT: launch failed; no retry is attempted.\n");
        return 7;
    }
    hipError_t last = hipGetLastError();
    printf("hipGetLastError=%d\n", (int)last);

    // ---- 7, 8 -- one synchronization, measured ---------------------------
    auto t_sync = std::chrono::steady_clock::now();
    hipError_t sync = hipDeviceSynchronize();
    double sync_ms = ms_since(t_sync);
    printf("hipDeviceSynchronize=%d elapsed_ms=%.4f\n", (int)sync, sync_ms);
    CHECK(sync == hipSuccess, "hipDeviceSynchronize returned success");
    CHECK(sync_ms < kHardFailMs, "synchronization under the 5 s hard limit");
    CHECK(sync_ms < kExpectMs, "synchronization inside the pre-registered "
                               "expectation (far below 1 s)");
    if (sync_ms >= kHardFailMs) {
        printf("WATCHDOG_THRESHOLD_EXCEEDED: %.1f ms -- collect evidence and "
               "stop; do not retry, do not continue to any other variant.\n",
               sync_ms);
    }

    // ---- 9, 10 -- read back and verify -----------------------------------
    if (sync == hipSuccess) {
        for (size_t i = 0; i < kNPtr; ++i) {
            size_t total = kGuard + g_payload[i] + kGuard;
            error = hipMemcpy(g_host[i].data(), g_dev[i], total,
                              hipMemcpyDeviceToHost);
            if (error != hipSuccess) {
                printf("result hipMemcpy f[%zu]=%d\n", i, (int)error);
                ++failures;
            }
        }
        for (size_t i = 0; i < kNPtr; ++i) {
            size_t bad = 0;
            for (size_t b = 0; b < kGuard; ++b) {
                if (g_host[i][b] != kCanary) ++bad;
                if (g_host[i][kGuard + g_payload[i] + b] != kCanary) ++bad;
            }
            char msg[140];
            std::snprintf(msg, sizeof msg, "post-guard f[%zu] intact", i);
            CHECK(bad == 0, msg);
        }
        // Output field (+0xA0): a structural census only.  This is a
        // termination/stability test, not an image-quality test.
        const uint8_t* out = g_host[5].data() + kGuard;   // kPtrOff[5]=0xA0
        size_t nz = 0, nz_pat = 0;
        for (size_t b = 0; b < g_payload[5]; ++b) {
            if (out[b] != pattern_at(b)) ++nz;
            if (out[b] != kFill) ++nz_pat;
        }
        printf("output(+0xA0) bytes differing from the input pattern=%zu "
               "nonzero=%zu of %zu\n", nz, nz_pat, g_payload[5]);
        char msg[160];
        std::snprintf(msg, sizeof msg,
                      "output(+0xA0) is structurally non-trivial (some bytes "
                      "written): changed=%zu", nz_pat);
        CHECK(nz_pat > 0, msg);
    }

    // ---- 11, 12 ----------------------------------------------------------
    event_state("post-run");

    for (size_t i = 0; i < kNPtr; ++i) {
        hipError_t fe = hipFree(g_dev[i]);
        if (fe != hipSuccess) { printf("hipFree f[%zu]=%d\n", i, (int)fe); }
    }
    hipError_t ue = hipModuleUnload(module);
    if (ue != hipSuccess) { printf("hipModuleUnload=%d\n", (int)ue); }
    printf("total_host_ms=%.3f\n", ms_since(t_all));

    if (failures == 0) {
        printf("\nPHASE 16J-J3 RESULT: PHYSICAL PASS (structural)\n");
        return 0;
    }
    printf("\nPHASE 16J-J3 RESULT: FAILURES=%d\n", failures);
    return 1;
}
