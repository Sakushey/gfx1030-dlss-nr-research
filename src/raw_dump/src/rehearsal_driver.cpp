// Phase 16AT RAW_DUMP -- the no-GPU rehearsal driver.
//
// WHAT IT DRIVES
//   A real launch path: the project's own HIP telemetry bridge
//   (phase16_bridge_telemetry/src/amdhip64_7.cpp) with the RAW_DUMP capture
//   point wired in by p16at_apply_capture_point.py, built with
//   -DDLSSNR_BRIDGE_TESTING so its backend is the project's EXISTING no-GPU
//   mock, phase10_hip_bridge/mock_hip6.dll. That mock is unmodified; nothing
//   in this directory imports, loads or calls any HIP runtime.
//
//   The driver registers two of the 15 identities through the bridge's own
//   __hipRegisterFunction, constructs their by-value parameter images in
//   guard-canyoned host memory -- the way a generated launch site does -- and
//   calls the bridge's hipLaunchKernel with a real void** args array.
//
//   It then writes, into the arm's run directory:
//     fixture_blob.bin        the target image AS CONSTRUCTED, before the call
//     post_launch_blob.bin    the same ADDRESS read again after the call
//     marker_blob.bin         the frame-marker image
//     driver_result.json      return codes, canary state, addresses, and the
//                             values baked in at the requested offsets
//
//   The verifier compares the emitted record against these artefacts. Nothing
//   here asserts anything; it produces evidence only.
//
// ARMS
//   clean                    two launches, nothing disturbed afterwards
//   mutate_after_capture     one byte of the target image flipped AFTER the
//                            bridge call returned -- i.e. after the capture
//                            point -- so the record and the image disagree
//   pre_emission_null_image  the target launch hands over args[0] == nullptr:
//                            the by-value image was never constructed, so the
//                            emission point is not reached
//
// Usage:
//   rehearsal_driver.exe --bridge <dll> --out <dir> --arm <arm>
//                        [--gate 0|1] [--recorder 0|1]
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

struct Dim3 {
    unsigned x, y, z;
};
typedef int (*LaunchKernelFn)(const void*, Dim3, Dim3, void**, size_t, void*);
typedef void (*RegisterFunctionFn)(void**, const void*, char*, const char*,
                                   unsigned int, void*, void*, void*, void*,
                                   int*);

namespace {

const char* kMarkerIdentity = "_Z10k_flag_setPjj";                 // 4 B, {0x0}
const char* kTargetIdentity = "_Z14k_dec_upsample11DecUpParams";   // 40 B,{0x0,0x20}
const unsigned kTargetBytes = 40;
const unsigned kArenaBytes = 64;      // [0,40) image, [40,64) canary
const unsigned char kCanary = 0xA5;

// Baked into the target image at its two requested offsets. Constants here so
// the verifier can PREDICT them instead of reading them back out of the very
// artefact it is checking.
const unsigned char kTargetPtr[8] = {0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
                                     0x00, 0x02};                   // @0x00
const unsigned char kTargetScalar[4] = {0xDE, 0xC0, 0xDE, 0x01};    // @0x20
const unsigned char kMarkerScalar[4] = {0x11, 0x22, 0x33, 0x44};    // @0x00

bool write_file(const char* path, const void* p, size_t n)
{
    FILE* f = std::fopen(path, "wb");
    if (!f) { return false; }
    size_t w = n ? std::fwrite(p, 1, n, f) : 0;
    std::fflush(f);
    std::fclose(f);
    return w == n;
}

void join(char* out, size_t cap, const char* dir, const char* name)
{
    std::snprintf(out, cap, "%s\\%s", dir, name);
}

const char* arg_of(int argc, char** argv, const char* name, const char* dflt)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], name) == 0) { return argv[i + 1]; }
    }
    return dflt;
}

// A Windows path dropped raw into a JSON string is not valid JSON ("\U" is not
// an escape). driver_result.json is re-parsed by the control runner, so every
// string this driver emits goes through here -- the arm name too, which arrives
// from argv and is therefore caller-supplied rather than a literal. The first
// version escaped only the bridge path and left --arm raw: the same
// escaped-one-site-left-the-others defect the recorder itself had.
void json_escape(const char* s, char* out, size_t cap)
{
    size_t j = 0;
    for (const char* q = s; q != nullptr && *q != '\0' && j + 6 < cap; ++q) {
        unsigned char c = (unsigned char)*q;
        switch (c) {
        case '"':  out[j++] = '\\'; out[j++] = '"';  break;
        case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
        case '\b': out[j++] = '\\'; out[j++] = 'b';  break;
        case '\f': out[j++] = '\\'; out[j++] = 'f';  break;
        case '\n': out[j++] = '\\'; out[j++] = 'n';  break;
        case '\r': out[j++] = '\\'; out[j++] = 'r';  break;
        case '\t': out[j++] = '\\'; out[j++] = 't';  break;
        default:
            if (c < 0x20) { j += (size_t)std::snprintf(out + j, cap - j, "\\u%04x", c); }
            else { out[j++] = (char)c; }
        }
    }
    out[j] = '\0';
}

}  // namespace

int main(int argc, char** argv)
{
    const char* bridge_path = arg_of(argc, argv, "--bridge", nullptr);
    const char* out = arg_of(argc, argv, "--out", nullptr);
    const char* arm = arg_of(argc, argv, "--arm", "clean");
    const char* gate_s = arg_of(argc, argv, "--gate", "1");
    const char* rec_s = arg_of(argc, argv, "--recorder", "1");
    if (!bridge_path || !out) {
        std::fprintf(stderr, "usage: %s --bridge <dll> --out <dir> --arm <arm>\n",
                     argv[0]);
        return 2;
    }
    const bool gate = (gate_s[0] == '1');
    const bool recorder_on = (rec_s[0] == '1');

    CreateDirectoryA(out, nullptr);

    char bridge_log[600];
    join(bridge_log, sizeof(bridge_log), out, "bridge.log");
    SetEnvironmentVariableA("DLSSNR_BRIDGE_LOG", bridge_log);
    // Process-local, and only for this rehearsal process. The gate is being
    // turned ON deliberately: the point is to exercise the FULL path including
    // the backend submission, so that "identical launch descriptor" has
    // something to compare. (The gate is OFF in every deployed run.)
    SetEnvironmentVariableA("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH", gate ? "1" : "0");
    DeleteFileA(bridge_log);
    // The mock writes its log into the process CWD, so each arm gets its own.
    SetCurrentDirectoryA(out);
    DeleteFileA("mock_hip6.log");

    SetEnvironmentVariableA("RAW_DUMP_DIR", out);
    SetEnvironmentVariableA("RAW_DUMP", recorder_on ? "1" : "0");
    SetEnvironmentVariableA("RAW_DUMP_KERNELS", "all");

    HMODULE bridge = LoadLibraryExA(bridge_path, nullptr,
                                    LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!bridge) {
        std::fprintf(stderr, "LOAD_FAILED %s error=%lu\n", bridge_path,
                     (unsigned long)GetLastError());
        return 3;
    }
    RegisterFunctionFn reg =
        (RegisterFunctionFn)GetProcAddress(bridge, "__hipRegisterFunction");
    LaunchKernelFn launch =
        (LaunchKernelFn)GetProcAddress(bridge, "hipLaunchKernel");
    if (!reg || !launch) {
        std::fprintf(stderr, "bridge exports missing reg=%p launch=%p\n",
                     (void*)reg, (void*)launch);
        return 4;
    }

    // Distinct host-function addresses so the bridge's registration ledger can
    // tell the two kernels apart.
    static int s_marker_fn = 0;
    static int s_target_fn = 0;

    char marker_name[160];
    char target_name[160];
    std::snprintf(marker_name, sizeof(marker_name), "%s", kMarkerIdentity);
    std::snprintf(target_name, sizeof(target_name), "%s", kTargetIdentity);
    char marker_dev[160];
    char target_dev[160];
    std::snprintf(marker_dev, sizeof(marker_dev), "%s", kMarkerIdentity);
    std::snprintf(target_dev, sizeof(target_dev), "%s", kTargetIdentity);
    reg(nullptr, &s_marker_fn, marker_dev, marker_name, 0, nullptr, nullptr,
        nullptr, nullptr, nullptr);
    reg(nullptr, &s_target_fn, target_dev, target_name, 0, nullptr, nullptr,
        nullptr, nullptr, nullptr);

    // ---- the by-value images, in guard-canyoned arenas -------------------
    static unsigned char marker_arena[kArenaBytes];
    static unsigned char target_arena[kArenaBytes];
    std::memset(marker_arena, kCanary, sizeof(marker_arena));
    std::memset(target_arena, kCanary, sizeof(target_arena));

    std::memcpy(marker_arena + 0x00, kMarkerScalar, 4);
    std::memcpy(target_arena + 0x00, kTargetPtr, 8);
    // A deterministic, offset-keyed filler everywhere else, so a shift or a
    // truncation changes bytes at every position rather than only at the two
    // offsets of interest.
    for (unsigned i = 8; i < kTargetBytes; ++i) {
        target_arena[i] = (unsigned char)(0x10 + i);
    }
    std::memcpy(target_arena + 0x20, kTargetScalar, 4);

    char f_fixture[600], f_marker[600], f_post[600];
    join(f_fixture, sizeof(f_fixture), out, "fixture_blob.bin");
    join(f_marker, sizeof(f_marker), out, "marker_blob.bin");
    join(f_post, sizeof(f_post), out, "post_launch_blob.bin");
    write_file(f_fixture, target_arena, kTargetBytes);
    write_file(f_marker, marker_arena, 4);

    void* marker_args[1];
    void* target_args[1];
    marker_args[0] = marker_arena;
    const bool null_image = (std::strcmp(arm, "pre_emission_null_image") == 0);
    target_args[0] = null_image ? nullptr : (void*)target_arena;

    Dim3 grid{1, 1, 1};
    Dim3 block{64, 1, 1};

    int rc_marker = launch(&s_marker_fn, grid, block, marker_args, 0, nullptr);
    int rc_target = launch(&s_target_fn, grid, block, target_args, 0, nullptr);

    // AFTER the capture point: mutate the image the bridge already recorded.
    bool mutated_after = false;
    if (std::strcmp(arm, "mutate_after_capture") == 0) {
        target_arena[0x20] ^= 0xFF;
        mutated_after = true;
    }

    bool canary_target_intact = true;
    bool canary_marker_intact = true;
    for (unsigned i = kTargetBytes; i < kArenaBytes; ++i) {
        if (target_arena[i] != kCanary) { canary_target_intact = false; }
        if (marker_arena[i] != kCanary) { canary_marker_intact = false; }
    }
    // Also: the bytes BEFORE the image must be untouched -- the shift mutant
    // reads past the end, so only the tail canary can see it, but a mutant that
    // read backwards would show here.
    (void)write_file(f_post, target_arena, kTargetBytes);

    char res[600];
    join(res, sizeof(res), out, "driver_result.json");
    char bridge_json[1200];
    json_escape(bridge_path, bridge_json, sizeof(bridge_json));
    // Every string field, escaped the same way -- including arm, which is argv.
    char arm_json[600];
    char marker_json[600];
    char target_json[600];
    json_escape(arm, arm_json, sizeof(arm_json));
    json_escape(kMarkerIdentity, marker_json, sizeof(marker_json));
    json_escape(kTargetIdentity, target_json, sizeof(target_json));
    char json[4096];
    std::snprintf(
        json, sizeof(json),
        "{\n"
        " \"schema\": \"p16at/raw-dump-rehearsal-driver/1\",\n"
        " \"arm\": \"%s\",\n"
        " \"gate\": %s,\n"
        " \"recorder_enabled\": %s,\n"
        " \"bridge\": \"%s\",\n"
        " \"backend\": \"phase10_hip_bridge/mock_hip6.dll (existing project "
        "no-GPU mock, unmodified)\",\n"
        " \"gpu_execution_performed\": false,\n"
        " \"hip_runtime_imported\": false,\n"
        " \"marker_identity\": \"%s\",\n"
        " \"target_identity\": \"%s\",\n"
        " \"target_blob_bytes\": %u,\n"
        " \"target_arena_address\": \"%p\",\n"
        " \"marker_arena_address\": \"%p\",\n"
        " \"target_args0\": \"%p\",\n"
        " \"rc_marker\": %d,\n"
        " \"rc_target\": %d,\n"
        " \"mutated_after_capture\": %s,\n"
        " \"canary_target_tail_intact\": %s,\n"
        " \"canary_marker_tail_intact\": %s,\n"
        " \"requested_offsets\": [0, 32],\n"
        " \"baked_value_at_offset_0x20_hex\": \"dec0de01\",\n"
        " \"baked_value_at_offset_0x00_hex\": "
        "\"0000000040000002\"\n"
        "}\n",
        arm_json, gate ? "true" : "false", recorder_on ? "true" : "false",
        bridge_json, marker_json, target_json, kTargetBytes,
        (void*)target_arena, (void*)marker_arena, target_args[0], rc_marker,
        rc_target, mutated_after ? "true" : "false",
        canary_target_intact ? "true" : "false",
        canary_marker_intact ? "true" : "false");
    if (!write_file(res, json, std::strlen(json))) {
        std::fprintf(stderr, "could not write %s\n", res);
        return 5;
    }

    std::printf("DRIVER arm=%s gate=%d recorder=%d rc_marker=%d rc_target=%d "
                "mutated_after=%d canary_target=%d canary_marker=%d\n",
                arm, (int)gate, (int)recorder_on, rc_marker, rc_target,
                (int)mutated_after, (int)canary_target_intact,
                (int)canary_marker_intact);
    FreeLibrary(bridge);
    return 0;
}
