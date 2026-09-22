// Phase 16AW RAW_DUMP -- the no-GPU rehearsal driver.
//
// WHAT THIS DRIVES
//   A real launch path: the project's own HIP telemetry bridge
//   (phase16_bridge_telemetry/src/amdhip64_7.cpp) with the 16AW capture point
//   wired in by p16aw_apply_capture_point.py, built with -DDLSSNR_BRIDGE_TESTING
//   so its backend resolves to the project's EXISTING no-GPU mock,
//   phase10_hip_bridge/mock_hip6.dll. That mock is unmodified. Nothing in this
//   directory imports, loads or calls any HIP runtime, and no launch is ever
//   submitted to a device: the launch gate is left OFF, and the capture point
//   sits BEFORE the gate's early return, so every rehearsal launch fires the
//   capture and then returns a real launch failure without a submission.
//
// THE POINT OF THE FIXTURE
//   Every explicit host argument of every identity is built in its OWN
//   separately-allocated region, page-aligned by VirtualAlloc, so no two
//   arguments are adjacent in host memory. Each region is filled with two
//   canaries whose VALUES DIFFER per argument index and per side, and the
//   payload is written strictly between them. The driver records the true
//   region addresses and the true gaps, so noncontiguity is a measured property
//   of the fixture and not a claim, and it re-checks every canary after every
//   launch.
//
//   The payload byte alphabet is [0x00,0xAF]; the canaries are 0xC0..0xC5. No
//   payload byte can be mistaken for a canary, so a captured tail that shows
//   canary bytes is proof that the layer read outside the argument.
//
// ARMS
//   selftest          run the layer's own checks and print them
//   capture_all       one launch of each of the 15 identities, in
//                     noncontiguous canary-surrounded storage
//   frame_authentic   replay a symbol stream (--events) through the legacy
//                     frame counter and the repaired state machine
//   frame_scenarios   eight built-in launch-sequence anomalies
//
// Usage:
//   p16aw_driver.exe --bridge <dll> --out <dir> --arm <name>
//                    [--events <file>] [--gate 0|1]
#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "raw_dump_repair_16aw.h"
#include "raw_dump_argspec_16aw.h"

struct Dim3 { unsigned x, y, z; };
typedef int (*LaunchKernelFn)(const void*, Dim3, Dim3, void**, size_t, void*);
typedef void (*RegisterFunctionFn)(void**, const void*, char*, const char*,
                                   unsigned int, void*, void*, void*, void*,
                                   int*);

namespace {

const unsigned kPrePad = 32;
const unsigned kPostPad = 32;
const unsigned long long kPtrBase = 0x00006A2B40000000ULL;

unsigned char canary_pre(unsigned j)  { return (unsigned char)(0xC0u + 2u * j); }
unsigned char canary_post(unsigned j) { return (unsigned char)(0xC1u + 2u * j); }

// The payload alphabet is 0x00..0xAF so no payload byte can be a canary.
void fill_payload(unsigned char* p, unsigned n, unsigned arg_index,
                  const char* value_kind)
{
    if (std::strcmp(value_kind, "global_buffer") == 0 && n >= 8) {
        unsigned long long v = kPtrBase + (unsigned long long)arg_index * 0x1000ULL;
        std::memcpy(p, &v, 8);
        for (unsigned i = 8; i < n; ++i) { p[i] = (unsigned char)((i * 7u + arg_index) % 0xB0u); }
        return;
    }
    if (n == 4 && std::strcmp(value_kind, "by_value") == 0) {
        unsigned v = 0x11223300u + arg_index * 0x100u;
        std::memcpy(p, &v, 4);
        return;
    }
    for (unsigned i = 0; i < n; ++i) {
        p[i] = (unsigned char)((i * 7u + arg_index * 13u) % 0xB0u);
    }
}

const char* arg_of(int argc, char** argv, const char* key, const char* dflt)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], key) == 0) { return argv[i + 1]; }
    }
    return dflt;
}

void join(char* out, size_t cap, const char* dir, const char* name)
{
    std::snprintf(out, cap, "%s\\%s", dir, name);
}

// RFC-8259 string escaping for the JSON this driver writes. The self-test
// details quote the environment value back (RAW_DUMP_16AW_MUTATION resolved to
// "NONE"), and an unescaped quote there produced a file no JSON reader would
// accept -- a check whose evidence cannot be read is not evidence.
void esc(char* dst, size_t cap, const char* s)
{
    size_t j = 0;
    for (const char* q = s; q != nullptr && *q != '\0' && j + 7 < cap; ++q) {
        unsigned char c = (unsigned char)*q;
        switch (c) {
        case '"':  dst[j++] = '\\'; dst[j++] = '"';  break;
        case '\\': dst[j++] = '\\'; dst[j++] = '\\'; break;
        case '\b': dst[j++] = '\\'; dst[j++] = 'b';  break;
        case '\f': dst[j++] = '\\'; dst[j++] = 'f';  break;
        case '\n': dst[j++] = '\\'; dst[j++] = 'n';  break;
        case '\r': dst[j++] = '\\'; dst[j++] = 'r';  break;
        case '\t': dst[j++] = '\\'; dst[j++] = 't';  break;
        default:
            if (c < 0x20) { j += (size_t)std::snprintf(dst + j, cap - j, "\\u%04x", c); }
            else { dst[j++] = (char)c; }
        }
    }
    dst[j] = '\0';
}

// CreateDirectoryA makes ONE component. The arms are run into nested
// directories (_runs\<arm>), so walk the chain: a missing parent silently made
// every arm write nothing while still reporting its counts.
void ensure_dir(const char* path)
{
    char tmp[700];
    std::snprintf(tmp, sizeof(tmp), "%s", path);
    for (char* p = tmp + 1; *p != '\0'; ++p) {
        if (*p == '\\' || *p == '/') {
            char keep = *p;
            *p = '\0';
            CreateDirectoryA(tmp, nullptr);
            *p = keep;
        }
    }
    CreateDirectoryA(tmp, nullptr);
}

// --------------------------------------------------------------- file writing
// BOM-less, UTF-8 (pure ASCII here), write-once per arm.
bool write_text(const char* dir, const char* name, const char* text, size_t n)
{
    char path[700];
    join(path, sizeof(path), dir, name);
    DeleteFileA(path);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { return false; }
    DWORD w = 0;
    BOOL ok = WriteFile(h, text, (DWORD)n, &w, nullptr);
    CloseHandle(h);
    return ok && w == (DWORD)n;
}

void hex_of(const unsigned char* p, size_t n, char* out)
{
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[i * 2] = d[p[i] >> 4]; out[i * 2 + 1] = d[p[i] & 15]; }
    out[n * 2] = '\0';
}

// ------------------------------------------------------------- the fixture
struct Region {
    unsigned char* base;       // the whole allocation
    size_t         bytes;      // the whole allocation
    unsigned char* payload;    // base + kPrePad
    unsigned       n;          // payload length
    unsigned       arg_index;
};

bool region_make(Region& r, unsigned arg_index, unsigned n)
{
    r.bytes = (size_t)kPrePad + n + kPostPad;
    r.base = (unsigned char*)VirtualAlloc(nullptr, r.bytes, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (r.base == nullptr) { return false; }
    std::memset(r.base, canary_pre(arg_index), kPrePad);
    std::memset(r.base + kPrePad + n, canary_post(arg_index), kPostPad);
    r.payload = r.base + kPrePad;
    r.n = n;
    r.arg_index = arg_index;
    return true;
}

bool region_canaries_intact(const Region& r, char* detail, size_t cap)
{
    for (unsigned i = 0; i < kPrePad; ++i) {
        if (r.base[i] != canary_pre(r.arg_index)) {
            std::snprintf(detail, cap, "pre-canary byte %u of arg %u is 0x%02X, "
                          "expected 0x%02X", i, r.arg_index, r.base[i],
                          canary_pre(r.arg_index));
            return false;
        }
    }
    for (unsigned i = 0; i < kPostPad; ++i) {
        unsigned char got = r.base[kPrePad + r.n + i];
        if (got != canary_post(r.arg_index)) {
            std::snprintf(detail, cap, "post-canary byte %u of arg %u is 0x%02X, "
                          "expected 0x%02X", i, r.arg_index, got,
                          canary_post(r.arg_index));
            return false;
        }
    }
    detail[0] = '\0';
    return true;
}

// ------------------------------------------------------------- legacy model
// A faithful model of the frame-id derivation this repair replaces, taken from
// p16at/raw_dump/src/raw_dump_recorder.cpp:486
//     if (std::strcmp(ident, "_Z10k_flag_setPjj") == 0) { ++g_frameCounter; }
//     ...
//     frame_id = g_frameCounter;  frame_src = "MARKER_K_FLAG_SET";
struct LegacyFrameMachine {
    unsigned counter;
    void reset() { counter = 0; }
    // Returns the frame id the legacy code would stamp on this launch.
    unsigned on_event(const char* symbol, const char** source)
    {
        if (std::strcmp(symbol, "_Z10k_flag_setPjj") == 0) { ++counter; }
        if (counter > 0) { *source = "MARKER_K_FLAG_SET"; return counter; }
        *source = "NO_MARKER_SEEN_YET";
        return 0;
    }
};

// ------------------------------------------------------------------- output
char g_big[512 * 1024];

void buf_reset(char* b, size_t cap) { if (cap) { b[0] = '\0'; } }

void buf_add(char* b, size_t cap, const char* fmt, ...)
{
    size_t n = std::strlen(b);
    if (n + 4 >= cap) { return; }
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(b + n, cap - n, fmt, ap);
    va_end(ap);
}

}  // namespace

int main(int argc, char** argv)
{
    const char* bridge_path = arg_of(argc, argv, "--bridge", nullptr);
    const char* out = arg_of(argc, argv, "--out", nullptr);
    const char* arm = arg_of(argc, argv, "--arm", "selftest");
    const char* events = arg_of(argc, argv, "--events", nullptr);
    const char* gate_s = arg_of(argc, argv, "--gate", "0");
    if (!out) {
        std::fprintf(stderr,
                     "usage: %s --out <dir> --arm <name> [--bridge <dll>] "
                     "[--events <file>] [--gate 0|1]\n", argv[0]);
        return 2;
    }
    CreateDirectoryA(out, nullptr);
    ensure_dir(out);
    SetEnvironmentVariableA("RAW_DUMP_DIR", out);

    // ------------------------------------------------------------- selftest
    if (std::strcmp(arm, "selftest") == 0) {
        rd16aw::SelfTestStep steps[32];
        std::size_t n = rd16aw::self_test(steps, 32);
        std::size_t ok = 0, bad = 0;
        buf_reset(g_big, sizeof(g_big));
        buf_add(g_big, sizeof(g_big), "{\n \"arm\": \"selftest\",\n");
        buf_add(g_big, sizeof(g_big), " \"n_steps\": %zu,\n", n);
        buf_add(g_big, sizeof(g_big), " \"steps\": [");
        for (std::size_t i = 0; i < n; ++i) {
            if (steps[i].ok) { ++ok; } else { ++bad; }
            char e_name[256], e_detail[1400];
            esc(e_name, sizeof(e_name), steps[i].name);
            esc(e_detail, sizeof(e_detail), steps[i].detail);
            buf_add(g_big, sizeof(g_big), "%s\n  {\"name\": \"%s\", \"ok\": %s, "
                    "\"detail\": \"%s\"}", i ? "," : "", e_name,
                    steps[i].ok ? "true" : "false", e_detail);
            std::printf("SELFTEST %-52s %s  %s\n", steps[i].name,
                        steps[i].ok ? "OK" : "FAIL", steps[i].detail);
        }
        buf_add(g_big, sizeof(g_big), "\n ],\n \"n_ok\": %zu,\n \"n_fail\": %zu\n}\n",
                ok, bad);
        bool wrote = write_text(out, "selftest.json", g_big, std::strlen(g_big));
        std::printf("SELFTEST steps=%zu ok=%zu fail=%zu wrote=%d\n", n, ok, bad,
                    (int)wrote);
        return bad == 0 && wrote ? 0 : 1;
    }

    // ---------------------------------------------------- frame replays
    if (std::strcmp(arm, "frame_authentic") == 0 ||
        std::strcmp(arm, "frame_scenarios") == 0) {
        const bool authentic = (std::strcmp(arm, "frame_authentic") == 0);
        FILE* fh = nullptr;
        if (authentic) {
            if (!events) { std::fprintf(stderr, "--events required\n"); return 2; }
            fh = std::fopen(events, "rb");
            if (!fh) { std::fprintf(stderr, "cannot open %s\n", events); return 3; }
        }
        // ("symbol<TAB>stream-id" per line; stream-id is an integer label.)
        char override_s[32];
        long override = 0;
        DWORD on = GetEnvironmentVariableA("RAW_DUMP_FRAME_ID", override_s,
                                           sizeof(override_s));
        if (on > 0 && override_s[0] != '\0') { override = std::atol(override_s); }

        rd16aw::frame_machine_reset(override);
        LegacyFrameMachine legacy;
        legacy.reset();

        buf_reset(g_big, sizeof(g_big));
        buf_add(g_big, sizeof(g_big), "{\n \"arm\": \"%s\",\n", arm);
        buf_add(g_big, sizeof(g_big), " \"declared_override\": %ld,\n", override);
        buf_add(g_big, sizeof(g_big), " \"events\": [");

        unsigned n_events = 0, n_disagree = 0, n_anomaly = 0, n_streams_max = 0;
        unsigned n_legacy_zero = 0, n_repaired_zero = 0;
        char line[512];
        char symbol[256] = "";
        long stream_id = 0;
        const char* scen_names[] = {
            "cold_initialization", "complete_frame", "two_consecutive_warm_frames",
            "aborted_incomplete_frame", "nested_concurrent_stream_activity",
            "missing_closing_event", "duplicate_marker",
            "initialization_before_first_opener"};
        const char* scen_syms[8][16] = {
            {"_Z12k_attention212AttnParams1d"},
            {"_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d", "_Z10k_flag_setPjj"},
            {"_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d", "_Z10k_flag_setPjj",
             "_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d", "_Z10k_flag_setPjj"},
            {"_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d",
             "_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d", "_Z10k_flag_setPjj"},
            {"_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d", "_Z10k_flag_setPjj",
             "_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d", "_Z10k_flag_setPjj"},
            {"_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d"},
            {"_Z11k_flag_waitPjjj", "_Z12k_attention212AttnParams1d", "_Z10k_flag_setPjj",
             "_Z10k_flag_setPjj"},
            {"_Z12k_attention212AttnParams1d", "_Z11k_flag_waitPjjj",
             "_Z12k_attention212AttnParams1d", "_Z10k_flag_setPjj"}};
        const long scen_streams[8][16] = {
            {1},
            {1, 1, 1},
            {1, 1, 1, 1, 1, 1},
            {1, 1, 1, 1, 1},
            {1, 1, 1, 2, 2, 2},      // the second job is a DIFFERENT stream
            {1, 1},
            {1, 1, 1, 1},
            {1, 1, 1, 1}};
        const unsigned scen_len[8] = {1, 3, 6, 5, 6, 2, 4, 4};

        unsigned emission = 0;
        unsigned n_scen_events = 0;
        for (unsigned si = 0; si < 8; ++si) { n_scen_events += scen_len[si]; }
        const unsigned kTotal = authentic ? 100000u : n_scen_events;
        unsigned cur_scen = 0;
        bool last_was_marker = false;
        while (emission < kTotal) {
            if (authentic) {
                if (std::fgets(line, sizeof(line), fh) == nullptr) { break; }
                char* t = std::strchr(line, '\t');
                if (t) { *t = '\0'; stream_id = std::atol(t + 1); }
                size_t l = std::strlen(line);
                while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) {
                    line[--l] = '\0';
                }
                if (line[0] == '\0') { continue; }
                std::snprintf(symbol, sizeof(symbol), "%s", line);
                if (stream_id == 0) { stream_id = 1; }
            } else {
                // The scenarios are concatenated into one flat event stream.
                unsigned base = 0, si = 0;
                for (si = 0; si < 8; ++si) {
                    if (emission < base + scen_len[si]) { break; }
                    base += scen_len[si];
                }
                if (si >= 8) { break; }
                unsigned idx = emission - base;
                std::snprintf(symbol, sizeof(symbol), "%s", scen_syms[si][idx]);
                stream_id = scen_streams[si][idx];
                cur_scen = si;
            }

            const char* legacy_src = "NO_MARKER_SEEN_YET";
            unsigned legacy_frame = legacy.on_event(symbol, &legacy_src);
            rd16aw::FrameAssignment fa =
                rd16aw::frame_machine().on_event(symbol, (const void*)(uintptr_t)stream_id,
                                                 emission);
            if (legacy_frame == 0) { ++n_legacy_zero; }
            if (fa.frame_id == 0) { ++n_repaired_zero; }
            if (fa.anomaly != nullptr) { ++n_anomaly; }
            if (legacy_frame != fa.frame_id) { ++n_disagree; }

            // For the authentic stream only a window is emitted, but the window
            // must CONTAIN every frame boundary: the disagreements are only
            // readable beside the events where the two machines agree.
            const bool is_marker = (fa.event_role[0] == 'O' || fa.event_role[0] == 'C');
            // NOT n_events: that counts KEPT events, so the window would stop
            // growing the moment anything was skipped.
            const bool keep = (!authentic) || emission < 40 || is_marker ||
                              last_was_marker;
            if (keep) {
                buf_add(g_big, sizeof(g_big), "%s\n  {\"i\": %u, \"symbol\": \"%s\", "
                        "\"stream\": %ld, \"legacy_frame\": %u, \"legacy_source\": "
                        "\"%s\", \"repaired_frame\": %u, \"repaired_source\": \"%s\", "
                        "\"provenance\": \"%s\", \"role\": \"%s\", \"anomaly\": \"%s\","
                        " \"scenario\": \"%s\", \"agrees\": %s}",
                        n_events ? "," : "", emission, symbol, stream_id,
                        legacy_frame, legacy_src, fa.frame_id, fa.source,
                        fa.provenance, fa.event_role,
                        fa.anomaly ? fa.anomaly : "",
                        authentic ? "" : scen_names[cur_scen],
                        legacy_frame == fa.frame_id ? "true" : "false");
            }
            last_was_marker = is_marker;
            ++n_events;
            ++emission;
            if (authentic && emission >= kTotal) { break; }
        }
        if (fh) { std::fclose(fh); }

        rd16aw::FrameMachine& m = rd16aw::frame_machine();
        if (m.n_streams_seen() > n_streams_max) { n_streams_max = m.n_streams_seen(); }
        buf_add(g_big, sizeof(g_big), "\n ],\n");
        buf_add(g_big, sizeof(g_big), " \"n_events\": %u,\n", n_events);
        buf_add(g_big, sizeof(g_big), " \"n_disagreements_with_legacy\": %u,\n",
                n_disagree);
        buf_add(g_big, sizeof(g_big), " \"n_events_with_an_anomaly\": %u,\n", n_anomaly);
        buf_add(g_big, sizeof(g_big), " \"n_events_legacy_could_not_place\": %u,\n",
                n_legacy_zero);
        buf_add(g_big, sizeof(g_big), " \"n_events_repaired_could_not_place\": %u,\n",
                n_repaired_zero);
        buf_add(g_big, sizeof(g_big), " \"n_streams_seen\": %u,\n", m.n_streams_seen());
        buf_add(g_big, sizeof(g_big), " \"frames_opened\": %u,\n", m.n_frames_opened());
        buf_add(g_big, sizeof(g_big), " \"frames_complete\": %u,\n", m.n_frames_complete());
        buf_add(g_big, sizeof(g_big), " \"frames_incomplete\": %u,\n", m.n_frames_incomplete());
        buf_add(g_big, sizeof(g_big), " \"anatomy_pre_opener\": %u,\n", m.n_anatomy_pre_opener());
        buf_add(g_big, sizeof(g_big), " \"unmatched_closer\": %u,\n", m.n_unmatched_closer());
        buf_add(g_big, sizeof(g_big), " \"duplicate_closer\": %u,\n", m.n_duplicate_closer());
        buf_add(g_big, sizeof(g_big), " \"post_close_stray\": %u,\n", m.n_post_close_stray());
        buf_add(g_big, sizeof(g_big), " \"frames_left_open_at_end\": %u,\n",
                m.n_frames_left_open());
        buf_add(g_big, sizeof(g_big), " \"override_active\": %s,\n",
                m.override_active() ? "true" : "false");
        buf_add(g_big, sizeof(g_big), " \"last_derived_frame_id\": %u,\n",
                m.last_derived_frame_id());
        buf_add(g_big, sizeof(g_big), " \"last_derived_source_is_opener\": %u,\n",
                m.last_derived_source_is_opener());
        buf_add(g_big, sizeof(g_big), " \"scenario_names\": [");
        for (unsigned i = 0; i < 8; ++i) {
            buf_add(g_big, sizeof(g_big), "%s\"%s\"", i ? ", " : "", scen_names[i]);
        }
        buf_add(g_big, sizeof(g_big), "]\n}\n");

        const char* fname = authentic ? "frame_authentic.json" : "frame_scenarios.json";
        bool wrote = write_text(out, fname, g_big, std::strlen(g_big));
        std::printf("FRAME arm=%s events=%u disagreements_with_legacy=%u "
                    "anomalies=%u legacy_unplaced=%u repaired_unplaced=%u "
                    "streams=%u opened=%u complete=%u incomplete=%u pre_opener=%u "
                    "unmatched_closer=%u duplicate_closer=%u post_close_stray=%u "
                    "wrote=%d\n",
                    arm, n_events, n_disagree, n_anomaly, n_legacy_zero,
                    n_repaired_zero, m.n_streams_seen(), m.n_frames_opened(),
                    m.n_frames_complete(), m.n_frames_incomplete(),
                    m.n_anatomy_pre_opener(), m.n_unmatched_closer(),
                    m.n_duplicate_closer(), m.n_post_close_stray(), (int)wrote);
        return wrote ? 0 : 1;
    }

    // ---------------------------------------------- the capture rehearsal
    if (std::strcmp(arm, "capture_all") != 0) {
        std::fprintf(stderr, "unknown arm \"%s\"\n", arm);
        return 2;
    }
    if (!bridge_path) { std::fprintf(stderr, "--bridge required\n"); return 2; }

    const bool gate = (gate_s[0] == '1');
    SetEnvironmentVariableA("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH", gate ? "1" : "0");
    SetEnvironmentVariableA("RAW_DUMP", "1");
    SetEnvironmentVariableA("RAW_DUMP_KERNELS", "all");
    {
        char d[16];
        DWORD n = GetEnvironmentVariableA("RAW_DUMP_16AW_MUTATION", d, sizeof(d));
        if (n == 0) { SetEnvironmentVariableA("RAW_DUMP_16AW_MUTATION", "NONE"); }
    }

    HMODULE bridge = LoadLibraryExA(bridge_path, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!bridge) {
        std::fprintf(stderr, "LOAD_FAILED %s error=%lu\n", bridge_path,
                     (unsigned long)GetLastError());
        return 3;
    }
    RegisterFunctionFn reg =
        (RegisterFunctionFn)GetProcAddress(bridge, "__hipRegisterFunction");
    LaunchKernelFn launch = (LaunchKernelFn)GetProcAddress(bridge, "hipLaunchKernel");
    if (!reg || !launch) {
        std::fprintf(stderr, "bridge exports missing reg=%p launch=%p\n",
                     (void*)reg, (void*)launch);
        return 4;
    }

    // Distinct host addresses so the bridge's registration ledger can tell the
    // 15 identities apart.
    static int s_fn[32];
    for (std::size_t i = 0; i < rd16aw::kNumKernelSpecs; ++i) {
        char nm[192], dv[192];
        std::snprintf(nm, sizeof(nm), "%s", rd16aw::kKernelSpecs[i].identity);
        std::snprintf(dv, sizeof(dv), "%s", rd16aw::kKernelSpecs[i].identity);
        reg(nullptr, &s_fn[i], dv, nm, 0, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    buf_reset(g_big, sizeof(g_big));
    buf_add(g_big, sizeof(g_big), "{\n \"arm\": \"capture_all\",\n");
    buf_add(g_big, sizeof(g_big), " \"identity_count\": %zu,\n",
            rd16aw::kNumKernelSpecs);
    buf_add(g_big, sizeof(g_big), " \"launches\": [");

    unsigned n_launch = 0, n_regions = 0, n_noncontig = 0, n_adjacent = 0;
    unsigned n_canary_ok = 0, n_canary_bad = 0, n_expected_failures = 0;

    for (std::size_t i = 0; i < rd16aw::kNumKernelSpecs; ++i) {
        const rd16aw::KernelSpec& k = rd16aw::kKernelSpecs[i];
        Region regions[8];
        void* args[8];
        unsigned n = k.n_explicit;
        if (n > 8) { continue; }
        bool ok = true;
        for (unsigned j = 0; j < n; ++j) {
            if (!region_make(regions[j], j, k.explicit_args[j].bytes)) { ok = false; }
            fill_payload(regions[j].payload, k.explicit_args[j].bytes, j,
                         k.explicit_args[j].value_kind);
            args[j] = regions[j].payload;
            ++n_regions;
        }
        if (!ok) { std::fprintf(stderr, "ALLOC_FAILED\n"); return 5; }

        // noncontiguity, measured
        unsigned noncontig = 1;
        for (unsigned j = 0; j + 1 < n; ++j) {
            unsigned char* end = regions[j].payload + regions[j].n;
            if (end == regions[j + 1].payload ||
                (uintptr_t)end + 1 >= (uintptr_t)regions[j + 1].payload) {
                noncontig = 0;
            }
        }
        if (noncontig) { ++n_noncontig; } else { ++n_adjacent; }

        const unsigned ordinal = n_launch + 1;
        Dim3 g{1, 1, 1}, bl{1, 1, 1};
        int rc = launch(&s_fn[i], g, bl, args, 0, (void*)(uintptr_t)1);
        ++n_launch;
        if (rc != 0) { ++n_expected_failures; }

        char detail[256];
        bool intact = true;
        for (unsigned j = 0; j < n; ++j) {
            char d2[256];
            if (!region_canaries_intact(regions[j], d2, sizeof(d2))) {
                intact = false;
                std::snprintf(detail, sizeof(detail), "%s", d2);
                break;
            }
        }
        if (intact) { ++n_canary_ok; } else { ++n_canary_bad; }

        buf_add(g_big, sizeof(g_big), "%s\n  {\"launch_ordinal\": %u, "
                "\"symbol\": \"%s\", \"n_explicit\": %u, \"storage_noncontiguous\": %s,"
                " \"canaries_intact\": %s, \"backend_return_code\": %d, \"args\": [",
                n_launch > 1 ? "," : "", ordinal, k.identity, n,
                noncontig ? "true" : "false", intact ? "true" : "false", rc);
        for (unsigned j = 0; j < n; ++j) {
            char hx[2 * 4096 + 1];
            hex_of(regions[j].payload, regions[j].n, hx);
            buf_add(g_big, sizeof(g_big),
                    "%s\n   {\"host_arg_index\": %u, \"declared_bytes\": %u, "
                    "\"value_kind\": \"%s\", \"type_name\": \"%s\", "
                    "\"region_address\": %llu, \"region_bytes\": %llu, "
                    "\"payload_address\": %llu, \"canary_pre\": %u, "
                    "\"canary_post\": %u, \"payload_hex\": \"%s\"}",
                    j ? "," : "", j, k.explicit_args[j].bytes,
                    k.explicit_args[j].value_kind, k.explicit_args[j].type_name,
                    (unsigned long long)(uintptr_t)regions[j].base,
                    (unsigned long long)regions[j].bytes,
                    (unsigned long long)(uintptr_t)regions[j].payload,
                    canary_pre(j), canary_post(j), hx);
        }
        buf_add(g_big, sizeof(g_big), "\n  ]}");
        for (unsigned j = 0; j < n; ++j) { VirtualFree(regions[j].base, 0, MEM_RELEASE); }
    }
    buf_add(g_big, sizeof(g_big), "\n ],\n");
    buf_add(g_big, sizeof(g_big), " \"n_launches\": %u,\n", n_launch);
    buf_add(g_big, sizeof(g_big), " \"n_argument_regions\": %u,\n", n_regions);
    buf_add(g_big, sizeof(g_big), " \"n_launches_with_noncontiguous_storage\": %u,\n",
            n_noncontig);
    buf_add(g_big, sizeof(g_big), " \"n_launches_with_adjacent_storage\": %u,\n", n_adjacent);
    buf_add(g_big, sizeof(g_big), " \"n_launches_canaries_intact\": %u,\n", n_canary_ok);
    buf_add(g_big, sizeof(g_big), " \"n_launches_canaries_disturbed\": %u,\n", n_canary_bad);
    buf_add(g_big, sizeof(g_big), " \"n_expected_launch_failures\": %u,\n",
            n_expected_failures);
    buf_add(g_big, sizeof(g_big), " \"gate\": %s\n}\n", gate ? "true" : "false");

    bool wrote = write_text(out, "fixture_16aw.json", g_big, std::strlen(g_big));
    std::printf("CAPTURE_ALL launches=%u argument_regions=%u noncontiguous=%u "
                "adjacent=%u canaries_intact=%u canaries_disturbed=%u "
                "expected_launch_failures=%u wrote=%d\n",
                n_launch, n_regions, n_noncontig, n_adjacent, n_canary_ok,
                n_canary_bad, n_expected_failures, (int)wrote);
    return wrote ? 0 : 1;
}
