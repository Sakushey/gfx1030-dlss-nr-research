// Phase 16AX -- THE FORWARDING-MATRIX DRIVER.
//
// WHAT IT DOES
//   Loads ONE bridge DLL by absolute path, drives a fixed, deterministic script
//   through ALL 29 of the bridge's HIP entry points, and writes a transcript of
//   what came back.  The same script runs in three arms:
//
//     BASELINE  the bridge built from the UNMODIFIED shipping source
//     OFF       the 16AX bridge (capture point wired), RAW_DUMP_DIR unset
//     ON        the 16AX bridge (capture point wired), RAW_DUMP_DIR set
//
//   OFF and ON are the SAME BINARY with a different environment, so a
//   difference between them cannot be a difference in code.
//
//   The BACKEND is held constant across all three arms: every build's
//   bridge_config.h resolves DLSSNR_BACKEND_PATH to the 16AX host-only WITNESS,
//   and the driver ASSERTS that by reading the testing-only
//   __bridge_backend_path() export back out of the LOADED bridge, rather than
//   trusting the build script that produced it.
//
//   Nothing here touches a GPU.  The witness never launches anything: it
//   records the launch and answers.  The launch gate is left at its shipping
//   default (OFF) except where a case explicitly turns it on, and the case that
//   turns it on forwards to the WITNESS, not to a runtime.
//
// WHY THE CRASH CASES RUN IN CHILD PROCESSES
//   "The recorder must never crash the forwarding path" cannot be established
//   inside the process that would crash.  Every hostile case is therefore run as
//   a CHILD of this exe (`--child <case>`), and the parent records the child's
//   exit code.  A case that kills the child is a measured result, not a lost
//   harness.
//
// POINTERS ARE REPORTED BY IDENTITY, NEVER BY ADDRESS
//   Addresses differ between processes, so a transcript intended to be compared
//   across arms must not contain one.  A pointer is reported as its declared
//   label, as "h<N>" for a handle the driver received, as "null", or as
//   "FOREIGN" -- and FOREIGN is itself a finding, because it means a handle the
//   driver never handed out came back.
//
// HOST-ONLY.  No HIP runtime is loaded or imported.
#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "raw_dump_repair_16ax.h"  // the layer's own self-test, run in-process

// ------------------------------------------------------------------ ABI
using hipError_t = int;
using hipStream_t = void*;
using hipEvent_t = void*;
using hipExternalMemory_t = void*;
using hipMemcpyKind = int;

struct hipDim3 {
    unsigned x, y, z;
};
struct hipUint3 {
    unsigned x, y, z;
};
struct hipDeviceProp_tR0600;
struct hipExternalMemoryHandleDesc;
struct hipExternalMemoryBufferDesc;

namespace {

// ------------------------------------------------------------- transcript
char   g_out[768 * 1024];
size_t g_outN = 0;
bool   g_firstStep = true;

void o(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(g_out + g_outN, sizeof(g_out) - g_outN, fmt, ap);
    va_end(ap);
    if (n > 0) {
        g_outN += (size_t)n;
    }
    if (g_outN >= sizeof(g_out) - 1) {
        g_outN = sizeof(g_out) - 2;
    }
}

void flush_out(const char* path)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD w = 0;
    WriteFile(h, g_out, (DWORD)g_outN, &w, nullptr);
    CloseHandle(h);
}

// ------------------------------------------------------------- label tables
struct Named {
    const void* p;
    char        label[128];
    unsigned    n;   // readable bytes; 0 == label this, never dereference it
};
Named    g_regions[256];
unsigned g_nregions = 0;
Named    g_funcs[64];
unsigned g_nfuncs = 0;
// A FULL TABLE IS COUNTED, NOT SWALLOWED.  `declare` used to drop silently past
// capacity, which degrades a declared region into `<unlabelled>` in the witness
// log -- a change in the EVIDENCE that looks like a change in BEHAVIOUR.  The
// concurrency case alone declares 16 more regions, so the 64-entry table was one
// case away from doing exactly that.
unsigned g_region_drop = 0;
unsigned g_func_drop   = 0;
Named    g_handles[32];
unsigned g_nhandles = 0;

void declare_n(const void* p, const char* label, unsigned n)
{
    if (g_nregions < 256) {
        g_regions[g_nregions].p = p;
        std::snprintf(g_regions[g_nregions].label,
                      sizeof(g_regions[g_nregions].label), "%s", label);
        g_regions[g_nregions].n = n;
        ++g_nregions;
    } else {
        ++g_region_drop;
    }
}

// `declare` keeps the prefix-inferred capacity for the regions whose true size
// happens to match it.  It is NOT the default: a label prefix is not a
// measurement of the object behind it, and the first version of this table let
// the prefix stand in for one.  `arg:w1` is 4 bytes but the `arg:` rule said 8,
// so the witness log reported "b0b1b2b3c0c1c2c3" -- four bytes of the NEXT
// global -- as if the caller had supplied them.  `arr:k_flag_set` is 16 bytes
// but the `arr:` rule said 64, so the witness reported FOUR arguments for a
// two-argument launch, the last two read out of the adjacent globals.  Nothing
// faulted (the globals are adjacent), which is exactly why it survived: an
// evidence channel inventing arguments is invisible unless the invented bytes
// happen to be wrong.  Regions whose size is knowable now declare it explicitly.
void declare(const void* p, const char* label)
{
    unsigned n = 0;
    if (std::strncmp(label, "data:", 5) == 0) { n = 64; }
    else if (std::strncmp(label, "arg:", 4) == 0) { n = 8; }
    else if (std::strncmp(label, "arr:", 4) == 0) { n = 64; }
    declare_n(p, label, n);
}
void declare_fn(const void* p, const char* label)
{
    if (g_nfuncs < 64) {
        g_funcs[g_nfuncs].p = p;
        g_funcs[g_nfuncs].n = 0;
        std::snprintf(g_funcs[g_nfuncs].label, sizeof(g_funcs[g_nfuncs].label),
                      "%s", label);
        ++g_nfuncs;
    } else {
        ++g_func_drop;
    }
}
void note_handle(const void* p)
{
    if (p == nullptr) {
        return;
    }
    for (unsigned i = 0; i < g_nhandles; ++i) {
        if (g_handles[i].p == p) {
            return;
        }
    }
    if (g_nhandles < 32) {
        g_handles[g_nhandles].p = p;
        std::snprintf(g_handles[g_nhandles].label,
                      sizeof(g_handles[g_nhandles].label), "h%u", g_nhandles);
        ++g_nhandles;
    }
}
const char* ref(const void* p)
{
    if (p == nullptr) {
        return "null";
    }
    for (unsigned i = 0; i < g_nregions; ++i) {
        if (g_regions[i].p == p) { return g_regions[i].label; }
    }
    for (unsigned i = 0; i < g_nfuncs; ++i) {
        if (g_funcs[i].p == p) { return g_funcs[i].label; }
    }
    for (unsigned i = 0; i < g_nhandles; ++i) {
        if (g_handles[i].p == p) { return g_handles[i].label; }
    }
    return "FOREIGN";
}

// ------------------------------------------------------------- step helpers
// JSON string escaping.  This is not cosmetic: the transcript carried
//   "bridge_path":"<USER_HOME>\Desktop\...\p16ax_bridge_16ax.dll"
// with the backslashes RAW, which is not valid JSON -- `\U` is an invalid
// escape and every parser rejects the whole document.  The comparator could not
// read its own instrument.  Every string this driver emits goes through here.
void json_esc(const char* s, char* out, std::size_t cap)
{
    std::size_t j = 0;
    if (cap == 0) { return; }
    for (std::size_t i = 0; s != nullptr && s[i] != '\0' && j + 8 < cap; ++i) {
        const unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  out[j++] = '\\'; out[j++] = '"';  break;
            case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
            case '\n': out[j++] = '\\'; out[j++] = 'n';  break;
            case '\r': out[j++] = '\\'; out[j++] = 'r';  break;
            case '\t': out[j++] = '\\'; out[j++] = 't';  break;
            default:
                if (c < 0x20) {
                    j += (std::size_t)std::snprintf(out + j, cap - j, "\\u%04x", c);
                } else {
                    out[j++] = (char)c;
                }
        }
    }
    out[j] = '\0';
}

void step_open(const char* step, const char* fn)
{
    o("%s\n {\"step\":\"%s\",\"fn\":\"%s\"", g_firstStep ? "" : ",", step, fn);
    g_firstStep = false;
}
void step_ret(long long rc) { o(",\"ret\":%lld", rc); }
void step_kv_str(const char* k, const char* v)
{
    char e[8192];
    json_esc(v, e, sizeof(e));
    o(",\"%s\":\"%s\"", k, e);
}
void step_kv_int(const char* k, long long v) { o(",\"%s\":%lld", k, v); }
void step_kv_bool(const char* k, bool v) { o(",\"%s\":%s", k, v ? "true" : "false"); }
void step_kv_ptr(const char* k, const void* v) { o(",\"%s\":\"%s\"", k, ref(v)); }
void step_close() { o("}"); }

// --------------------------------------------------------------- canary
// The canary is a region the DRIVER owns and the capture layer was never given a
// reason to touch, so any write to it is attributable to the layer under test.
// It is the by-construction half of "the recorder must not mutate the launch";
// the witness log comparison is the by-observation half.
unsigned char g_canary[64];
unsigned      g_canary_checks = 0;
unsigned      g_canary_failures = 0;

void canary_fill()
{
    for (unsigned i = 0; i < 64; ++i) { g_canary[i] = 0xCD; }
}
void canary_check(const char* when)
{
    ++g_canary_checks;
    bool ok = true;
    for (unsigned i = 0; i < 64; ++i) {
        if (g_canary[i] != 0xCD) { ok = false; break; }
    }
    if (!ok) { ++g_canary_failures; }
    step_open(when, "canary");
    step_kv_int("intact", ok ? 1 : 0);
    step_close();
}

// ------------------------------------------------------------- module state
HMODULE g_bridge = nullptr;
HMODULE g_witness = nullptr;

using RegisterFatbinFn = void** (*)(const void*);
using UnregisterFatbinFn = void (*)(void**);
using RegisterFunctionFn = void (*)(void**, const void*, char*, const char*,
                                    unsigned, hipUint3*, hipUint3*, hipDim3*,
                                    hipDim3*, int*);
using RegisterVarFn = void (*)(void**, void*, char*, char*, int, size_t, int, int);
using LaunchFn = hipError_t (*)(const void*, hipDim3, hipDim3, void**, size_t,
                                hipStream_t);
using BackendPathFn = const wchar_t* (*)();

RegisterFatbinFn   p_register_fatbin = nullptr;
UnregisterFatbinFn p_unregister_fatbin = nullptr;
RegisterFunctionFn p_register_function = nullptr;
RegisterVarFn      p_register_var = nullptr;
LaunchFn           p_launch = nullptr;
BackendPathFn      p_backend_path = nullptr;

using WitnessRegisterFn = void (*)(const void*, unsigned, const char*);
using WitnessSnapshotFn = void (*)();
using WitnessIdentityFn = const char* (*)();
WitnessRegisterFn p_w_register = nullptr;
WitnessSnapshotFn p_w_snapshot = nullptr;
WitnessIdentityFn p_w_identity = nullptr;

const char* kExports[29] = {
    "__hipRegisterFatBinary", "__hipUnregisterFatBinary", "__hipRegisterFunction",
    "__hipRegisterVar", "hipGetErrorString", "hipLaunchKernel",
    "__hipPopCallConfiguration", "__hipPushCallConfiguration",
    "hipDestroyExternalMemory", "hipDeviceSynchronize", "hipDriverGetVersion",
    "hipEventCreate", "hipEventElapsedTime", "hipEventRecord",
    "hipEventSynchronize", "hipExternalMemoryGetMappedBuffer", "hipFree",
    "hipGetDeviceCount", "hipGetDevicePropertiesR0600", "hipGetLastError",
    "hipImportExternalMemory", "hipMalloc", "hipMemcpy", "hipMemcpyAsync",
    "hipMemcpyToSymbol", "hipMemset", "hipMemsetAsync", "hipRuntimeGetVersion",
    "hipSetDevice"};
void* g_export[29];

// ------------------------------------------------------------- dummy kernels
// The registration ledger maps a HOST FUNCTION ADDRESS to a kernel name, and the
// capture layer is handed that name as its identity.  These stand-ins are never
// called -- nothing here is executed -- they exist only to be distinct addresses
// the ledger can key on.
void dummy_wait() {}
void dummy_set() {}
void dummy_views() {}
void dummy_unregistered() {}

// ------------------------------------------------------------- buffers
unsigned char g_src[64];
unsigned char g_dst[64];
unsigned char g_dst2[64];
unsigned char g_extmem_desc[32];
unsigned char g_buf_desc[32];
unsigned char g_prop[512];
unsigned char g_wrapper_plain[32];
unsigned char g_fn_device[64];
unsigned char g_arg_w0[16];
unsigned char g_arg_w1[4];
unsigned char g_arg_w2[4];
unsigned char g_arg_s0[16];
unsigned char g_arg_s1[4];
unsigned char g_arg_c0[80];
unsigned char g_arg_e0[8];
unsigned char g_payload[4096];

void* g_arr_w[3];
void* g_arr_s[2];
void* g_arr_c[1];
void* g_arr_e[1];
void* g_arr_nullarg[3];

// -------- per-thread regions for the SYNTHETIC concurrency case only
// Each thread owns its own buffers, filled with a thread-specific pattern, so a
// record that crossed threads shows up as BYTES UNDER THE WRONG INSTANCE rather
// than merely as a duplicate id.
unsigned char g_conc_w0[8][8];
unsigned char g_conc_s1[8][4];
unsigned char g_conc_s2[8][4];
void*         g_conc_arr[8][3];

void** g_modules = nullptr;
hipEvent_t g_e0 = nullptr;
hipEvent_t g_e1 = nullptr;
void* g_extmem = nullptr;

void fill(unsigned char* p, unsigned n, unsigned char seed)
{
    for (unsigned i = 0; i < n; ++i) {
        p[i] = (unsigned char)(seed + i);
    }
}

// Every size below is `sizeof` of the object the label names, or an explicit
// count where the label names an object the witness must NOT be allowed to walk
// past.  `obj:` regions declare ZERO on purpose: that is how the driver states
// "label this, never dereference it", and it is written as an explicit zero
// rather than as the absence of a matching prefix rule.
void declare_all_regions()
{
    declare_n(g_src, "data:src", sizeof(g_src));
    declare_n(g_dst, "data:dst", sizeof(g_dst));
    declare_n(g_dst2, "data:dst2", sizeof(g_dst2));
    declare_n(g_canary, "data:canary", sizeof(g_canary));
    declare_n(g_extmem_desc, "obj:extmem_handle_desc", 0);
    declare_n(g_buf_desc, "obj:extmem_buffer_desc", 0);
    declare_n(g_prop, "obj:device_prop", sizeof(g_prop));
    declare_n(g_wrapper_plain, "obj:fatbin_wrapper_plain", 0);
    declare_n(g_payload, "obj:fatbin_payload", 0);
    declare_n(g_fn_device, "obj:device_function_name", 0);
    declare_n(g_arg_w0, "arg:w0", sizeof(g_arg_w0));
    declare_n(g_arg_w1, "arg:w1", sizeof(g_arg_w1));
    declare_n(g_arg_w2, "arg:w2", sizeof(g_arg_w2));
    declare_n(g_arg_s0, "arg:s0", sizeof(g_arg_s0));
    declare_n(g_arg_s1, "arg:s1", sizeof(g_arg_s1));
    declare_n(g_arg_c0, "arg:c0", sizeof(g_arg_c0));
    declare_n(g_arg_e0, "arg:e0", sizeof(g_arg_e0));
    declare_n(g_arr_w, "arr:k_flag_wait", sizeof(g_arr_w));
    declare_n(g_arr_s, "arr:k_flag_set", sizeof(g_arr_s));
    declare_n(g_arr_c, "arr:k_conv_res_views", sizeof(g_arr_c));
    declare_n(g_arr_e, "arr:unregistered", sizeof(g_arr_e));
    declare_n(g_arr_nullarg, "arr:k_flag_wait_missing_arg", sizeof(g_arr_nullarg));
    declare_fn((const void*)&dummy_wait, "fn:k_flag_wait");
    declare_fn((const void*)&dummy_set, "fn:k_flag_set");
    declare_fn((const void*)&dummy_views, "fn:k_conv_res_views");
    declare_fn((const void*)&dummy_unregistered, "fn:unregistered");
}

// The witness reads NOTHING it has not been given.  The capacity it is handed
// comes from the declaration, never from the label's prefix, so a region the
// driver sized wrongly is a driver bug rather than a witness over-read.
void witness_declare_all()
{
    if (p_w_register == nullptr) {
        return;
    }
    for (unsigned i = 0; i < g_nregions; ++i) {
        p_w_register(g_regions[i].p, g_regions[i].n, g_regions[i].label);
    }
    for (unsigned i = 0; i < g_nfuncs; ++i) {
        p_w_register(g_funcs[i].p, 0, g_funcs[i].label);
    }
}

void build_arg_arrays()
{
    g_arr_w[0] = g_arg_w0;
    g_arr_w[1] = g_arg_w1;
    g_arr_w[2] = g_arg_w2;
    g_arr_s[0] = g_arg_s0;
    g_arr_s[1] = g_arg_s1;
    g_arr_c[0] = g_arg_c0;
    g_arr_e[0] = g_arg_e0;
    g_arr_nullarg[0] = nullptr;
    g_arr_nullarg[1] = g_arg_w1;
    g_arr_nullarg[2] = g_arg_w2;
}

void fill_common()
{
    fill(g_src, sizeof(g_src), 0x00);
    fill(g_dst, sizeof(g_dst), 0x80);
    fill(g_dst2, sizeof(g_dst2), 0x40);
    fill(g_extmem_desc, sizeof(g_extmem_desc), 0x11);
    fill(g_buf_desc, sizeof(g_buf_desc), 0x22);
    fill(g_prop, sizeof(g_prop), 0x00);
    fill(g_wrapper_plain, sizeof(g_wrapper_plain), 0x00);
    for (unsigned i = 0; i < sizeof(g_payload); ++i) { g_payload[i] = 0x00; }
    for (unsigned i = 128; i < 192; ++i) { g_payload[i] = 0x77; }
    fill(g_fn_device, sizeof(g_fn_device), 0x30);
    fill(g_arg_w0, sizeof(g_arg_w0), 0xA0);
    fill(g_arg_w1, sizeof(g_arg_w1), 0xB0);
    fill(g_arg_w2, sizeof(g_arg_w2), 0xC0);
    fill(g_arg_s0, sizeof(g_arg_s0), 0xD0);
    fill(g_arg_s1, sizeof(g_arg_s1), 0xE0);
    fill(g_arg_c0, sizeof(g_arg_c0), 0x10);
    fill(g_arg_e0, sizeof(g_arg_e0), 0x50);
    canary_fill();
    build_arg_arrays();
    declare_all_regions();
    witness_declare_all();
}

// ------------------------------------------------------------------ bridge log
// The bridge writes its own log whose lines carry timestamps and addresses, so
// the transcript records the MULTISET OF EVENT KINDS instead: a per-class count
// is comparable across arms and would move if the capture point had changed what
// the bridge did.
struct EvCount {
    char     kind[64];
    unsigned n;
};
// 32 was too small: the matrix produces 35 distinct kinds, so the table silently
// dropped three of them and the per-kind counts no longer summed to the line
// count.  A table that quietly loses rows is worse than no table, because it
// still looks like a measurement.
const unsigned kMaxEvKinds = 256;
EvCount  g_ev[kMaxEvKinds];
unsigned g_nev     = 0;
unsigned g_ev_drop = 0;   // kinds seen after the table filled: must stay 0

// The bridge's log line is `YYYY-MM-DD HH:MM:SS.mmm t=<tid> pid=<pid> MESSAGE`.
// The event kind is therefore the first token AFTER the `pid=<n> ` field, not
// the first token of the line.  The first version of this extractor took the
// first token and so counted the DATE as the event kind: every arm reported one
// distinct kind ("2026-09-21") with a count of 62, which is a plausible-looking
// table that carries no information about what the bridge did.  Skipping the
// prefix is what makes the table a fact about the bridge.
void count_event(const char* line)
{
    const char* msg = line;
    const char* p   = std::strstr(line, " pid=");
    if (p != nullptr) {
        const char* q = std::strchr(p + 5, ' ');
        if (q != nullptr && q[1] != '\0') { msg = q + 1; }
    }
    char kind[64];
    unsigned k = 0;
    while (msg[k] && msg[k] != ' ' && msg[k] != '\t' && k < 63) {
        kind[k] = msg[k];
        ++k;
    }
    kind[k] = '\0';
    if (k == 0) {
        return;
    }
    for (unsigned i = 0; i < g_nev; ++i) {
        if (std::strcmp(g_ev[i].kind, kind) == 0) { ++g_ev[i].n; return; }
    }
    if (g_nev < kMaxEvKinds) {
        std::snprintf(g_ev[g_nev].kind, sizeof(g_ev[g_nev].kind), "%s", kind);
        g_ev[g_nev].n = 1;
        ++g_nev;
    } else {
        ++g_ev_drop;   // counted, not swallowed
    }
}

void read_bridge_log(const char* path)
{
    g_nev = 0;
    g_ev_drop = 0;
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        step_open("S90.bridge_log", "read");
        step_kv_str("path", path);
        step_kv_str("status", "ABSENT");
        step_kv_int("lines", 0);
        step_close();
        return;
    }
    char     buf[1 << 16];
    char     line[2048];
    DWORD    got = 0;
    unsigned nlines = 0, npartial = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) {
        for (DWORD i = 0; i < got; ++i) {
            if (buf[i] == '\n') {
                line[npartial] = '\0';
                if (npartial > 0) { count_event(line); ++nlines; }
                npartial = 0;
            } else if (buf[i] != '\r' && npartial < sizeof(line) - 1) {
                line[npartial++] = buf[i];
            }
        }
    }
    CloseHandle(h);

    // deterministic order: insertion-sort by kind, so the transcript's event
    // table does not depend on the order kinds happened to appear
    for (unsigned i = 1; i < g_nev; ++i) {
        EvCount key = g_ev[i];
        unsigned j = i;
        while (j > 0 && std::strcmp(g_ev[j - 1].kind, key.kind) > 0) {
            g_ev[j] = g_ev[j - 1];
            --j;
        }
        g_ev[j] = key;
    }
    // the sum check: every counted line contributed exactly one kind count, so
    // the counts must reconstruct the line count.  If the table dropped a kind,
    // this is short and the shortfall is visible rather than silent.
    unsigned sum = 0;
    for (unsigned i = 0; i < g_nev; ++i) { sum += g_ev[i].n; }

    step_open("S90.bridge_log", "read");
    step_kv_str("path", path);
    step_kv_str("status", "READ");
    step_kv_int("lines", nlines);
    step_kv_int("distinct_event_kinds", g_nev);
    step_kv_int("kinds_dropped_table_full", g_ev_drop);
    step_kv_int("sum_of_event_kind_counts", sum);
    step_kv_bool("counts_reconstruct_line_count", sum == nlines && g_ev_drop == 0);
    step_close();
    // the table itself is emitted at S14, once per run
}

// --------------------------------------------------------- case declarations
void case_gate_off(const char* out);
void case_overread_guard(const char* out, bool undersized);
void case_recorder_invalid(const char* out);
void case_concurrency(const char* out);

}  // namespace

// ============================================================== process setup
namespace {

int setup(const char* bridge_path, const char* witness_path)
{
    if (witness_path != nullptr && witness_path[0] != '\0') {
        g_witness = LoadLibraryExA(witness_path, nullptr,
                                   LOAD_WITH_ALTERED_SEARCH_PATH);
    }
    if (g_witness != nullptr) {
        p_w_register = (WitnessRegisterFn)(void*)GetProcAddress(
            g_witness, "p16ax_witness_register_region");
        p_w_snapshot = (WitnessSnapshotFn)(void*)GetProcAddress(
            g_witness, "p16ax_witness_snapshot");
        p_w_identity = (WitnessIdentityFn)(void*)GetProcAddress(
            g_witness, "p16ax_witness_identity");
    }
    g_bridge = LoadLibraryExA(bridge_path, nullptr,
                              LOAD_WITH_ALTERED_SEARCH_PATH);
    if (g_bridge == nullptr) {
        return 1;
    }
    for (unsigned i = 0; i < 29; ++i) {
        g_export[i] = (void*)GetProcAddress(g_bridge, kExports[i]);
    }
    p_register_fatbin = (RegisterFatbinFn)g_export[0];
    p_unregister_fatbin = (UnregisterFatbinFn)g_export[1];
    p_register_function = (RegisterFunctionFn)g_export[2];
    p_register_var = (RegisterVarFn)g_export[3];
    p_launch = (LaunchFn)g_export[5];
    p_backend_path = (BackendPathFn)(void*)GetProcAddress(
        g_bridge, "__bridge_backend_path");
    return 0;
}

bool arg_str(int argc, char** argv, const char* key, const char** out)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], key) == 0) {
            *out = argv[i + 1];
            return true;
        }
    }
    return false;
}

void set_env(const char* kv)
{
    const char* eq = std::strchr(kv, '=');
    if (eq == nullptr) {
        return;
    }
    char   name[256];
    size_t n = (size_t)(eq - kv);
    if (n >= sizeof(name)) { return; }
    std::memcpy(name, kv, n);
    name[n] = '\0';
    SetEnvironmentVariableA(name, eq + 1);
}

void run_matrix(const char* arm, const char* bridge_path, const char* run_dir);

}  // namespace

// ============================================================== entry
int main(int argc, char** argv)
{
    const char* child = nullptr;
    const char* bridge_path = nullptr;
    const char* witness_path = nullptr;
    const char* out_path = nullptr;
    arg_str(argc, argv, "--child", &child);
    arg_str(argc, argv, "--bridge", &bridge_path);
    arg_str(argc, argv, "--witness", &witness_path);
    arg_str(argc, argv, "--out", &out_path);
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--env") == 0) {
            set_env(argv[i + 1]);
        }
    }

    if (child != nullptr) {
        if (bridge_path == nullptr || setup(bridge_path, witness_path) != 0) {
            return 90;
        }
        if (std::strcmp(child, "gate_off") == 0) {
            case_gate_off(out_path);
        } else if (std::strcmp(child, "recorder_invalid") == 0) {
            case_recorder_invalid(out_path);
        } else if (std::strcmp(child, "overread_guard_sized") == 0) {
            case_overread_guard(out_path, false);
        } else if (std::strcmp(child, "overread_guard_undersized") == 0) {
            case_overread_guard(out_path, true);
        } else if (std::strcmp(child, "concurrency") == 0) {
            case_concurrency(out_path);
        } else {
            return 91;
        }
        flush_out(out_path);
        return 0;
    }

    const char* arm = nullptr;
    const char* run_dir = nullptr;
    arg_str(argc, argv, "--arm", &arm);
    arg_str(argc, argv, "--run-dir", &run_dir);
    if (bridge_path == nullptr || arm == nullptr || out_path == nullptr) {
        std::fprintf(stderr,
                     "usage: p16ax_driver --bridge <dll> --arm "
                     "<baseline|off|on> --out <json> [--witness <dll>] "
                     "[--run-dir <dir>]\n");
        return 2;
    }
    if (setup(bridge_path, witness_path) != 0) {
        std::fprintf(stderr, "bridge load failed: %s\n", bridge_path);
        return 3;
    }
    run_matrix(arm, bridge_path, run_dir ? run_dir : ".");
    flush_out(out_path);
    return 0;
}

namespace {

void run_matrix(const char* arm, const char* bridge_path, const char* run_dir)
{
    o("{\n \"schema\":\"p16ax/forwarding-arm-transcript/1\",\n");
    o(" \"arm\":\"%s\",\n", arm);
    {
        char ep[8192];
        json_esc(bridge_path, ep, sizeof(ep));
        o(" \"bridge_path\":\"%s\",\n", ep);
    }
    o(" \"host_only\":true,\n");
    o(" \"steps\":[\n");

    // ---------------------------------------------------------- S00 liveness
    {
        unsigned present = 0;
        for (unsigned i = 0; i < 29; ++i) {
            if (g_export[i] != nullptr) { ++present; }
        }
        step_open("S00.exports", "GetProcAddress");
        step_kv_int("n_expected", 29);
        step_kv_int("n_present_by_name", present);
        step_kv_int("backend_path_export_present", p_backend_path ? 1 : 0);
        step_close();

        step_open("S00.witness_identity", "p16ax_witness_identity");
        step_kv_str("identity", p_w_identity ? p_w_identity() : "(not loaded)");
        step_close();

        // THE ASSERTION THE BUILD SCRIPT CANNOT MAKE: read the backend path back
        // out of the LOADED image, rather than trusting which header the
        // compiler was given.
        step_open("S00.backend_path", "__bridge_backend_path");
        if (p_backend_path) {
            char narrow[MAX_PATH * 4] = {0};
            WideCharToMultiByte(CP_UTF8, 0, p_backend_path(), -1, narrow,
                                sizeof(narrow), nullptr, nullptr);
            step_kv_str("resolved", narrow);
            step_kv_int("is_the_witness",
                        std::strstr(narrow, "p16ax_witness.dll") ? 1 : 0);
        } else {
            step_kv_str("resolved", "(export absent)");
            step_kv_int("is_the_witness", 0);
        }
        step_close();

        // Declaration health: a region the witness was never told about is
        // reported as `<unlabelled>`, so a full declaration table would corrupt
        // the EVIDENCE in a way that reads as a behaviour difference.  Both
        // counts must be zero for the rest of the transcript to mean anything.
        step_open("S00.declaration_health", "region tables");
        step_kv_int("n_regions_declared", g_nregions);
        step_kv_int("n_functions_declared", g_nfuncs);
        step_kv_int("regions_dropped_table_full", g_region_drop);
        step_kv_int("functions_dropped_table_full", g_func_drop);
        step_kv_bool("no_declaration_was_dropped",
                     g_region_drop == 0 && g_func_drop == 0);
        step_close();
    }

    // ------------------------------------- S01 the layer's own self-test
    // Two facts from one artefact is a tautology, so this is NOT offered as
    // independent evidence of the matrix: it is the layer's own reported state,
    // run in the DRIVER'S OWN COPY of the layer, and it is compared across arms
    // like everything else.
    {
        rd16aw::SelfTestStep steps[32];
        std::size_t n = rd16aw::self_test(steps, 32);
        step_open("S01.layer_self_test", "rd16aw::self_test");
        step_kv_int("n_steps", (long long)n);
        unsigned nok = 0;
        for (std::size_t i = 0; i < n; ++i) {
            if (steps[i].ok) { ++nok; }
        }
        step_kv_int("n_ok", nok);
        step_close();
        for (std::size_t i = 0; i < n; ++i) {
            step_open(steps[i].name, "rd16aw::self_test_step");
            step_kv_int("ok", steps[i].ok ? 1 : 0);
            step_close();
        }
    }

    fill_common();

    // ------------------------------------------------- S02 registration ledger
    {
        // The wrapper is deliberately NOT a 'HIPF' magic, so the bridge's
        // identity path records FATBIN_UNEXPECTED_WRAPPER and forwards the
        // pointer UNCHANGED.
        unsigned char wrapper[32];
        std::memcpy(wrapper, g_wrapper_plain, 32);
        declare_n(wrapper, "obj:fatbin_wrapper_plain_local", 0);
        if (p_w_register) { p_w_register(wrapper, 0, "obj:fatbin_wrapper_plain_local"); }
        step_open("S02.__hipRegisterFatBinary_plain", "__hipRegisterFatBinary");
        g_modules = p_register_fatbin(wrapper);
        note_handle(g_modules);
        step_kv_ptr("handle", g_modules);
        step_kv_int("returned_null", g_modules ? 0 : 1);
        step_close();

        // A 'HIPF' wrapper whose payload is unidentifiable by construction: the
        // bridge must classify it NOT_OURS and forward it unchanged rather than
        // substituting a bundle.
        unsigned char hipf[32];
        std::memcpy(hipf, g_wrapper_plain, 32);
        *(unsigned*)hipf = 0x48495046u;  // 'HIPF'
        *(unsigned*)(hipf + 4) = 1u;
        *(void**)(hipf + 8) = g_payload;
        declare_n(hipf, "obj:fatbin_wrapper_hipf", 0);
        if (p_w_register) { p_w_register(hipf, 0, "obj:fatbin_wrapper_hipf"); }
        void** hipf_handle = p_register_fatbin(hipf);
        note_handle(hipf_handle);
        step_open("S02.__hipRegisterFatBinary_hipf", "__hipRegisterFatBinary");
        step_kv_str("wrapper_magic", "HIPF");
        step_kv_str("payload_kind", "unidentifiable-by-construction");
        step_kv_ptr("handle", hipf_handle);
        step_close();
    }

    {
        struct Reg {
            const char* step;
            const char* name;
            void        (*hostfn)();
        };
        const Reg regs[3] = {
            {"S03.__hipRegisterFunction_wait", "_Z11k_flag_waitPjjj", dummy_wait},
            {"S03.__hipRegisterFunction_set", "_Z10k_flag_setPjj", dummy_set},
            {"S03.__hipRegisterFunction_views",
             "_Z16k_conv_res_views12ConvPlParams", dummy_views},
        };
        for (unsigned i = 0; i < 3; ++i) {
            int wsize = 64;
            step_open(regs[i].step, "__hipRegisterFunction");
            step_kv_str("deviceName", regs[i].name);
            step_kv_ptr("hostFunction", (const void*)regs[i].hostfn);
            step_kv_ptr("modules", g_modules);
            p_register_function(g_modules, (const void*)regs[i].hostfn,
                                (char*)g_fn_device, regs[i].name, 0, nullptr,
                                nullptr, nullptr, nullptr, &wsize);
            step_kv_int("wSize_in", wsize);
            step_close();
        }

        step_open("S04.__hipRegisterVar", "__hipRegisterVar");
        p_register_var(g_modules, g_dst2, (char*)"g_hostvar", (char*)"g_devvar", 0,
                       64, 1, 0);
        step_kv_str("hostVar", "g_hostvar");
        step_kv_int("size", 64);
        step_close();
    }

    // ---------------------------------------------------------- S05 simple
    {
        int v = -1;
        step_open("S05.hipDriverGetVersion", "hipDriverGetVersion");
        hipError_t rc = ((hipError_t(*)(int*))g_export[10])(&v);
        step_ret(rc);
        step_kv_int("out", v);
        step_close();

        v = -1;
        step_open("S05.hipRuntimeGetVersion", "hipRuntimeGetVersion");
        rc = ((hipError_t(*)(int*))g_export[27])(&v);
        step_ret(rc);
        step_kv_int("out", v);
        step_close();

        v = -1;
        step_open("S05.hipGetDeviceCount", "hipGetDeviceCount");
        rc = ((hipError_t(*)(int*))g_export[17])(&v);
        step_ret(rc);
        step_kv_int("out", v);
        step_close();

        step_open("S05.hipGetDevicePropertiesR0600", "hipGetDevicePropertiesR0600");
        rc = ((hipError_t(*)(struct hipDeviceProp_tR0600*, int))g_export[18])(
            (struct hipDeviceProp_tR0600*)g_prop, 0);
        step_ret(rc);
        step_close();

        step_open("S05.hipSetDevice", "hipSetDevice");
        rc = ((hipError_t(*)(int))g_export[28])(0);
        step_ret(rc);
        step_close();

        step_open("S05.hipGetLastError", "hipGetLastError");
        rc = ((hipError_t(*)(void))g_export[19])();
        step_ret(rc);
        step_close();

        step_open("S05.hipDeviceSynchronize", "hipDeviceSynchronize");
        rc = ((hipError_t(*)(void))g_export[9])();
        step_ret(rc);
        step_close();

        const int codes[4] = {0, 719, 4001, 999};
        for (unsigned i = 0; i < 4; ++i) {
            step_open("S06.hipGetErrorString", "hipGetErrorString");
            const char* s = ((const char*(*)(hipError_t))g_export[4])(codes[i]);
            step_kv_int("code", codes[i]);
            step_kv_str("string", s ? s : "(null)");
            step_close();
        }
    }

    // ------------------------------------------------------- S07 push/pop
    {
        hipDim3 g = {11, 12, 13};
        hipDim3 b = {21, 22, 23};
        step_open("S07.__hipPushCallConfiguration", "__hipPushCallConfiguration");
        hipError_t rc =
            ((hipError_t(*)(hipDim3, hipDim3, size_t, hipStream_t))g_export[7])(
                g, b, 128, nullptr);
        step_ret(rc);
        step_close();

        hipDim3 pg = {0, 0, 0};
        hipDim3 pb = {0, 0, 0};
        size_t  sm = 0;
        hipStream_t st = (hipStream_t)0x1;
        step_open("S07.__hipPopCallConfiguration", "__hipPopCallConfiguration");
        rc = ((hipError_t(*)(hipDim3*, hipDim3*, size_t*, hipStream_t*))
              g_export[6])(&pg, &pb, &sm, &st);
        step_ret(rc);
        step_kv_int("grid_x", pg.x);
        step_kv_int("grid_y", pg.y);
        step_kv_int("grid_z", pg.z);
        step_kv_int("block_x", pb.x);
        step_kv_int("block_y", pb.y);
        step_kv_int("block_z", pb.z);
        step_kv_int("sharedMem", (long long)sm);
        step_kv_ptr("stream", st);
        step_close();
    }

    // ---------------------------------------------------------- S08 events
    {
        step_open("S08.hipEventCreate_e0", "hipEventCreate");
        hipError_t rc = ((hipError_t(*)(hipEvent_t*))g_export[11])(&g_e0);
        note_handle(g_e0);
        step_ret(rc);
        step_kv_ptr("event", g_e0);
        step_close();

        step_open("S08.hipEventCreate_e1", "hipEventCreate");
        rc = ((hipError_t(*)(hipEvent_t*))g_export[11])(&g_e1);
        note_handle(g_e1);
        step_ret(rc);
        step_kv_ptr("event", g_e1);
        step_kv_int("distinct_from_e0", (g_e1 != g_e0) ? 1 : 0);
        step_close();

        step_open("S08.hipEventRecord", "hipEventRecord");
        rc = ((hipError_t(*)(hipEvent_t, hipStream_t))g_export[13])(g_e0, nullptr);
        step_ret(rc);
        step_close();

        step_open("S08.hipEventSynchronize", "hipEventSynchronize");
        rc = ((hipError_t(*)(hipEvent_t))g_export[14])(g_e0);
        step_ret(rc);
        step_close();

        float ms = -1.0f;
        step_open("S08.hipEventElapsedTime", "hipEventElapsedTime");
        rc = ((hipError_t(*)(float*, hipEvent_t, hipEvent_t))g_export[12])(
            &ms, g_e0, g_e1);
        step_ret(rc);
        step_kv_int("ms_x1000", (long long)(ms * 1000.0f));
        step_close();

        // NEGATIVE: an event handle the witness never minted.  The backend's own
        // ownership rule must fire, and the bridge must pass that code back
        // UNCHANGED -- a bridge that masked it would be altering behaviour.
        step_open("S08.hipEventRecord_FOREIGN", "hipEventRecord");
        rc = ((hipError_t(*)(hipEvent_t, hipStream_t))g_export[13])(
            (hipEvent_t)g_src, nullptr);
        step_ret(rc);
        step_kv_str("expect", "backend ownership refusal, forwarded unchanged");
        step_close();
    }

    // -------------------------------------------------- S09 external memory
    {
        step_open("S09.hipImportExternalMemory", "hipImportExternalMemory");
        hipError_t rc =
            ((hipError_t(*)(hipExternalMemory_t*,
                            const struct hipExternalMemoryHandleDesc*))
             g_export[20])(&g_extmem,
                           (const struct hipExternalMemoryHandleDesc*)
                               g_extmem_desc);
        note_handle(g_extmem);
        step_ret(rc);
        step_kv_ptr("extMem", g_extmem);
        step_close();

        void* mapped = nullptr;
        step_open("S09.hipExternalMemoryGetMappedBuffer",
                  "hipExternalMemoryGetMappedBuffer");
        rc = ((hipError_t(*)(void**, hipExternalMemory_t,
                             const struct hipExternalMemoryBufferDesc*))
              g_export[15])(&mapped, g_extmem,
                            (const struct hipExternalMemoryBufferDesc*)
                                g_buf_desc);
        step_ret(rc);
        step_kv_int("mapped_non_null", mapped ? 1 : 0);
        step_close();

        step_open("S09.hipDestroyExternalMemory", "hipDestroyExternalMemory");
        rc = ((hipError_t(*)(hipExternalMemory_t))g_export[8])(g_extmem);
        step_ret(rc);
        step_close();
    }

    // ---------------------------------------------------------- S10 memory
    {
        void* p = nullptr;
        step_open("S10.hipMalloc", "hipMalloc");
        hipError_t rc = ((hipError_t(*)(void**, size_t))g_export[21])(&p, 4096);
        note_handle(p);
        step_ret(rc);
        step_kv_int("returned_non_null", p ? 1 : 0);
        step_close();

        // The byte values are recorded RAW, before and after, rather than as a
        // boolean against an expectation the driver computed: a boolean would
        // hide which side moved.
        const unsigned dst0_before = g_dst[0];
        const unsigned dst16_before = g_dst[16];
        step_open("S10.hipMemcpy", "hipMemcpy");
        rc = ((hipError_t(*)(void*, const void*, size_t, hipMemcpyKind))
              g_export[22])(g_dst, g_src, 16, 1);
        step_ret(rc);
        step_kv_int("dst_byte0_before", dst0_before);
        step_kv_int("dst_byte0_after", g_dst[0]);
        step_kv_int("dst_byte15_after", g_dst[15]);
        step_kv_int("dst_byte16_before", dst16_before);
        step_kv_int("dst_byte16_after", g_dst[16]);
        step_close();

        const unsigned d2_0 = g_dst2[0];
        const unsigned d2_8 = g_dst2[8];
        step_open("S10.hipMemcpyAsync", "hipMemcpyAsync");
        rc = ((hipError_t(*)(void*, const void*, size_t, hipMemcpyKind,
                             hipStream_t))g_export[23])(g_dst2, g_src, 16, 1,
                                                        nullptr);
        step_ret(rc);
        step_kv_int("dst2_byte0_before", d2_0);
        step_kv_int("dst2_byte0_after", g_dst2[0]);
        step_kv_int("dst2_byte8_before", d2_8);
        step_kv_int("dst2_byte8_after", g_dst2[8]);
        step_close();

        step_open("S10.hipMemcpyToSymbol", "hipMemcpyToSymbol");
        rc = ((hipError_t(*)(const void*, const void*, size_t, size_t,
                             hipMemcpyKind))g_export[24])(g_arg_e0, g_src, 8, 0,
                                                          1);
        step_ret(rc);
        step_close();

        const unsigned m0 = g_dst2[0];
        const unsigned m8 = g_dst2[8];
        step_open("S10.hipMemset", "hipMemset");
        rc = ((hipError_t(*)(void*, int, size_t))g_export[25])(g_dst2, 0x5A, 8);
        step_ret(rc);
        step_kv_int("dst2_byte0_before", m0);
        step_kv_int("dst2_byte0_after", g_dst2[0]);
        step_kv_int("dst2_byte8_before", m8);
        step_kv_int("dst2_byte8_after", g_dst2[8]);
        step_close();

        step_open("S10.hipMemsetAsync", "hipMemsetAsync");
        rc = ((hipError_t(*)(void*, int, size_t, hipStream_t))g_export[26])(
            g_dst2, 0x3C, 4, nullptr);
        step_ret(rc);
        step_kv_int("dst2_byte0_after_async", g_dst2[0]);
        step_close();

        step_open("S10.hipFree", "hipFree");
        rc = ((hipError_t(*)(void*))g_export[16])(p);
        step_ret(rc);
        step_close();
    }

    // ------------------------------------------------- S11 THE LAUNCH MATRIX
    // Every launch forwards to the WITNESS (the gate is ON for this process), so
    // the same launch is observed on BOTH sides of the bridge: the driver sees
    // the return value, the witness sees the arguments it received.
    {
        hipDim3 nb = {1, 2, 3};
        hipDim3 db = {4, 5, 6};
        struct L {
            const char* step;
            const void* fn;
            void**      args;
            const char* identity;
            const char* note;
        };
        const L ls[6] = {
            {"S11.LAUNCH_opener_wait", (const void*)dummy_wait, g_arr_w,
             "_Z11k_flag_waitPjjj", "opener, 3 explicit args, stream null"},
            {"S11.LAUNCH_closer_set", (const void*)dummy_set, g_arr_s,
             "_Z10k_flag_setPjj", "closer, 2 explicit args, stream null"},
            {"S11.LAUNCH_views_byvalue", (const void*)dummy_views, g_arr_c,
             "_Z16k_conv_res_views12ConvPlParams",
             "single BY_VALUE struct, 72 B: the shape the legacy capture read "
             "from args[0] with a union length"},
            {"S11.LAUNCH_unregistered", (const void*)dummy_unregistered, g_arr_e,
             "<UNREGISTERED>",
             "no ledger entry: capture must refuse, launch must still forward"},
            {"S11.LAUNCH_wait_missing_arg", (const void*)dummy_wait,
             g_arr_nullarg, "_Z11k_flag_waitPjjj",
             "args[0] is null: capture must refuse rather than read through it"},
            {"S11.LAUNCH_repeat_wait", (const void*)dummy_wait, g_arr_w,
             "_Z11k_flag_waitPjjj", "repeat, to exercise frame grouping"},
        };
        for (unsigned i = 0; i < 6; ++i) {
            step_open(ls[i].step, "hipLaunchKernel");
            step_kv_str("identity", ls[i].identity);
            step_kv_str("note", ls[i].note);
            hipError_t rc = p_launch(ls[i].fn, nb, db, ls[i].args, 0, nullptr);
            step_ret(rc);
            step_close();
            canary_check(ls[i].step);
        }
    }

    // ------------------------------------ S92 the driver's OWN arg prediction
    // WHAT THIS IS FOR
    //   The capture layer's record states, per host argument, the bytes it read
    //   through the pointer the caller supplied.  This step states, in the same
    //   vocabulary, the bytes the DRIVER believes it put there.  The two facts
    //   have different lineages -- one is a compile-time static table of what
    //   the driver fills, the other is a runtime read of a caller-supplied
    //   address -- and they agree only if the capture read the pointer it was
    //   handed.  A layer that read the wrong address, or the wrong length, would
    //   produce bytes that agree with the RECORD and disagree with this.
    //
    //   It is NOT an independent oracle on its own: the comparator also carries
    //   its own seed table read out of this file's buffer initialisation, and
    //   checks THIS table against that.  Two comparisons, so neither the driver
    //   nor the layer is grading its own homework.
    {
        struct Pred {
            const char* symbol;
            unsigned    idx;
            const char* region;
            const unsigned char* p;
            unsigned    n;
        };
        const Pred preds[] = {
            {"_Z11k_flag_waitPjjj", 0, "arg:w0", g_arg_w0, 8},
            {"_Z11k_flag_waitPjjj", 1, "arg:w1", g_arg_w1, 4},
            {"_Z11k_flag_waitPjjj", 2, "arg:w2", g_arg_w2, 4},
            {"_Z10k_flag_setPjj", 0, "arg:s0", g_arg_s0, 8},
            {"_Z10k_flag_setPjj", 1, "arg:s1", g_arg_s1, 4},
            {"_Z16k_conv_res_views12ConvPlParams", 0, "arg:c0", g_arg_c0, 72},
        };
        step_open("S92.declared_arg_patterns", "driver buffer prediction");
        for (unsigned i = 0; i < sizeof(preds) / sizeof(preds[0]); ++i) {
            char key[160];
            std::snprintf(key, sizeof(key), "%s#%u", preds[i].symbol, preds[i].idx);
            char hex[256];
            unsigned k = 0;
            for (unsigned b = 0; b < preds[i].n && k + 3 < sizeof(hex); ++b) {
                std::snprintf(hex + k, sizeof(hex) - k, "%02x", preds[i].p[b]);
                k += 2;
            }
            hex[k] = '\0';
            o(",\"%s\":{\"region\":\"%s\",\"declared_bytes\":%u,"
              "\"expected_bytes_hex\":\"%s\"}",
              key, preds[i].region, preds[i].n, hex);
        }
        step_close();
    }

    // ------------------------------------------------------- S12 canary final
    canary_check("S12.canary_final");    step_open("S12.canary_summary", "canary");
    step_kv_int("checks", g_canary_checks);
    step_kv_int("failures", g_canary_failures);
    step_close();

    // ------------------------------------------------ S13 unregister + snapshot
    step_open("S13.__hipUnregisterFatBinary", "__hipUnregisterFatBinary");
    p_unregister_fatbin(g_modules);
    step_kv_ptr("modules", g_modules);
    step_close();

    if (p_w_snapshot) {
        p_w_snapshot();
    }

    // ------------------------------------------------------- S14 bridge log
    {
        char  logpath[MAX_PATH * 2];
        DWORD n = GetEnvironmentVariableA("DLSSNR_BRIDGE_LOG", logpath,
                                          (DWORD)sizeof(logpath));
        if (n == 0 || n >= sizeof(logpath)) {
            std::snprintf(logpath, sizeof(logpath), "%s\\amdhip64_7_bridge.log",
                          run_dir);
        }
        read_bridge_log(logpath);
    }
    step_open("S14.bridge_log_event_kinds", "bridge_log");
    step_kv_int("n_kinds", g_nev);
    for (unsigned i = 0; i < g_nev; ++i) {
        o(",\"%s\":%u", g_ev[i].kind, g_ev[i].n);
    }
    step_close();

    o("\n ],\n");
    o(" \"canary\":{\"checks\":%u,\"failures\":%u},\n", g_canary_checks,
      g_canary_failures);
    o(" \"arm_complete\":true\n}\n");
}

// ============================================================== child cases

// GATE OFF: with the launch gate at its shipping default, hipLaunchKernel must
// return the real failure code WITHOUT submitting, and the witness must see no
// launch at all.  This is the case that establishes the gate is closed by
// default -- the standing safety property of the whole project.
void case_gate_off(const char* out)
{
    (void)out;
    fill_common();
    int wsize = 64;
    g_modules = p_register_fatbin(g_wrapper_plain);
    p_register_function(g_modules, (const void*)dummy_wait, (char*)g_fn_device,
                        "_Z11k_flag_waitPjjj", 0, nullptr, nullptr, nullptr,
                        nullptr, &wsize);

    hipDim3 nb = {1, 1, 1};
    hipDim3 db = {1, 1, 1};
    hipError_t rc = p_launch((const void*)dummy_wait, nb, db, g_arr_w, 0, nullptr);

    const char* gate = std::getenv("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH");
    o("{\"case\":\"gate_off\",\"gate_env\":\"%s\",\"ret\":%lld,"
      "\"ret_is_hipErrorLaunchFailure\":%d}\n",
      gate ? gate : "(unset)", (long long)rc, rc == 719 ? 1 : 0);
}

// RECORDER FAILURE: RAW_DUMP_DIR points at something that cannot be a directory.
// The capture must refuse and stay silent -- and the LAUNCH must be completely
// unaffected.  The parent pairs this with the witness log, so "the capture was
// invalid" and "the launch was untouched" are two SEPARATE measurements rather
// than one assertion.
void case_recorder_invalid(const char* out)
{
    (void)out;
    fill_common();
    int wsize = 64;
    g_modules = p_register_fatbin(g_wrapper_plain);
    p_register_function(g_modules, (const void*)dummy_wait, (char*)g_fn_device,
                        "_Z11k_flag_waitPjjj", 0, nullptr, nullptr, nullptr,
                        nullptr, &wsize);
    p_register_function(g_modules, (const void*)dummy_set, (char*)g_fn_device,
                        "_Z10k_flag_setPjj", 0, nullptr, nullptr, nullptr,
                        nullptr, &wsize);

    hipDim3 nb = {1, 1, 1};
    hipDim3 db = {1, 1, 1};
    char dir[MAX_PATH * 2] = {0};
    GetEnvironmentVariableA("RAW_DUMP_DIR", dir, (DWORD)sizeof(dir));
    char edir[8192];
    json_esc(dir, edir, sizeof(edir));
    hipError_t rc1 = p_launch((const void*)dummy_wait, nb, db, g_arr_w, 0, nullptr);
    hipError_t rc2 = p_launch((const void*)dummy_set, nb, db, g_arr_s, 0, nullptr);

    o("{\"case\":\"recorder_invalid\",\"raw_dump_dir\":\"%s\","
      "\"launch_wait_ret\":%lld,\"launch_set_ret\":%lld,"
      "\"both_forwards_returned_success\":%d}\n",
      edir, (long long)rc1, (long long)rc2, (rc1 == 0 && rc2 == 0) ? 1 : 0);
}

// GUARD PAGE: the by-value argument's declared size is 72 bytes.  With
// `undersized`, only 8 of those bytes are readable and the rest of the page is
// PAGE_NOACCESS, so ANY read past the 8th byte raises an access violation and
// kills the child.  This turns "does the capture read past the declared size?"
// into an exit code instead of a claim.
//
// The sized variant is the POSITIVE CONTROL: it must survive, or the guard-page
// apparatus itself would be rejecting a known-good case and reading as strict.
void case_overread_guard(const char* out, bool undersized)
{
    (void)out;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    const size_t page = si.dwPageSize;
    unsigned char* base = (unsigned char*)VirtualAlloc(
        nullptr, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (base == nullptr) {
        o("{\"case\":\"overread_guard\",\"status\":\"ALLOC_FAILED\"}\n");
        return;
    }
    DWORD old = 0;
    VirtualProtect(base + page, page, PAGE_NOACCESS, &old);

    // the argument buffer ENDS at the guard page boundary
    unsigned char* argbuf = base + page - 72;
    for (unsigned i = 0; i < 72; ++i) {
        argbuf[i] = (unsigned char)(0x10 + i);
    }
    if (undersized) {
        // Only the LAST 8 bytes stay readable; the 64 bytes below them become
        // unreadable.  A 72-byte read starting at argbuf therefore crosses into
        // a non-readable page and faults -- while an 8-byte read does not.
        DWORD o2 = 0;
        VirtualProtect(base, page - 8, PAGE_NOACCESS, &o2);
    }

    void* arr[1];
    arr[0] = argbuf;
    // THE DECLARED CAPACITY MUST BE THE SIZE READABLE **AT THE ADDRESS THE
    // CALLER PASSED**, not the size readable anywhere in the allocation.
    //
    // The first version of this case declared 8 for the undersized variant, on
    // the reasoning that only 8 bytes remain readable.  They are readable at
    // argbuf+64, not at argbuf: the witness probes a declared region from its
    // FIRST byte, so it read argbuf[0] inside the PAGE_NOACCESS span and faulted
    // -- on all three bridges, including the shipping baseline, which proved the
    // case had been measuring the witness rather than the capture layer.
    //
    // Declaring 0 makes the witness refuse to read at all (it reports
    // NOT_A_DATA_REGION), which is the truth: at THIS address there is nothing
    // the caller has made readable.  The capture layer, which reads the size the
    // argspec declares rather than the size that exists, is then the only thing
    // that can fault -- which is exactly the quantity this case exists to
    // measure.
    declare_n((const void*)argbuf,
              undersized ? "arg:guard_undersized" : "arg:guard_sized",
              undersized ? 0u : 72u);
    declare_n(arr, "arr:guard", sizeof(arr));
    declare_fn((const void*)dummy_views, "fn:k_conv_res_views");
    witness_declare_all();

    int wsize = 64;
    g_modules = p_register_fatbin(g_wrapper_plain);
    p_register_function(g_modules, (const void*)dummy_views, (char*)g_fn_device,
                        "_Z16k_conv_res_views12ConvPlParams", 0, nullptr, nullptr,
                        nullptr, nullptr, &wsize);

    // written BEFORE the launch, and never overwritten: if the launch faults,
    // the parent still has this line and knows the child reached the launch.
    o("{\"case\":\"overread_guard\",\"undersized\":%d,"
      "\"declared_by_value_bytes\":72,\"readable_bytes\":%u,"
      "\"status\":\"ABOUT_TO_LAUNCH\"}\n",
      undersized ? 1 : 0, undersized ? 8u : 72u);
    // the flush must happen now, or a crash would discard the line that says the
    // child got this far
    {
        char tmp[MAX_PATH * 2];
        DWORD n = GetEnvironmentVariableA("P16AX_CHILD_NOTE", tmp, sizeof(tmp));
        if (n > 0 && n < sizeof(tmp)) {
            HANDLE h = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                char note[256];
                int m = std::snprintf(note, sizeof(note),
                                      "{\"undersized\":%d,\"status\":"
                                      "\"ABOUT_TO_LAUNCH\"}\n",
                                      undersized ? 1 : 0);
                DWORD w = 0;
                WriteFile(h, note, (DWORD)m, &w, nullptr);
                CloseHandle(h);
            }
        }
    }

    hipDim3 nb = {1, 1, 1};
    hipDim3 db = {1, 1, 1};
    hipError_t rc = p_launch((const void*)dummy_views, nb, db, arr, 0, nullptr);

    o("{\"case\":\"overread_guard\",\"undersized\":%d,\"status\":\"SURVIVED\","
      "\"ret\":%lld}\n",
      undersized ? 1 : 0, (long long)rc);
    if (p_w_snapshot) { p_w_snapshot(); }
}

// ===================================================== SYNTHETIC concurrency
//
// THE CEILING THIS CASE EXISTS TO STATE HONESTLY
//   All 2,239 authentic launches in the corpus sit on a SINGLE stream, so
//   genuine concurrency is NOT observable in the authentic data.  Everything
//   measured here is SYNTHETIC, and the word "SYNTHETIC" is carried in the
//   case's own output so it cannot be quoted as an observation.
//
// WHAT IT CAN AND CANNOT ESTABLISH
//   It establishes that the capture layer's OWN synchronisation -- the atomic
//   instance mint, the recursive-mutex frame machine, the serialised trace and
//   the thread_local record buffer -- survives genuinely overlapping
//   invocations.  It does NOT establish that the FRAME MACHINE groups
//   concurrent frames correctly: that machine is single-frame by design, and
//   with 8 streams open at once it will legitimately report aborted frames.
//   Frame grouping is therefore checked only on the single-stream corpus.
//
// WHY THE THREAD-SPECIFIC FILL PATTERN MATTERS
//   With one shared fill value, a record composed in another thread's buffer
//   would still carry the right bytes and the test would pass on a layer that
//   mis-attributes argument data.  Giving thread i a pattern of (0x30+i),
//   (0x40+i), (0x50+i) makes mis-attribution visible as a BYTES mismatch.

struct ConcSlot {
    unsigned long long tid;
    long long          ret[4];
    int                n_ok;
};
ConcSlot g_conc[8];

void child_note(const char* text)
{
    char tmp[MAX_PATH * 2];
    DWORD n = GetEnvironmentVariableA("P16AX_CHILD_NOTE", tmp, sizeof(tmp));
    if (n == 0 || n >= sizeof(tmp)) { return; }
    HANDLE h = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { return; }
    DWORD w = 0;
    WriteFile(h, text, (DWORD)std::strlen(text), &w, nullptr);
    CloseHandle(h);
}

DWORD WINAPI conc_proc(LPVOID param)
{
    const unsigned i = (unsigned)(uintptr_t)param;
    g_conc[i].tid  = (unsigned long long)GetCurrentThreadId();
    g_conc[i].n_ok = 0;
    void* stream = (void*)(uintptr_t)(0x2000 + i * 0x100);
    hipDim3 nb = {1, 1, 1};
    hipDim3 db = {1, 1, 1};
    for (int k = 0; k < 4; ++k) {
        const void* fn =
            (k % 2 == 0) ? (const void*)dummy_wait : (const void*)dummy_set;
        hipError_t rc = p_launch(fn, nb, db, g_conc_arr[i], 0, stream);
        g_conc[i].ret[k] = (long long)rc;
        if (rc == 0) { ++g_conc[i].n_ok; }
    }
    return 0;
}

void case_concurrency(const char* out)
{
    (void)out;
    fill_common();
    for (unsigned i = 0; i < 8; ++i) {
        for (unsigned b = 0; b < 8; ++b) {
            g_conc_w0[i][b] = (unsigned char)(0x30 + i);
        }
        for (unsigned b = 0; b < 4; ++b) {
            g_conc_s1[i][b] = (unsigned char)(0x40 + i);
            g_conc_s2[i][b] = (unsigned char)(0x50 + i);
        }
        char lb[48];
        std::snprintf(lb, sizeof(lb), "arg:conc_w0_%u", i);
        declare_n(g_conc_w0[i], lb, sizeof(g_conc_w0[i]));
        std::snprintf(lb, sizeof(lb), "arg:conc_s1_%u", i);
        declare_n(g_conc_s1[i], lb, sizeof(g_conc_s1[i]));
        std::snprintf(lb, sizeof(lb), "arg:conc_s2_%u", i);
        declare_n(g_conc_s2[i], lb, sizeof(g_conc_s2[i]));
        g_conc_arr[i][0] = g_conc_w0[i];
        g_conc_arr[i][1] = g_conc_s1[i];
        g_conc_arr[i][2] = g_conc_s2[i];
        std::snprintf(lb, sizeof(lb), "arr:conc_%u", i);
        declare_n(g_conc_arr[i], lb, sizeof(g_conc_arr[i]));
    }
    witness_declare_all();

    int wsize = 64;
    g_modules = p_register_fatbin(g_wrapper_plain);
    p_register_function(g_modules, (const void*)dummy_wait, (char*)g_fn_device,
                        "_Z11k_flag_waitPjjj", 0, nullptr, nullptr, nullptr,
                        nullptr, &wsize);
    p_register_function(g_modules, (const void*)dummy_set, (char*)g_fn_device,
                        "_Z10k_flag_setPjj", 0, nullptr, nullptr, nullptr,
                        nullptr, &wsize);

    const char* gate = std::getenv("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH");
    o("{\"case\":\"concurrency\",\"provenance\":\"SYNTHETIC\","
      "\"threads\":8,\"launches_per_thread\":4,\"total_launches\":32,"
      "\"gate_env\":\"%s\",\"status\":\"ABOUT_TO_SPAWN\"}\n",
      gate ? gate : "(unset)");
    // written BEFORE the spawn and never rewritten: if a worker faults the whole
    // process, the parent still holds the line that says the child got this far
    child_note("{\"case\":\"concurrency\",\"provenance\":\"SYNTHETIC\","
               "\"status\":\"ABOUT_TO_SPAWN\",\"total_launches\":32}\n");

    HANDLE th[8];
    for (unsigned i = 0; i < 8; ++i) {
        th[i] = CreateThread(nullptr, 0, conc_proc, (LPVOID)(uintptr_t)i, 0,
                             nullptr);
        if (th[i] == nullptr) {
            o("{\"case\":\"concurrency\",\"status\":\"SPAWN_FAILED\","
              "\"which\":%u}\n", i);
            return;
        }
    }
    WaitForMultipleObjects(8, th, TRUE, 60000);
    int total_ok = 0;
    for (unsigned i = 0; i < 8; ++i) {
        total_ok += g_conc[i].n_ok;
        CloseHandle(th[i]);
    }
    o("{\"case\":\"concurrency\",\"provenance\":\"SYNTHETIC\","
      "\"status\":\"SURVIVED\",\"total_launches\":32,"
      "\"total_returned_success\":%d,\"all_forwards_returned_success\":%d",
      total_ok, total_ok == 32 ? 1 : 0);
    for (unsigned i = 0; i < 8; ++i) {
        o(",\"t%u\":{\"tid\":%llu,\"n_ok\":%d,\"ret\":[%lld,%lld,%lld,%lld]}",
          i, g_conc[i].tid, g_conc[i].n_ok, g_conc[i].ret[0], g_conc[i].ret[1],
          g_conc[i].ret[2], g_conc[i].ret[3]);
    }
    o("}\n");
    if (p_w_snapshot) { p_w_snapshot(); }
}

}  // namespace
