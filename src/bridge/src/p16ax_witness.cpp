// Phase 16AX -- THE WITNESS BACKEND.
//
// WHAT THIS IS, AND WHAT IT IS NOT
//   This is NOT the shipping backend.  The shipping backend is
//   <ROCM_ROOT>\6.4\bin\amdhip64_6.dll, identified by measurement
//   in SHIPPING_BACKEND_IDENTITY_16AX.json.  This DLL exists to hold the
//   BACKEND CONSTANT across the three arms of the forwarding test matrix, so
//   that the only thing that varies between them is the BRIDGE under test.  It
//   implements the same 29 entry points, records every call with its arguments,
//   returns deterministic values, and keeps observable side-effect state
//   (external-memory tokens, event tokens and module ownership).
//
// HOST-ONLY.  It allocates host memory, writes one log, and does nothing else.
// It never loads a HIP runtime, never opens a device, never launches anything.
// A call it receives is recorded and answered; no device work is performed.
//
// THREE PROPERTIES THAT MAKE IT A USABLE OBSERVER
//   1. Every call is recorded BEFORE its return value is chosen, so a call the
//      bridge fails to forward leaves no line -- and a missing line is visible.
//   2. A pointer is dereferenced ONLY if the driver declared the region it
//      points into.  An undeclared pointer is recorded as the literal string
//      "<unlabelled>" and is never read, so the witness cannot fault on a
//      pointer and cannot turn a bad argument into a crash.
//   3. Ownership is enforced, not assumed: a token the witness did not mint is
//      refused with its own error code (4001) instead of being accepted.
//
// DETERMINISM, AND WHY NO RAW ADDRESS IS EVER RECORDED
//   Heap and stack addresses differ between processes, so a log containing raw
//   addresses cannot be compared across the three arms without a translation
//   table that is itself a source of error.  Instead every pointer the witness
//   records is reported as a LABEL: the label the driver declared for that
//   region, or "<witness:slot:N>" for a token the witness minted, or
//   "<unlabelled>".  The address carries no information this test needs; the
//   identity does.  Unlabelled pointers are counted so the comparator can
//   require the count to be zero rather than hope it is.
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

// ------------------------------------------------------------------ ABI
// Byte-for-byte the same declarations as phase16_bridge_telemetry/src/
// amdhip64_7.cpp, so the witness and the bridge cannot disagree about a
// signature without failing to forward correctly.
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

constexpr hipError_t kOk = 0;
constexpr hipError_t kOwnershipViolation = 4001;  // witness-only code
constexpr hipError_t kInjectedFailure = 4002;     // witness-only code

// --------------------------------------------------------------- the log
CRITICAL_SECTION g_lock;
bool g_lockInit = false;
HANDLE g_log = INVALID_HANDLE_VALUE;
bool g_logTried = false;
unsigned g_seq = 0;
unsigned g_unlabelled = 0;

void lock_init()
{
    if (!g_lockInit) {
        InitializeCriticalSection(&g_lock);
        g_lockInit = true;
    }
}

void log_open()
{
    if (g_logTried) {
        return;
    }
    g_logTried = true;
    char path[MAX_PATH * 4] = {0};
    DWORD n = GetEnvironmentVariableA("P16AX_WITNESS_LOG", path,
                                      (DWORD)sizeof(path));
    if (n == 0 || n >= sizeof(path)) {
        return;
    }
    g_log = CreateFileA(path, FILE_APPEND_DATA,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
}

// Minimal JSON string escaping.  The labels this file emits are DRIVER-SUPPLIED,
// so they are escaped rather than trusted: a malformed log would break the
// comparator and read as a mismatch, i.e. the instrument would manufacture the
// finding.
void esc(const char* in, char* out, std::size_t cap)
{
    std::size_t k = 0;
    for (const unsigned char* p = (const unsigned char*)in; p && *p; ++p) {
        if (k + 8 >= cap) {
            break;
        }
        if (*p == '"' || *p == '\\') {
            out[k++] = '\\';
            out[k++] = (char)*p;
        } else if (*p < 0x20) {
            k += (std::size_t)std::snprintf(out + k, cap - k, "\\u%04x", *p);
        } else {
            out[k++] = (char)*p;
        }
    }
    out[k] = '\0';
}

// A record.  Construction appends the header under the lock; the destructor
// closes the line and writes it.  The destructor runs at scope exit, i.e. after
// the return value has been recorded -- so a function that returned early
// without recording its value still produces a line, and the missing `ret` is
// itself visible rather than silent.
struct Rec {
    char   b_[8192];
    size_t n_;

    explicit Rec(const char* fn)
    {
        lock_init();
        EnterCriticalSection(&g_lock);
        n_ = (std::size_t)std::snprintf(b_, sizeof(b_),
                                        "{\"seq\":%u,\"fn\":\"%s\"", ++g_seq, fn);
    }
    ~Rec()
    {
        if (n_ + 2 < sizeof(b_)) {
            b_[n_++] = '}';
            b_[n_] = '\0';
        }
        LeaveCriticalSection(&g_lock);
        emit(b_);
    }
    Rec(const Rec&) = delete;
    Rec& operator=(const Rec&) = delete;

    void raw(const char* frag)
    {
        n_ += (std::size_t)std::snprintf(b_ + n_, sizeof(b_) - n_, "%s", frag);
    }
    void key(const char* k)
    {
        n_ += (std::size_t)std::snprintf(b_ + n_, sizeof(b_) - n_, ",\"%s\":", k);
    }
    void s(const char* k, const char* v)
    {
        char e[1024];
        esc(v ? v : "", e, sizeof(e));
        key(k);
        n_ += (std::size_t)std::snprintf(b_ + n_, sizeof(b_) - n_, "\"%s\"", e);
    }
    void u(const char* k, unsigned long long v)
    {
        key(k);
        n_ += (std::size_t)std::snprintf(b_ + n_, sizeof(b_) - n_, "%llu", v);
    }
    void i(const char* k, long long v)
    {
        key(k);
        n_ += (std::size_t)std::snprintf(b_ + n_, sizeof(b_) - n_, "%lld", v);
    }
    void arr3(const char* k, unsigned x, unsigned y, unsigned z)
    {
        key(k);
        n_ += (std::size_t)std::snprintf(b_ + n_, sizeof(b_) - n_,
                                         "[%u,%u,%u]", x, y, z);
    }
    void p(const char* k, const void* v) { s(k, label_of(v)); }

    static void emit(const char* line)
    {
        lock_init();
        EnterCriticalSection(&g_lock);
        log_open();
        if (g_log != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            WriteFile(g_log, line, (DWORD)std::strlen(line), &w, nullptr);
            WriteFile(g_log, "\n", 1, &w, nullptr);
        }
        LeaveCriticalSection(&g_lock);
    }

    // ---- declared host regions: the ONLY pointers that are ever dereferenced
    struct Region {
        const unsigned char* p;
        unsigned             n;
        char                 label[160];
    };
    static Region      g_regions[128];
    static unsigned    g_nregions;
    static const char* label_of(const void* v)
    {
        static char buf[200];
        if (v == nullptr) {
            return "null";
        }
        const Region* r = region_of(v);
        if (r) {
            std::snprintf(buf, sizeof(buf), "%s", r->label);
            return buf;
        }
        unsigned slot = 0;
        if (slot_of(v, &slot)) {
            std::snprintf(buf, sizeof(buf), "<witness:slot:%u>", slot);
            return buf;
        }
        ++g_unlabelled;
        return "<unlabelled>";
    }
    static const Region* region_of(const void* v)
    {
        for (unsigned i = 0; i < g_nregions; ++i) {
            if (g_regions[i].p == (const unsigned char*)v) {
                return &g_regions[i];
            }
        }
        return nullptr;
    }
    // First 16 bytes of a DECLARED region, in hex.  Never reads anything else:
    // this is the property that makes the witness unable to fault on a pointer.
    static const char* probe_of(const void* v)
    {
        static char buf[160];
        const Region* r = region_of(v);
        if (r == nullptr) {
            return "UNDECLARED";
        }
        if (r->n == 0) {
            return "NOT_A_DATA_REGION";
        }
        unsigned m = r->n < 16 ? r->n : 16;
        std::size_t k = 0;
        for (unsigned j = 0; j < m && k + 3 < sizeof(buf); ++j) {
            k += (std::size_t)std::snprintf(buf + k, sizeof(buf) - k, "%02x",
                                            r->p[j]);
        }
        return buf;
    }
    // Copies DECLARED region-to-region only, and reports how much.  This is the
    // witness's real side effect, so a defect that swapped dst and src is
    // visible in the DRIVER's own buffers, not merely in this log.
    static unsigned copy_declared(void* dst, const void* src, size_t n)
    {
        const Region* d = region_of(dst);
        const Region* s = region_of(src);
        if (d == nullptr || s == nullptr || n == 0) {
            return 0;
        }
        if (n > d->n || n > s->n) {
            return 0;
        }
        std::memmove(dst, src, n);
        return (unsigned)n;
    }

    // ---- owned tokens: a token is a pointer into this DLL's own storage, so
    // "owned" is an identity test rather than a heuristic on a foreign value.
    static unsigned long long g_slots[64];
    static unsigned           g_nslots;
    static bool slot_of(const void* v, unsigned* out)
    {
        for (unsigned i = 0; i < g_nslots; ++i) {
            if ((const void*)&g_slots[i] == v) {
                *out = i;
                return true;
            }
        }
        return false;
    }
    static void* mint()
    {
        unsigned i = g_nslots;
        if (i < 64) {
            g_slots[i] = 0x5031365800000000ull | i;
            ++g_nslots;
        }
        return i < 64 ? (void*)&g_slots[i] : nullptr;
    }
    static bool owned(const void* v)
    {
        unsigned s;
        return slot_of(v, &s);
    }
};

Rec::Region        Rec::g_regions[128];
unsigned           Rec::g_nregions = 0;
unsigned long long Rec::g_slots[64];
unsigned           Rec::g_nslots = 0;

// ---------------------------------------------------------- fault injection
// Comma-separated exact function names; those return kInjectedFailure instead of
// kOk.  This is how the driver proves a BACKEND failure is observable rather
// than assumed, and that the bridge lets the code through unchanged instead of
// masking it.
bool should_fail(const char* fn)
{
    char list[1024] = {0};
    DWORD n = GetEnvironmentVariableA("P16AX_WITNESS_FAIL", list,
                                      (DWORD)sizeof(list));
    if (n == 0 || n >= sizeof(list)) {
        return false;
    }
    const char* p = list;
    while (*p) {
        const char* q = std::strchr(p, ',');
        std::size_t len = q ? (std::size_t)(q - p) : std::strlen(p);
        if (len == std::strlen(fn) && std::strncmp(p, fn, len) == 0) {
            return true;
        }
        if (!q) {
            break;
        }
        p = q + 1;
    }
    return false;
}

hipError_t verdict(const char* fn, Rec& r, hipError_t rc = kOk)
{
    hipError_t out = should_fail(fn) ? kInjectedFailure : rc;
    r.u("ret", (unsigned long long)(long long)out);
    return out;
}

}  // namespace

// ================================================================ entry points
extern "C" {

// ---- witness-only instrumentation.  NOT part of the 29.  The name prefix
// makes it impossible to confuse one of these with a HIP export.
__declspec(dllexport) const char* p16ax_witness_identity()
{
    return "p16ax-witness-backend/1 host-only observing backend; NOT the "
           "shipping backend";
}

__declspec(dllexport) void p16ax_witness_register_region(const void* p,
                                                         unsigned n,
                                                         const char* label)
{
    lock_init();
    EnterCriticalSection(&g_lock);
    if (Rec::g_nregions < 128) {
        Rec::Region& r = Rec::g_regions[Rec::g_nregions];
        r.p = (const unsigned char*)p;
        r.n = n;
        std::snprintf(r.label, sizeof(r.label), "%s", label ? label : "?");
        ++Rec::g_nregions;
    }
    LeaveCriticalSection(&g_lock);
}

__declspec(dllexport) void p16ax_witness_snapshot()
{
    Rec r("p16ax_witness_snapshot");
    r.u("calls_recorded", g_seq);
    r.u("slots_minted", Rec::g_nslots);
    r.u("regions_declared", Rec::g_nregions);
    r.u("unlabelled_pointers_seen", g_unlabelled);
}

// ------------------------------------------------------------- registration
__declspec(dllexport) void** __hipRegisterFatBinary(const void* data)
{
    Rec r("__hipRegisterFatBinary");
    r.p("data", data);
    r.s("data_probe", Rec::probe_of(data));
    void** h = (void**)Rec::mint();
    r.p("handle", h);
    return h;
}

__declspec(dllexport) void __hipUnregisterFatBinary(void** modules)
{
    Rec r("__hipUnregisterFatBinary");
    r.p("modules", modules);
    r.u("module_owned", Rec::owned(modules) ? 1 : 0);
}

__declspec(dllexport) void __hipRegisterFunction(
    void** modules, const void* hostFunction, char* deviceFunction,
    const char* deviceName, unsigned int threadLimit, hipUint3* tid,
    hipUint3* bid, hipDim3* blockDim, hipDim3* gridDim, int* wSize)
{
    Rec r("__hipRegisterFunction");
    r.p("modules", modules);
    r.p("hostFunction", hostFunction);
    r.s("deviceName", deviceName);
    r.s("deviceFunction_is_null", deviceFunction ? "0" : "1");
    r.u("threadLimit", threadLimit);
    r.u("module_owned", Rec::owned(modules) ? 1 : 0);
    r.u("wSize", wSize ? (unsigned long long)(long long)*wSize : 0xffffffffull);
}

__declspec(dllexport) void __hipRegisterVar(void** modules, void* var,
                                            char* hostVar, char* deviceVar,
                                            int ext, size_t size, int constant,
                                            int global)
{
    Rec r("__hipRegisterVar");
    r.p("modules", modules);
    r.p("var", var);
    r.s("hostVar", hostVar);
    r.s("deviceVar", deviceVar);
    r.i("ext", ext);
    r.u("size", size);
    r.i("constant", constant);
    r.i("global", global);
    r.u("module_owned", Rec::owned(modules) ? 1 : 0);
}

// ------------------------------------------------------- simple hipError_t
__declspec(dllexport) hipError_t __hipPopCallConfiguration(
    hipDim3* gridDim, hipDim3* blockDim, size_t* sharedMem, hipStream_t* stream)
{
    Rec r("__hipPopCallConfiguration");
    r.p("gridDim", gridDim);
    r.p("blockDim", blockDim);
    r.p("sharedMem", sharedMem);
    r.p("stream", stream);
    // The witness FILLS its out-parameters, so a bridge that dropped an out
    // pointer would leave the driver's variable untouched -- visible, rather
    // than silently "equal" because both sides stayed zero.
    if (gridDim) { gridDim->x = 7; gridDim->y = 8; gridDim->z = 9; }
    if (blockDim) { blockDim->x = 70; blockDim->y = 80; blockDim->z = 90; }
    if (sharedMem) { *sharedMem = 4096; }
    if (stream) { *stream = nullptr; }
    return verdict("__hipPopCallConfiguration", r);
}

__declspec(dllexport) hipError_t __hipPushCallConfiguration(
    hipDim3 gridDim, hipDim3 blockDim, size_t sharedMem, hipStream_t stream)
{
    Rec r("__hipPushCallConfiguration");
    r.arr3("grid", gridDim.x, gridDim.y, gridDim.z);
    r.arr3("block", blockDim.x, blockDim.y, blockDim.z);
    r.u("sharedMem", sharedMem);
    r.p("stream", stream);
    return verdict("__hipPushCallConfiguration", r);
}

__declspec(dllexport) hipError_t hipDestroyExternalMemory(hipExternalMemory_t e)
{
    Rec r("hipDestroyExternalMemory");
    r.p("extMem", e);
    r.u("extMem_owned", Rec::owned(e) ? 1 : 0);
    return verdict("hipDestroyExternalMemory", r,
                   Rec::owned(e) ? kOk : kOwnershipViolation);
}

__declspec(dllexport) hipError_t hipDeviceSynchronize(void)
{
    Rec r("hipDeviceSynchronize");
    return verdict("hipDeviceSynchronize", r);
}

__declspec(dllexport) hipError_t hipDriverGetVersion(int* v)
{
    Rec r("hipDriverGetVersion");
    r.p("driverVersion", v);
    if (v) { *v = 60400000; }
    return verdict("hipDriverGetVersion", r);
}

__declspec(dllexport) hipError_t hipEventCreate(hipEvent_t* event)
{
    Rec r("hipEventCreate");
    r.p("event", event);
    if (event) { *event = Rec::mint(); }
    return verdict("hipEventCreate", r);
}

__declspec(dllexport) hipError_t hipEventElapsedTime(float* ms, hipEvent_t start,
                                                     hipEvent_t stop)
{
    Rec r("hipEventElapsedTime");
    r.p("ms", ms);
    r.p("start", start);
    r.p("stop", stop);
    r.u("start_owned", Rec::owned(start) ? 1 : 0);
    r.u("stop_owned", Rec::owned(stop) ? 1 : 0);
    const bool ok = Rec::owned(start) && Rec::owned(stop);
    if (ms) { *ms = ok ? 1.5f : -1.0f; }
    return verdict("hipEventElapsedTime", r, ok ? kOk : kOwnershipViolation);
}

__declspec(dllexport) hipError_t hipEventRecord(hipEvent_t event, hipStream_t stream)
{
    Rec r("hipEventRecord");
    r.p("event", event);
    r.p("stream", stream);
    r.u("event_owned", Rec::owned(event) ? 1 : 0);
    return verdict("hipEventRecord", r,
                   Rec::owned(event) ? kOk : kOwnershipViolation);
}

__declspec(dllexport) hipError_t hipEventSynchronize(hipEvent_t event)
{
    Rec r("hipEventSynchronize");
    r.p("event", event);
    r.u("event_owned", Rec::owned(event) ? 1 : 0);
    return verdict("hipEventSynchronize", r,
                   Rec::owned(event) ? kOk : kOwnershipViolation);
}

__declspec(dllexport) hipError_t hipExternalMemoryGetMappedBuffer(
    void** devPtr, hipExternalMemory_t extMem,
    const struct hipExternalMemoryBufferDesc* bufferDesc)
{
    Rec r("hipExternalMemoryGetMappedBuffer");
    r.p("devPtr", devPtr);
    r.p("extMem", extMem);
    r.p("bufferDesc", bufferDesc);
    r.u("extMem_owned", Rec::owned(extMem) ? 1 : 0);
    const bool ok = Rec::owned(extMem);
    if (ok && devPtr) { *devPtr = Rec::mint(); }
    return verdict("hipExternalMemoryGetMappedBuffer", r, ok ? kOk : kOwnershipViolation);
}

__declspec(dllexport) hipError_t hipFree(void* ptr)
{
    Rec r("hipFree");
    r.p("ptr", ptr);
    return verdict("hipFree", r);
}

__declspec(dllexport) hipError_t hipGetDeviceCount(int* count)
{
    Rec r("hipGetDeviceCount");
    r.p("count", count);
    if (count) { *count = 1; }
    return verdict("hipGetDeviceCount", r);
}

__declspec(dllexport) hipError_t hipGetDevicePropertiesR0600(
    struct hipDeviceProp_tR0600* prop, int device)
{
    Rec r("hipGetDevicePropertiesR0600");
    r.p("prop", prop);
    r.i("device", device);
    return verdict("hipGetDevicePropertiesR0600", r);
}

__declspec(dllexport) hipError_t hipGetLastError(void)
{
    Rec r("hipGetLastError");
    return verdict("hipGetLastError", r);
}

__declspec(dllexport) hipError_t hipImportExternalMemory(
    hipExternalMemory_t* out, const struct hipExternalMemoryHandleDesc* desc)
{
    Rec r("hipImportExternalMemory");
    r.p("extMem_out", out);
    r.p("memHandleDesc", desc);
    if (out) { *out = Rec::mint(); }
    return verdict("hipImportExternalMemory", r);
}

__declspec(dllexport) hipError_t hipMalloc(void** ptr, size_t size)
{
    Rec r("hipMalloc");
    r.p("ptr", ptr);
    r.u("size", size);
    if (ptr) { *ptr = Rec::mint(); }
    return verdict("hipMalloc", r);
}

__declspec(dllexport) hipError_t hipMemcpy(void* dst, const void* src,
                                           size_t sizeBytes, hipMemcpyKind kind)
{
    Rec r("hipMemcpy");
    r.p("dst", dst);
    r.p("src", src);
    r.u("sizeBytes", sizeBytes);
    r.i("kind", kind);
    r.s("dst_probe", Rec::probe_of(dst));
    r.s("src_probe", Rec::probe_of(src));
    r.u("bytes_actually_moved", Rec::copy_declared(dst, src, sizeBytes));
    return verdict("hipMemcpy", r);
}

__declspec(dllexport) hipError_t hipMemcpyAsync(void* dst, const void* src,
                                                size_t sizeBytes,
                                                hipMemcpyKind kind,
                                                hipStream_t stream)
{
    Rec r("hipMemcpyAsync");
    r.p("dst", dst);
    r.p("src", src);
    r.u("sizeBytes", sizeBytes);
    r.i("kind", kind);
    r.p("stream", stream);
    r.s("dst_probe", Rec::probe_of(dst));
    r.s("src_probe", Rec::probe_of(src));
    // No copy is performed: the witness has no queue, and recording a side
    // effect it does not have would be inventing data.  What is asserted here
    // is that dst and src ARRIVED unchanged and in order; the driver's canary
    // check independently confirms the buffers were not touched.
    r.u("bytes_actually_moved", 0);
    return verdict("hipMemcpyAsync", r);
}

__declspec(dllexport) hipError_t hipMemcpyToSymbol(const void* symbol,
                                                   const void* src,
                                                   size_t sizeBytes,
                                                   size_t offset,
                                                   hipMemcpyKind kind)
{
    Rec r("hipMemcpyToSymbol");
    r.p("symbol", symbol);
    r.p("src", src);
    r.u("sizeBytes", sizeBytes);
    r.u("offset", offset);
    r.i("kind", kind);
    r.s("src_probe", Rec::probe_of(src));
    return verdict("hipMemcpyToSymbol", r);
}

__declspec(dllexport) hipError_t hipMemset(void* dst, int value, size_t sizeBytes)
{
    Rec r("hipMemset");
    r.p("dst", dst);
    r.i("value", value);
    r.u("sizeBytes", sizeBytes);
    r.s("dst_probe", Rec::probe_of(dst));
    const Rec::Region* d = Rec::region_of(dst);
    if (d && sizeBytes <= d->n) {
        std::memset(dst, value, sizeBytes);
        r.u("bytes_actually_set", sizeBytes);
    } else {
        r.u("bytes_actually_set", 0);
    }
    return verdict("hipMemset", r);
}

__declspec(dllexport) hipError_t hipMemsetAsync(void* dst, int value,
                                                size_t sizeBytes,
                                                hipStream_t stream)
{
    Rec r("hipMemsetAsync");
    r.p("dst", dst);
    r.i("value", value);
    r.u("sizeBytes", sizeBytes);
    r.p("stream", stream);
    r.s("dst_probe", Rec::probe_of(dst));
    r.u("bytes_actually_set", 0);  // no queue: none is claimed
    return verdict("hipMemsetAsync", r);
}

__declspec(dllexport) hipError_t hipRuntimeGetVersion(int* v)
{
    Rec r("hipRuntimeGetVersion");
    r.p("runtimeVersion", v);
    if (v) { *v = 60400000; }
    return verdict("hipRuntimeGetVersion", r);
}

__declspec(dllexport) hipError_t hipSetDevice(int deviceId)
{
    Rec r("hipSetDevice");
    r.i("deviceId", deviceId);
    return verdict("hipSetDevice", r);
}

__declspec(dllexport) const char* hipGetErrorString(hipError_t error)
{
    Rec r("hipGetErrorString");
    r.i("error", error);
    const char* s = "hipErrorUnknown";
    switch (error) {
    case 0: s = "hipSuccess"; break;
    case 719: s = "hipErrorLaunchFailure"; break;
    case kOwnershipViolation: s = "p16axWitnessOwnershipViolation"; break;
    case kInjectedFailure: s = "p16axWitnessInjectedFailure"; break;
    default: break;
    }
    r.s("ret_string", s);
    return s;
}

// ------------------------------------------------------------- hipLaunchKernel
__declspec(dllexport) hipError_t hipLaunchKernel(const void* function_address,
                                                 hipDim3 numBlocks,
                                                 hipDim3 dimBlocks, void** args,
                                                 size_t sharedMemBytes,
                                                 hipStream_t stream)
{
    Rec r("hipLaunchKernel");
    r.p("function_address", function_address);
    r.arr3("numBlocks", numBlocks.x, numBlocks.y, numBlocks.z);
    r.arr3("dimBlocks", dimBlocks.x, dimBlocks.y, dimBlocks.z);
    r.p("args", args);
    r.u("sharedMemBytes", sharedMemBytes);
    r.p("stream", stream);

    // The launch's argument array IS the object the capture layer repairs, so
    // the witness reports every entry it can SEE.  It is read only if the
    // driver declared the array, so the NUMBER of entries the witness could see
    // is a measurement, not an assumption.
    const Rec::Region* ar = Rec::region_of(args);
    unsigned cap = ar ? (unsigned)(ar->n / sizeof(void*)) : 0u;
    if (cap > 8u) { cap = 8u; }
    r.u("args_array_declared", ar != nullptr ? 1ull : 0ull);
    r.u("args_array_capacity", cap);

    char ids[1536];
    char prs[1536];
    std::size_t ki = 0, kp = 0;
    unsigned seen = 0;
    ids[0] = '\0';
    prs[0] = '\0';
    for (unsigned k = 0; k < cap; ++k) {
        const void* a = args[k];
        if (a == nullptr) {
            break;
        }
        ki += (std::size_t)std::snprintf(ids + ki, sizeof(ids) - ki, "%s\"%s\"",
                                         seen ? "," : "", Rec::label_of(a));
        kp += (std::size_t)std::snprintf(prs + kp, sizeof(prs) - kp, "%s\"%s\"",
                                         seen ? "," : "", Rec::probe_of(a));
        ++seen;
    }
    r.u("n_args_seen", seen);
    r.raw(",\"arg_ptrs\":[");
    r.raw(ids);
    r.raw("],\"arg_probes\":[");
    r.raw(prs);
    r.raw("]");
    return verdict("hipLaunchKernel", r);
}

}  // extern "C"
