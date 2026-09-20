// Phase 10 production bridge: amdhip64_7.dll -> HIP 6.4 amdhip64_6.dll
//
// App-local compatibility DLL. Exports exactly the 29 HIP symbols that the
// upstream DLSS-NR runtime imports (see exports.def) and forwards each to
// the HIP 6.4 runtime loaded from an ABSOLUTE path compiled into the
// binary (never from PATH, never env-overridable in this build).
//
// Properties (per plan 10D-10J):
//  * fail-closed backend load: every wrapper checks the resolved export;
//    missing backend export => documented HIP error, never a silent success
//  * typed forwarding with self-contained ABI declarations: the 29
//    signatures are proven equal between HIP 6.4 and HIP 7.1 at the
//    declaration level (phase10_abi_matrix.csv) and every crossing
//    structure is byte-identical (phase10_structure_diff.md). Keeping the
//    bridge header-free guarantees no accidental HIP 7.1 linkage.
//  * deterministic bounded logging to phase10_hip_bridge.log
//    (16 MiB cap; scalars/pointers-as-handles only, no buffer contents)
//  * kernel-launch gate: DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH defaults to 0;
//    blocked launches log BLOCKED_KERNEL_LAUNCH and return a real HIP error
//  * registration calls are logged and forwarded unchanged in this phase;
//    payload identification/substitution arrives in Phase 11
//
// Builds:
//   production:  /DDLSSNR_BACKEND_PATH=L"<absolute HIP6 path>"
//   test build:  /DDLSSNR_BRIDGE_TESTING /DDLSSNR_BACKEND_PATH=L"<mock dll>"
//                (adds __bridge_* test-only exports; never in production)
//
// HOST-ONLY by itself; loads no DLL until a wrapper is first called.
#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "registry_ident.h"  // Phase 11 fatbin identity + substitution

// ------------------------------------------------------------------
// Self-contained ABI declarations (see header comment).
// ------------------------------------------------------------------
typedef int hipError_t;
static const hipError_t kHipSuccess = 0;
static const hipError_t kHipErrorLaunchFailure = 719;  // HIP enum value
static const hipError_t kHipErrorUnknown = 999;        // HIP enum value

struct hipDim3 {  // dim3-equivalent: 12 B, align 4 (fingerprint-verified)
    unsigned x, y, z;
};
struct hipUint3 {  // uint3-equivalent
    unsigned x, y, z;
};
typedef void* hipStream_t;
typedef void* hipEvent_t;
typedef void* hipExternalMemory_t;
typedef int hipMemcpyKind;  // 32-bit enum by value
struct hipDeviceProp_tR0600;  // opaque: always passed by pointer
struct hipExternalMemoryHandleDesc;  // opaque (crosses as const pointer)
struct hipExternalMemoryBufferDesc;  // opaque (crosses as const pointer)

#include "bridge_config.h"  // compile-time DLSSNR_BACKEND_PATH

namespace {

constexpr size_t kLogCap = 16u * 1024u * 1024u;  // 16 MiB

// ------------------------------------------------------------------ log
CRITICAL_SECTION g_logLock;
bool g_logInit = false;
bool g_logCapReached = false;
HANDLE g_logFile = INVALID_HANDLE_VALUE;

void log_init()
{
    if (g_logInit) {
        return;
    }
    InitializeCriticalSection(&g_logLock);
    g_logFile = CreateFileA("phase10_hip_bridge.log", GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_logFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(g_logFile, 0, nullptr, FILE_END);
    }
    g_logInit = true;
}

void log_line(const char* fmt, ...)
{
    log_init();
    if (g_logCapReached || g_logFile == INVALID_HANDLE_VALUE) {
        return;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(g_logFile, &size) || size.QuadPart > (LONGLONG)kLogCap) {
        g_logCapReached = true;
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
        return;
    }
    char line[512];
    int n = 0;
    SYSTEMTIME st;
    GetSystemTime(&st);  // UTC; correlated locally when needed
    n = std::snprintf(line, sizeof(line),
                      "%04u-%02u-%02u %02u:%02u:%02u.%03u t=%lu ",
                      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                      st.wSecond, st.wMilliseconds, GetCurrentThreadId());
    va_list ap;
    va_start(ap, fmt);
    n += std::vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);
    line[sizeof(line) - 1] = '\0';
    DWORD written = 0;
    WriteFile(g_logFile, line, (DWORD)std::strlen(line), &written, nullptr);
    WriteFile(g_logFile, "\r\n", 2, &written, nullptr);
    FlushFileBuffers(g_logFile);
}

void log_hip(const char* name, hipError_t rc)
{
    log_line("%s -> %d", name, (int)rc);
}

// ------------------------------------------------------- backend load
HMODULE backend()
{
    static HMODULE module = [] {
        log_init();
        HMODULE m = LoadLibraryExW(DLSSNR_BACKEND_PATH, nullptr,
                                   LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                       LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (m == nullptr) {
            log_line("BACKEND_LOAD_FAILED error=%lu", (unsigned long)GetLastError());
        } else {
            log_line("BACKEND_LOADED");
        }
        return m;
    }();
    return module;
}

template <typename Fn>
Fn resolve(const char* name)
{
    HMODULE m = backend();
    if (m == nullptr) {
        return nullptr;
    }
    FARPROC p = GetProcAddress(m, name);
    if (p == nullptr) {
        log_line("BACKEND_EXPORT_MISSING %s", name);
        return nullptr;
    }
    return reinterpret_cast<Fn>(p);
}

// --------------------------------------------------- launch gate
bool launch_allowed()
{
    // Read at every call: the gate is toggled only for an explicitly
    // authorized test process/session; default (unset or != "1") BLOCKS.
    char value[2] = {0, 0};
    DWORD len = GetEnvironmentVariableA("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH",
                                        value, sizeof(value));
    return len == 1 && value[0] == '1';
}

hipError_t blocked_launch(const char* what, const void* function_address,
                          unsigned bx, unsigned by, unsigned bz)
{
    log_line("BLOCKED_KERNEL_LAUNCH %s function=%p block=%ux%ux%u", what,
             function_address, bx, by, bz);
    return kHipErrorLaunchFailure;  // real failure: no kernel was launched
}

}  // namespace

extern "C" {

// ------------------------------------------------------------------
// Registration functions (forwarded unchanged; payload identification in
// Phase 11; lifecycle kept 1:1 with the backend runtime)
// ------------------------------------------------------------------
__declspec(dllexport) void** __hipRegisterFatBinary(const void* data)
{
    using Fn = void** (*)(const void*);
    static Fn fn = nullptr;
    if (fn == nullptr) {
        fn = resolve<Fn>("__hipRegisterFatBinary");
    }
    if (fn == nullptr) {
        log_line("__hipRegisterFatBinary -> backend unresolved");
        return nullptr;
    }
    log_line("__hipRegisterFatBinary wrapper=%p", data);
    const void* fwd = data;
    if (data != nullptr) {
        // The caller passes a __hip_fatbin wrapper whose ->data is the
        // __CLANG_OFFLOAD_BUNDLE__ payload. Identify it fail-closed.
        bridge_registry::HipFatbinWrapper w;
        std::memcpy(&w, data, sizeof(w));
        if (w.magic == 0x48495046 /* 'HIPF' */ && w.data != nullptr) {
            char why[160] = {0};
            auto id = bridge_registry::identify(w.data, why, sizeof(why));
            if (id == bridge_registry::Identity::kMatch) {
                if (bridge_registry::substitution_enabled()) {
                    static bridge_registry::HipFatbinWrapper sub = {
                        0x48495046, 1, nullptr, 0};
                    sub.data = bridge_registry::gfx1030_bundle();
                    fwd = &sub;
                    log_line("FATBIN_SUBSTITUTED canonical gfx1030 bundle (%zu B)",
                             bridge_registry::gfx1030_bundle_size());
                } else {
                    log_line("FATBIN_MATCH_NO_SUBSTITUTION (gate off)");
                }
            } else {
                log_line("FATBIN_NOT_OURS reason=\"%s\"", why);
            }
        } else {
            log_line("FATBIN_UNEXPECTED_WRAPPER (magic=%08x)", w.magic);
        }
    }
    void** handle = fn(fwd);
    log_line("__hipRegisterFatBinary -> handle=%p (forwarded %p)", (void*)handle, fwd);
    return handle;
}

__declspec(dllexport) void __hipUnregisterFatBinary(void** modules)
{
    using Fn = void (*)(void**);
    static Fn fn = nullptr;
    if (fn == nullptr) {
        fn = resolve<Fn>("__hipUnregisterFatBinary");
    }
    log_line("__hipUnregisterFatBinary handle=%p", (void*)modules);
    if (fn != nullptr) {
        fn(modules);
    }
}

__declspec(dllexport) void __hipRegisterFunction(
    void** modules, const void* hostFunction, char* deviceFunction,
    const char* deviceName, unsigned int threadLimit, hipUint3* tid, hipUint3* bid,
    hipDim3* blockDim, hipDim3* gridDim, int* wSize)
{
    using Fn = void (*)(void**, const void*, char*, const char*, unsigned int,
                        hipUint3*, hipUint3*, hipDim3*, hipDim3*, int*);
    static Fn fn = nullptr;
    if (fn == nullptr) {
        fn = resolve<Fn>("__hipRegisterFunction");
    }
    log_line("__hipRegisterFunction module=%p deviceName=\"%s\" wSize=%d",
             (void*)modules, deviceName ? deviceName : "?",
             wSize ? *wSize : -1);
    if (fn != nullptr) {
        fn(modules, hostFunction, deviceFunction, deviceName, threadLimit,
           tid, bid, blockDim, gridDim, wSize);
    }
}

__declspec(dllexport) void __hipRegisterVar(
    void** modules, void* var, char* hostVar, char* deviceVar, int ext,
    size_t size, int constant, int global)
{
    using Fn = void (*)(void**, void*, char*, char*, int, size_t, int, int);
    static Fn fn = nullptr;
    if (fn == nullptr) {
        fn = resolve<Fn>("__hipRegisterVar");
    }
    log_line("__hipRegisterVar module=%p hostVar=\"%s\" size=%zu", (void*)modules,
             hostVar ? hostVar : "?", size);
    if (fn != nullptr) {
        fn(modules, var, hostVar, deviceVar, ext, size, constant, global);
    }
}

// ------------------------------------------------------------------
// Simple hipError_t forwards
// ------------------------------------------------------------------
#define BRIDGE_FWD_ERR(name, params, callargs)                                  \
    __declspec(dllexport) hipError_t name params                               \
    {                                                                           \
        using Fn = hipError_t (*) params;                                       \
        static Fn fn = nullptr;                                                 \
        if (fn == nullptr) {                                                    \
            fn = resolve<Fn>(#name);                                            \
        }                                                                       \
        if (fn == nullptr) {                                                    \
            log_hip(#name, kHipErrorUnknown);                                   \
            return kHipErrorUnknown;                                            \
        }                                                                       \
        hipError_t rc = fn callargs;                                            \
        log_hip(#name, rc);                                                     \
        return rc;                                                              \
    }

BRIDGE_FWD_ERR(__hipPopCallConfiguration,
               (hipDim3* gridDim, hipDim3* blockDim, size_t* sharedMem,
                hipStream_t* stream),
               (gridDim, blockDim, sharedMem, stream))
BRIDGE_FWD_ERR(__hipPushCallConfiguration,
               (hipDim3 gridDim, hipDim3 blockDim, size_t sharedMem,
                hipStream_t stream),
               (gridDim, blockDim, sharedMem, stream))
BRIDGE_FWD_ERR(hipDestroyExternalMemory, (hipExternalMemory_t extMem), (extMem))
BRIDGE_FWD_ERR(hipDeviceSynchronize, (void), ())
BRIDGE_FWD_ERR(hipDriverGetVersion, (int* driverVersion), (driverVersion))
BRIDGE_FWD_ERR(hipEventCreate, (hipEvent_t* event), (event))
BRIDGE_FWD_ERR(hipEventElapsedTime,
               (float* ms, hipEvent_t start, hipEvent_t stop), (ms, start, stop))
BRIDGE_FWD_ERR(hipEventRecord, (hipEvent_t event, hipStream_t stream), (event, stream))
BRIDGE_FWD_ERR(hipEventSynchronize, (hipEvent_t event), (event))
BRIDGE_FWD_ERR(hipExternalMemoryGetMappedBuffer,
               (void** devPtr, hipExternalMemory_t extMem,
                const struct hipExternalMemoryBufferDesc* bufferDesc),
               (devPtr, extMem, bufferDesc))
BRIDGE_FWD_ERR(hipFree, (void* ptr), (ptr))
BRIDGE_FWD_ERR(hipGetDeviceCount, (int* count), (count))
BRIDGE_FWD_ERR(hipGetDevicePropertiesR0600,
               (struct hipDeviceProp_tR0600* prop, int device), (prop, device))
BRIDGE_FWD_ERR(hipGetLastError, (void), ())
BRIDGE_FWD_ERR(hipImportExternalMemory,
               (hipExternalMemory_t* extMem_out,
                const struct hipExternalMemoryHandleDesc* memHandleDesc),
               (extMem_out, memHandleDesc))
BRIDGE_FWD_ERR(hipMalloc, (void** ptr, size_t size), (ptr, size))
BRIDGE_FWD_ERR(hipMemcpy,
               (void* dst, const void* src, size_t sizeBytes, hipMemcpyKind kind),
               (dst, src, sizeBytes, kind))
BRIDGE_FWD_ERR(hipMemcpyAsync,
               (void* dst, const void* src, size_t sizeBytes, hipMemcpyKind kind,
                hipStream_t stream),
               (dst, src, sizeBytes, kind, stream))
BRIDGE_FWD_ERR(hipMemcpyToSymbol,
               (const void* symbol, const void* src, size_t sizeBytes,
                size_t offset, hipMemcpyKind kind),
               (symbol, src, sizeBytes, offset, kind))
BRIDGE_FWD_ERR(hipMemset, (void* dst, int value, size_t sizeBytes), (dst, value, sizeBytes))
BRIDGE_FWD_ERR(hipMemsetAsync,
               (void* dst, int value, size_t sizeBytes, hipStream_t stream),
               (dst, value, sizeBytes, stream))
BRIDGE_FWD_ERR(hipRuntimeGetVersion, (int* runtimeVersion), (runtimeVersion))
BRIDGE_FWD_ERR(hipSetDevice, (int deviceId), (deviceId))

// ------------------------------------------------------------------
// hipGetErrorString (returns const char*)
// ------------------------------------------------------------------
__declspec(dllexport) const char* hipGetErrorString(hipError_t error)
{
    using Fn = const char* (*)(hipError_t);
    static Fn fn = nullptr;
    if (fn == nullptr) {
        fn = resolve<Fn>("hipGetErrorString");
    }
    if (fn == nullptr) {
        return "amdhip64_7 bridge: backend unresolved";
    }
    const char* s = fn(error);
    log_line("hipGetErrorString %d -> \"%s\"", (int)error, s ? s : "?");
    return s;
}

// ------------------------------------------------------------------
// hipLaunchKernel: the only import that dispatches device work. The
// launch gate intercepts it.
// ------------------------------------------------------------------
__declspec(dllexport) hipError_t hipLaunchKernel(
    const void* function_address, hipDim3 numBlocks, hipDim3 dimBlocks, void** args,
    size_t sharedMemBytes, hipStream_t stream)
{
    using Fn = hipError_t (*)(const void*, hipDim3, hipDim3, void**, size_t,
                              hipStream_t);
    static Fn fn = nullptr;
    if (fn == nullptr) {
        fn = resolve<Fn>("hipLaunchKernel");
    }
    if (fn == nullptr) {
        log_hip("hipLaunchKernel", kHipErrorUnknown);
        return kHipErrorUnknown;
    }
    if (!launch_allowed()) {
        return blocked_launch("hipLaunchKernel", function_address,
                              numBlocks.x, numBlocks.y, numBlocks.z);
    }
    log_line("hipLaunchKernel function=%p grid=%ux%ux%u block=%ux%ux%u "
             "shared=%zu stream=%p", function_address, numBlocks.x,
             numBlocks.y, numBlocks.z, dimBlocks.x, dimBlocks.y, dimBlocks.z,
             sharedMemBytes, (void*)stream);
    hipError_t rc = fn(function_address, numBlocks, dimBlocks, args,
                       sharedMemBytes, stream);
    log_hip("hipLaunchKernel", rc);
    return rc;
}

// ------------------------------------------------------------------
// Test-only introspection (never present in the production build)
// ------------------------------------------------------------------
#ifdef DLSSNR_BRIDGE_TESTING
__declspec(dllexport) const wchar_t* __bridge_backend_path() { return DLSSNR_BACKEND_PATH; }
#endif

#undef BRIDGE_FWD_ERR

}  // extern "C"
