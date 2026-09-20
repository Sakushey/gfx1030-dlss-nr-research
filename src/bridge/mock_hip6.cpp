// Phase 10I mock backend: mock_hip6.dll
//
// Exports the same 29 symbols as the production backend (see
// exports.def) with deterministic sentinel behavior. Records every call
// into mock_hip6.log (name, scalar args) so the bridge smoke test can
// verify forwarding, the launch gate, and the registration path WITHOUT
// touching a GPU or the real HIP runtime.
//
// Deterministic behavior:
//   hipGetDeviceCount            -> *count = 1
//   hipGetDevicePropertiesR0600  -> name "Mock HIP6 Radeon RX 6950 XT",
//                                   gcnArchName "gfx1030", warpSize 32,
//                                   major/minor 10/3 style fields
//   hipMalloc/hipFree            -> VirtualAlloc arena
//   hipMemcpy*                   -> memcpy over the arena (kind-agnostic)
//   hipMemset*                   -> memset over the arena
//   versions                     -> 60400000 / 60040000 style constants
//   __hipRegisterFatBinary       -> sequential handle
//   __hipRegisterFunction/Var    -> record only
//   __hipUnregisterFatBinary     -> record only
//   hipLaunchKernel              -> record + hipSuccess (sentinel; the
//                                   bridge gate decides whether we see it)
//   everything else              -> hipSuccess
#include <windows.h>

#include <cstdio>
#include <cstring>

namespace {
HANDLE g_lock = nullptr;

void rec(const char* fmt, ...)
{
    if (g_lock == nullptr) {
        g_lock = CreateMutexA(nullptr, FALSE, nullptr);
    }
    if (g_lock) {
        WaitForSingleObject(g_lock, INFINITE);
    }
    FILE* f = nullptr;
    fopen_s(&f, "mock_hip6.log", "a");
    if (f) {
        char buf[384];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        std::fprintf(f, "t=%lu %s\n", GetCurrentThreadId(), buf);
        std::fclose(f);
    }
    if (g_lock) {
        ReleaseMutex(g_lock);
    }
}

void* arena_alloc(size_t size)
{
    static char* base = nullptr;
    static size_t used = 0;
    if (base == nullptr) {
        base = (char*)VirtualAlloc(nullptr, 64u << 20, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_READWRITE);
    }
    size_t off = used;
    used += (size + 15u) & ~15u;
    if (base == nullptr || used > (64u << 20)) {
        return nullptr;
    }
    return base + off;
}

int g_handleCounter = 0x100;
}  // namespace

#define MOCK_ERR(name)                                                           \
    extern "C" __declspec(dllexport) int name
#define MOCK_BEGIN(name)                                                         \
    rec("MOCK " #name);                                                          \
    {                                                                            \
        using fn_t = decltype(&name);                                            \
        (void)sizeof(fn_t);

#define MOCK_END() }

// HIP error enum sentinel constants used by the mock (match HIP 6.4):
namespace mock_hip {
constexpr int hipSuccess = 0;
}

extern "C" {

__declspec(dllexport) void** __hipRegisterFatBinary(const void* data)
{
    rec("MOCK __hipRegisterFatBinary data=%p", data);
    return (void**)(size_t)(++g_handleCounter);
}

__declspec(dllexport) void __hipUnregisterFatBinary(void** modules)
{
    rec("MOCK __hipUnregisterFatBinary handle=%p", (void*)modules);
}

__declspec(dllexport) void __hipRegisterFunction(
    void** modules, const void* hostFunction, char* deviceFunction,
    const char* deviceName, unsigned int threadLimit, void* tid, void* bid,
    void* blockDim, void* gridDim, int* wSize)
{
    rec("MOCK __hipRegisterFunction module=%p deviceName=\"%s\" wSize=%d",
        (void*)modules, deviceName ? deviceName : "?",
        wSize ? *wSize : -1);
}

__declspec(dllexport) void __hipRegisterVar(
    void** modules, void* var, char* hostVar, char* deviceVar, int ext,
    size_t size, int constant, int global)
{
    rec("MOCK __hipRegisterVar module=%p hostVar=\"%s\" size=%zu",
        (void*)modules, hostVar ? hostVar : "?", size);
}

__declspec(dllexport) int hipGetDeviceCount(int* count)
{
    rec("MOCK hipGetDeviceCount");
    if (count) {
        *count = 1;
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipGetDevicePropertiesR0600(void* prop_raw, int device)
{
    rec("MOCK hipGetDevicePropertiesR0600 device=%d", device);
    // Fill the ASCII fields of hipDeviceProp_tR0600 at their real HIP 6.4
    // offsets (verified in phase10_structure_diff.md / structure CSV:
    // name@0 [256], gcnArchName@1160 [256]). The smoke test asserts the
    // same offsets.
    if (prop_raw) {
        char* p = (char*)prop_raw;
        memset(p, 0, 2048);
        strcpy_s(p + 0, 256, "Mock HIP6 Radeon RX 6950 XT");
        strcpy_s(p + 1160, 256, "gfx1030");
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipSetDevice(int deviceId)
{
    rec("MOCK hipSetDevice device=%d", deviceId);
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipDeviceSynchronize()
{
    rec("MOCK hipDeviceSynchronize");
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipDriverGetVersion(int* version)
{
    rec("MOCK hipDriverGetVersion");
    if (version) {
        *version = 60040000;  // mock driver 6.4-style version
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipRuntimeGetVersion(int* version)
{
    rec("MOCK hipRuntimeGetVersion");
    if (version) {
        *version = 60400000;  // mock runtime 6.4.0-style version
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipMalloc(void** ptr, size_t size)
{
    rec("MOCK hipMalloc size=%zu", size);
    if (ptr) {
        *ptr = arena_alloc(size);
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipFree(void* ptr)
{
    rec("MOCK hipFree ptr=%p", ptr);
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipMemcpy(void* dst, const void* src, size_t sizeBytes, int kind)
{
    rec("MOCK hipMemcpy size=%zu kind=%d", sizeBytes, kind);
    if (dst && src) {
        memmove(dst, src, sizeBytes);
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipMemcpyAsync(void* dst, const void* src, size_t sizeBytes,
                                         int kind, void* stream)
{
    rec("MOCK hipMemcpyAsync size=%zu kind=%d stream=%p", sizeBytes, kind, stream);
    if (dst && src) {
        memmove(dst, src, sizeBytes);
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipMemcpyToSymbol(const void* symbol, const void* src,
                                            size_t sizeBytes, size_t offset, int kind)
{
    rec("MOCK hipMemcpyToSymbol symbol=%p size=%zu", symbol, sizeBytes);
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipMemset(void* dst, int value, size_t sizeBytes)
{
    rec("MOCK hipMemset size=%zu value=%d", sizeBytes, value);
    if (dst) {
        memset(dst, value, sizeBytes);
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipMemsetAsync(void* dst, int value, size_t sizeBytes, void* stream)
{
    rec("MOCK hipMemsetAsync size=%zu stream=%p", sizeBytes, stream);
    if (dst) {
        memset(dst, value, sizeBytes);
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipEventCreate(void** event)
{
    rec("MOCK hipEventCreate");
    if (event) {
        *event = (void*)(size_t)(++g_handleCounter);
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipEventRecord(void* event, void* stream)
{
    rec("MOCK hipEventRecord");
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipEventSynchronize(void* event)
{
    rec("MOCK hipEventSynchronize");
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipEventElapsedTime(float* ms, void* start, void* stop)
{
    rec("MOCK hipEventElapsedTime");
    if (ms) {
        *ms = 1.25f;
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipImportExternalMemory(void** extMem_out, const void* desc)
{
    rec("MOCK hipImportExternalMemory desc=%p", desc);
    if (extMem_out) {
        *extMem_out = (void*)(size_t)(++g_handleCounter);
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipDestroyExternalMemory(void* extMem)
{
    rec("MOCK hipDestroyExternalMemory");
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int hipExternalMemoryGetMappedBuffer(void** devPtr, void* extMem,
                                                           const void* desc)
{
    rec("MOCK hipExternalMemoryGetMappedBuffer");
    if (devPtr) {
        *devPtr = arena_alloc(1024);
    }
    return mock_hip::hipSuccess;
}

__declspec(dllexport) const char* hipGetErrorString(int error)
{
    rec("MOCK hipGetErrorString error=%d", error);
    return "mock hip success";
}

__declspec(dllexport) int hipGetLastError()
{
    rec("MOCK hipGetLastError");
    return mock_hip::hipSuccess;
}

// dim3-compatible layout (3 x unsigned, 12 B, align 4) -- must match the
// HIP 6.4 dim3 the bridge passes by value.
struct MockDim3 {
    unsigned x, y, z;
};

__declspec(dllexport) int hipLaunchKernel(const void* function_address,
                                          MockDim3 numBlocks, MockDim3 dimBlocks,
                                          void** args, size_t sharedMemBytes,
                                          void* stream)
{
    rec("MOCK hipLaunchKernel function=%p grid=%ux%ux%u block=%ux%ux%u shared=%zu",
        function_address, numBlocks.x, numBlocks.y, numBlocks.z,
        dimBlocks.x, dimBlocks.y, dimBlocks.z, sharedMemBytes);
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int __hipPopCallConfiguration(void* gridDim, void* blockDim,
                                                    size_t* sharedMem, void** stream)
{
    rec("MOCK __hipPopCallConfiguration");
    return mock_hip::hipSuccess;
}

__declspec(dllexport) int __hipPushCallConfiguration(unsigned gx, unsigned gy, unsigned gz,
                                                     unsigned bx, unsigned by, unsigned bz,
                                                     size_t sharedMem, void* stream)
{
    rec("MOCK __hipPushCallConfiguration");
    return mock_hip::hipSuccess;
}

}  // extern "C"
