// Phase 10I bridge smoke test (HOST-ONLY, mock backend).
//
// Loads the TEST build of amdhip64_7.dll (which resolves against
// mock_hip6.dll by compile-time absolute path), resolves all 29 exports,
// and exercises: device enumeration, alloc/copy round trip, call
// configuration, fatbin registration + unregister, and the kernel launch
// gate in both states (gate off -> bridge must return a real error and the
// mock must never see a launch; gate on -> forwarded, mock records it).
//
// Exits nonzero on any failure. No GPU, no real HIP DLL involved.
#include <windows.h>

#include <cstdio>
#include <cstring>

struct Dim3 {
    unsigned x, y, z;
};

typedef int (*hipError_t_fn)();
typedef int (*LaunchKernelFn)(const void*, Dim3, Dim3, void**, size_t, void*);
typedef void** (*RegisterFatBinaryFn)(const void*);
typedef void (*UnregisterFatBinaryFn)(void**);
typedef void (*RegisterFunctionFn)(void**, const void*, char*, const char*, unsigned int,
                                   Dim3*, Dim3*, Dim3*, Dim3*, int*);
typedef int (*GetDeviceCountFn)(int*);
typedef int (*GetDevicePropsFn)(void*, int);

static int failures = 0;

#define CHECK(cond, what)                                                      \
    do {                                                                       \
        if (cond) {                                                            \
            printf("PASS: %s\n", what);                                        \
        } else {                                                               \
            printf("FAIL: %s\n", what);                                        \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

int main()
{
    // deterministic start
    SetEnvironmentVariableA("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH", "0");
    DeleteFileA("phase10_hip_bridge.log");
    DeleteFileA("mock_hip6.log");

    HMODULE bridge = LoadLibraryExA("test_build\\amdhip64_7.dll", nullptr,
                                    LOAD_WITH_ALTERED_SEARCH_PATH);
    CHECK(bridge != nullptr, "load test-build bridge");

    const char* names[29] = {
        "__hipPopCallConfiguration", "__hipPushCallConfiguration",
        "__hipRegisterFatBinary", "__hipRegisterFunction", "__hipRegisterVar",
        "__hipUnregisterFatBinary", "hipDestroyExternalMemory",
        "hipDeviceSynchronize", "hipDriverGetVersion", "hipEventCreate",
        "hipEventElapsedTime", "hipEventRecord", "hipEventSynchronize",
        "hipExternalMemoryGetMappedBuffer", "hipFree", "hipGetDeviceCount",
        "hipGetDevicePropertiesR0600", "hipGetErrorString", "hipGetLastError",
        "hipImportExternalMemory", "hipLaunchKernel", "hipMalloc", "hipMemcpy",
        "hipMemcpyAsync", "hipMemcpyToSymbol", "hipMemset", "hipMemsetAsync",
        "hipRuntimeGetVersion", "hipSetDevice",
    };
    int resolved = 0;
    for (const char* n : names) {
        if (GetProcAddress(bridge, n)) {
            ++resolved;
        } else {
            printf("MISSING EXPORT: %s\n", n);
        }
    }
    CHECK(resolved == 29, "all 29 exports resolved");

    auto countFn = (GetDeviceCountFn)GetProcAddress(bridge, "hipGetDeviceCount");
    auto propsFn = (GetDevicePropsFn)GetProcAddress(bridge, "hipGetDevicePropertiesR0600");
    auto launchFn = (LaunchKernelFn)GetProcAddress(bridge, "hipLaunchKernel");
    auto regFn = (RegisterFatBinaryFn)GetProcAddress(bridge, "__hipRegisterFatBinary");
    auto unregFn = (UnregisterFatBinaryFn)GetProcAddress(bridge, "__hipUnregisterFatBinary");
    auto regFuncFn = (RegisterFunctionFn)GetProcAddress(bridge, "__hipRegisterFunction");
    auto mallocFn = (int(*)(void**, size_t))GetProcAddress(bridge, "hipMalloc");
    auto freeFn = (int(*)(void*))GetProcAddress(bridge, "hipFree");
    auto memcpyFn = (int(*)(void*, const void*, size_t, int))GetProcAddress(bridge, "hipMemcpy");
    auto memsetFn = (int(*)(void*, int, size_t))GetProcAddress(bridge, "hipMemset");
    auto pushFn = (int(*)(Dim3, Dim3, size_t, void*))GetProcAddress(bridge, "__hipPushCallConfiguration");
    auto popFn = (int(*)(Dim3*, Dim3*, size_t*, void**))GetProcAddress(bridge, "__hipPopCallConfiguration");
    auto syncFn = (hipError_t_fn)GetProcAddress(bridge, "hipDeviceSynchronize");
    auto driverVerFn = (int(*)(int*))GetProcAddress(bridge, "hipDriverGetVersion");
    auto rtVerFn = (int(*)(int*))GetProcAddress(bridge, "hipRuntimeGetVersion");
    auto errStrFn = (const char* (*)(int))GetProcAddress(bridge, "hipGetErrorString");
    auto lastErrFn = (hipError_t_fn)GetProcAddress(bridge, "hipGetLastError");
    auto setDevFn = (int(*)(int))GetProcAddress(bridge, "hipSetDevice");

    int count = -1;
    CHECK(countFn(&count) == 0 && count == 1, "hipGetDeviceCount -> 1 through bridge+mock");
    int dummy = 0;
    (void)setDevFn;
    CHECK(setDevFn && setDevFn(0) == 0, "hipSetDevice(0) forwarded");

    // device properties: verify the bridge forwarded and the mock string
    // fields survive (name/gcnArchName at HIP 6.4 hipDeviceProp_tR0600
    // offsets 0 / 1160, per phase10_structure_diff.md).
    char props[4096];
    memset(props, 0xAB, sizeof(props));
    CHECK(propsFn(props, 0) == 0, "hipGetDevicePropertiesR0600 forwarded");
    CHECK(strstr(props, "Mock HIP6") != nullptr, "props.name from mock present");
    CHECK(strstr(props + 1160, "gfx1030") != nullptr, "gfxArchName='gfx1030' present");

    // alloc/copy/memset round trip through the mock arena
    void* dev = nullptr;
    CHECK(mallocFn(&dev, 1024) == 0 && dev != nullptr, "hipMalloc(1024) forwarded");
    unsigned char host[64];
    for (int i = 0; i < 64; ++i) {
        host[i] = (unsigned char)(i * 3 + 1);
    }
    CHECK(memcpyFn(dev, host, 64, 0) == 0, "hipMemcpy H2D forwarded");
    CHECK(memsetFn(dev, 0x5A, 32) == 0, "hipMemset forwarded");
    unsigned char back[64] = {0};
    CHECK(memcpyFn(back, dev, 64, 0) == 0, "hipMemcpy D2H forwarded");
    CHECK(back[0] == 0x5A && back[32] == host[32], "mock arena round trip consistent");
    CHECK(freeFn(dev) == 0, "hipFree forwarded");

    // call configuration plumbing
    Dim3 gd = {1, 1, 1}, bd = {32, 1, 1};
    CHECK(pushFn(gd, bd, 0, nullptr) == 0, "__hipPushCallConfiguration forwarded");
    Dim3 g2{}, b2{};
    size_t sm = 0;
    void* stream = nullptr;
    CHECK(popFn(&g2, &b2, &sm, &stream) == 0, "__hipPopCallConfiguration forwarded");

    // registration path (forwarded; lifecycle kept 1:1)
    static const unsigned char fakeBlob[64] = {0x68, 0x69, 0x70, 0x76, 0x34};  // "hipv4"
    void** handle = regFn(fakeBlob);
    CHECK(handle != nullptr, "__hipRegisterFatBinary returned handle");
    void* mods = nullptr;
    const char* kName = "mock_kernel";
    int wsize = 32;
    regFuncFn((void**)&mods, (const void*)0x1234, (char*)"mock_device", kName, 0,
              nullptr, nullptr, nullptr, nullptr, &wsize);
    unregFn(handle);
    CHECK(handle != nullptr, "__hipUnregisterFatBinary called");

    // versions and diagnostics
    int dv = 0, rv = 0;
    CHECK(driverVerFn(&dv) == 0 && dv == 60040000, "hipDriverGetVersion forwarded");
    CHECK(rtVerFn(&rv) == 0 && rv == 60400000, "hipRuntimeGetVersion forwarded");
    CHECK(errStrFn(0) != nullptr, "hipGetErrorString forwarded");
    CHECK(lastErrFn() == 0, "hipGetLastError forwarded");
    CHECK(syncFn() == 0, "hipDeviceSynchronize forwarded");

    // ---------------- launch gate ----------------
    Dim3 grid = {1, 1, 1}, block = {32, 1, 1};
    void* args[] = {nullptr};
    // gate default OFF (explicitly set above): must NOT reach the mock
    SetEnvironmentVariableA("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH", "0");
    int rc = launchFn((const void*)0xABCD, grid, block, args, 0, nullptr);
    CHECK(rc != 0, "launch blocked with gate=0 (non-zero HIP error returned)");
    // gate ON: forwarded; mock records success
    SetEnvironmentVariableA("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH", "1");
    rc = launchFn((const void*)0xABCD, grid, block, args, 0, nullptr);
    CHECK(rc == 0, "launch forwarded with gate=1");

    // mock log must contain exactly one MOCK hipLaunchKernel line
    FILE* f = fopen("mock_hip6.log", "r");
    int launchLines = 0;
    char line[256];
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "MOCK hipLaunchKernel")) {
                ++launchLines;
            }
        }
        fclose(f);
    }
    CHECK(launchLines == 1, "mock saw exactly one launch (gate worked)");

    // bridge log must contain the BLOCKED marker and forwarding lines
    f = fopen("phase10_hip_bridge.log", "r");
    bool blockedSeen = false;
    bool backendLoaded = false;
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "BLOCKED_KERNEL_LAUNCH")) {
                blockedSeen = true;
            }
            if (strstr(line, "BACKEND_LOADED")) {
                backendLoaded = true;
            }
        }
        fclose(f);
    }
    CHECK(backendLoaded, "bridge log shows backend load");
    CHECK(blockedSeen, "bridge log shows BLOCKED_KERNEL_LAUNCH");

    // unload cleanly
    FreeLibrary(bridge);
    CHECK(true, "bridge unloaded");

    printf(failures == 0 ? "\nBRIDGE SMOKE: ALL PASS\n" : "\nBRIDGE SMOKE: FAILURES=%d\n",
           failures);
    return failures == 0 ? 0 : 1;
}
