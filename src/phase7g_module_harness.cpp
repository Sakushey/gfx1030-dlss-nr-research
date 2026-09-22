#include <hip/hip_runtime.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

struct ConvParams48 {
    uint64_t p0;
    uint64_t p1;
    uint64_t p2;
    uint64_t p3;
    uint64_t p4;
    int32_t split_count;
};
static_assert(sizeof(ConvParams48) == 48, "target user kernarg must remain 48 bytes");

static int report(const char* stage, hipError_t error)
{
    std::cout << stage << "=" << static_cast<int>(error)
              << " (" << hipGetErrorString(error) << ")\n";
    return error == hipSuccess ? 0 : 1;
}

int main(int argc, char** argv)
{
    const bool launch_no_work = argc >= 2 && std::string(argv[1]) == "--launch-no-work";
    const char* path = argc >= 3 ? argv[2] : argc >= 2 && !launch_no_work ? argv[1] : nullptr;
    if (path == nullptr) {
        std::cerr << "usage: phase7g_module_harness.exe [--launch-no-work] code_object.co\n";
        return 2;
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        std::cerr << "cannot open code object: " << path << "\n";
        return 2;
    }
    std::vector<char> image((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::cout << "code_object_bytes=" << image.size() << "\n";

    hipError_t error = hipInit(0);
    if (report("hipInit", error) != 0) return 3;
    int device = 0;
    error = hipGetDevice(&device);
    if (report("hipGetDevice", error) != 0) return 3;

    hipDeviceProp_t properties{};
    error = hipGetDeviceProperties(&properties, device);
    if (report("hipGetDeviceProperties", error) != 0) return 3;
    std::cout << "device=" << properties.name << " arch=" << properties.gcnArchName
              << " wavefront=" << properties.warpSize << "\n";

    hipModule_t module = nullptr;
    error = hipModuleLoadData(&module, image.data());
    if (report("hipModuleLoadData", error) != 0) return 4;

    hipFunction_t function = nullptr;
    error = hipModuleGetFunction(&function, module, "_Z13k_conv_splitk12ConvParams1d");
    if (report("hipModuleGetFunction", error) != 0) {
        hipModuleUnload(module);
        return 5;
    }
    std::cout << "symbol_resolution=PASS\n";

    if (!launch_no_work) {
        hipModuleUnload(module);
        std::cout << "registration_only=PASS\n";
        return 0;
    }

    constexpr size_t guard = 4096;
    constexpr size_t payload = 4096;
    constexpr size_t allocation = guard + payload + guard;
    std::vector<void*> raw(5, nullptr);
    std::vector<uint8_t> host(payload, 0);
    std::vector<uint8_t> before(payload, 0);
    for (void*& item : raw) {
        error = hipMalloc(&item, allocation);
        if (report("hipMalloc_guarded", error) != 0) {
            for (void* allocated : raw) if (allocated != nullptr) hipFree(allocated);
            hipModuleUnload(module);
            return 6;
        }
        error = hipMemset(item, 0, allocation);
        if (report("hipMemset_guarded", error) != 0) {
            for (void* allocated : raw) if (allocated != nullptr) hipFree(allocated);
            hipModuleUnload(module);
            return 6;
        }
    }

    ConvParams48 params{};
    params.p0 = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(raw[0]) + guard);
    params.p1 = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(raw[1]) + guard);
    params.p2 = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(raw[2]) + guard);
    params.p3 = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(raw[3]) + guard);
    params.p4 = reinterpret_cast<uintptr_t>(static_cast<uint8_t*>(raw[4]) + guard);
    params.split_count = 0;
    void* kernel_params[] = {&params};

    std::cout << "launch_config=grid(1,1,1) block(256,1,1) lds=4096 split_count=0\n";
    error = hipModuleLaunchKernel(function, 1, 1, 1, 256, 1, 1, 0, nullptr, kernel_params, nullptr);
    if (report("hipModuleLaunchKernel", error) != 0) {
        for (void* allocated : raw) hipFree(allocated);
        hipModuleUnload(module);
        return 7;
    }
    error = hipGetLastError();
    if (report("hipGetLastError", error) != 0) {
        for (void* allocated : raw) hipFree(allocated);
        hipModuleUnload(module);
        return 7;
    }
    error = hipDeviceSynchronize();
    if (report("hipDeviceSynchronize", error) != 0) {
        for (void* allocated : raw) hipFree(allocated);
        hipModuleUnload(module);
        return 8;
    }

    error = hipMemcpy(host.data(), static_cast<uint8_t*>(raw[0]) + guard, payload, hipMemcpyDeviceToHost);
    if (report("hipMemcpy_inspect", error) != 0) {
        for (void* allocated : raw) hipFree(allocated);
        hipModuleUnload(module);
        return 9;
    }
    size_t changed = 0;
    for (size_t index = 0; index < host.size(); ++index) {
        if (host[index] != before[index]) ++changed;
    }
    std::cout << "no_work_completed=PASS changed_bytes_buffer0=" << changed << "\n";

    for (void* allocated : raw) {
        error = hipFree(allocated);
        if (report("hipFree_guarded", error) != 0) {
            hipModuleUnload(module);
            return 10;
        }
    }
    error = hipModuleUnload(module);
    if (report("hipModuleUnload", error) != 0) return 11;
    std::cout << "result=PASS mode=registration-only\n" << (launch_no_work ? "NO_WORK_LAUNCH_PASS\n" : "")
              << "NO_WORK_LAUNCH_PROCESS_EXIT=0\n";
    return 0;
}
