// Phase 14B metadata/kernarg runtime sentinel host.
// Loads the tiny gfx1030 diagnostic code object through the HIP 6.4 module
// API and performs EXACTLY ONE launch: grid(1,1,1) block(256,1,1).
// Kernel writes out[0..3] = {hidden_group_size_x, _y, _z,
//                             hidden_block_count_x} (lane-uniform values).
// Expects {256, 1, 1, 1}. No loop in the kernel, no benchmark here.
#include <hip/hip_runtime.h>

#include <chrono>
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
    uint32_t split_count;
};
static_assert(sizeof(ConvParams48) == 48, "user kernarg must remain 48 bytes");

static int report(const char* stage, hipError_t error)
{
    std::cout << stage << "=" << static_cast<int>(error)
              << " (" << hipGetErrorString(error) << ")\n";
    return error == hipSuccess ? 0 : 1;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: p14_diag_host.exe code_object.co\n";
        return 2;
    }

    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        std::cerr << "cannot open code object: " << argv[1] << "\n";
        return 2;
    }
    std::vector<char> image((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
    std::cout << "code_object_bytes=" << image.size() << "\n";

    hipError_t error = hipInit(0);
    if (report("hipInit", error) != 0) return 3;
    int device = 0;
    error = hipGetDevice(&device);
    if (report("hipGetDevice", error) != 0) return 3;
    hipDeviceProp_t properties{};
    error = hipGetDeviceProperties(&properties, device);
    if (report("hipGetDeviceProperties", error) != 0) return 3;
    std::cout << "device=" << properties.name
              << " arch=" << properties.gcnArchName
              << " wavefront=" << properties.warpSize << "\n";

    hipModule_t module = nullptr;
    error = hipModuleLoadData(&module, image.data());
    if (report("hipModuleLoadData", error) != 0) return 4;

    hipFunction_t function = nullptr;
    error = hipModuleGetFunction(&function, module, "p14_diag_hidden");
    if (report("hipModuleGetFunction", error) != 0) {
        hipModuleUnload(module);
        return 5;
    }

    constexpr size_t allocation = 4096;  // <= 4 KiB per Phase 14B
    void* output = nullptr;
    error = hipMalloc(&output, allocation);
    if (report("hipMalloc", error) != 0) {
        hipModuleUnload(module);
        return 6;
    }
    error = hipMemset(output, 0, allocation);
    if (report("hipMemset", error) != 0) {
        hipFree(output);
        hipModuleUnload(module);
        return 6;
    }

    ConvParams48 params{};
    params.p0 = reinterpret_cast<uintptr_t>(output);
    params.p1 = 0;
    params.p2 = 0;
    params.p3 = 0;
    params.p4 = 0;
    params.split_count = 0;
    void* kernel_params[] = {&params};

    std::cout << "launch_config=grid(1,1,1) block(256,1,1) shared=0\n";
    error = hipModuleLaunchKernel(function, 1, 1, 1, 256, 1, 1, 0, nullptr,
                                  kernel_params, nullptr);
    if (report("hipModuleLaunchKernel", error) != 0) {
        hipFree(output);
        hipModuleUnload(module);
        return 7;
    }
    error = hipGetLastError();
    if (report("hipGetLastError", error) != 0) {
        hipFree(output);
        hipModuleUnload(module);
        return 7;
    }

    auto t0 = std::chrono::steady_clock::now();
    error = hipDeviceSynchronize();
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "hipDeviceSynchronize_ms=" << ms << "\n";
    if (ms > 5000.0) {
        std::cout << "HANG_SUSPECTED elapsed_ms=" << ms
                  << " -- no further GPU work issued\n";
        return 90;  // do NOT issue further HIP calls
    }
    if (report("hipDeviceSynchronize", error) != 0) {
        hipFree(output);
        hipModuleUnload(module);
        return 8;
    }

    std::vector<uint32_t> host(allocation / 4, 0);
    error = hipMemcpy(host.data(), output, allocation, hipMemcpyDeviceToHost);
    if (report("hipMemcpy", error) != 0) {
        hipFree(output);
        hipModuleUnload(module);
        return 9;
    }

    const uint32_t expect[4] = {256u, 1u, 1u, 1u};
    bool match = true;
    for (int i = 0; i < 4; ++i) {
        std::cout << "out[" << i << "]=" << host[i]
                  << " expected=" << expect[i] << "\n";
        if (host[i] != expect[i]) match = false;
    }
    size_t tail_touched = 0;
    for (size_t i = 4; i < host.size(); ++i) {
        if (host[i] != 0) ++tail_touched;
    }
    std::cout << "tail_nonzero_dwords=" << tail_touched << "\n";
    if (tail_touched != 0) match = false;

    error = hipFree(output);
    if (report("hipFree", error) != 0) {
        hipModuleUnload(module);
        return 10;
    }
    error = hipModuleUnload(module);
    if (report("hipModuleUnload", error) != 0) return 11;

    if (!match) {
        std::cout << "SENTINEL_FAIL\n";
        return 12;
    }
    std::cout << "SENTINEL_PASS hidden_group_size_x=256 confirmed\n";
    std::cout << "process_exit=0\n";
    return 0;
}
