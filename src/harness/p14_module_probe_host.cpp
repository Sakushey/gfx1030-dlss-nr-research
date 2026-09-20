// Phase 14B isolation probe host: loads an arbitrary tiny module code
// object through the HIP 6.4 module API and performs EXACTLY ONE launch.
// Used with the stock-clang-built ref_probe kernel (no hidden args).
// Unlike the sentinel host, the hipDeviceSynchronize error code is always
// captured and printed even on the slow path.
#include <hip/hip_runtime.h>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static int report(const char* stage, hipError_t error)
{
    std::cout << stage << "=" << static_cast<int>(error)
              << " (" << hipGetErrorString(error) << ")\n";
    return error == hipSuccess ? 0 : 1;
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "usage: p14_module_probe_host.exe code_object fn_name\n";
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
    hipDeviceProp_t properties{};
    error = hipGetDeviceProperties(&properties, 0);
    if (report("hipGetDeviceProperties", error) != 0) return 3;
    std::cout << "device=" << properties.name
              << " arch=" << properties.gcnArchName
              << " wavefront=" << properties.warpSize << "\n";

    hipModule_t module = nullptr;
    error = hipModuleLoadData(&module, image.data());
    if (report("hipModuleLoadData", error) != 0) return 4;

    hipFunction_t function = nullptr;
    error = hipModuleGetFunction(&function, module, argv[2]);
    if (report("hipModuleGetFunction", error) != 0) {
        hipModuleUnload(module);
        return 5;
    }

    constexpr size_t allocation = 4096;
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

    uint64_t ptr = reinterpret_cast<uintptr_t>(output);
    void* kernel_params[] = {&ptr};

    std::cout << "launch_config=grid(1,1,1) block(64,1,1) shared=0\n";
    error = hipModuleLaunchKernel(function, 1, 1, 1, 64, 1, 1, 0, nullptr,
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
    hipError_t sync_error = hipDeviceSynchronize();
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "hipDeviceSynchronize_ms=" << ms << "\n";
    std::cout << "hipDeviceSynchronize_code=" << static_cast<int>(sync_error)
              << " (" << hipGetErrorString(sync_error) << ")\n";
    if (ms > 5000.0) {
        std::cout << "HANG_SUSPECTED elapsed_ms=" << ms
                  << " -- no further GPU work issued\n";
        return 90;
    }
    if (sync_error != hipSuccess) {
        hipFree(output);
        hipModuleUnload(module);
        return 8;
    }

    std::vector<uint64_t> host(allocation / 8, 0);
    error = hipMemcpy(host.data(), output, allocation, hipMemcpyDeviceToHost);
    if (report("hipMemcpy", error) != 0) {
        hipFree(output);
        hipModuleUnload(module);
        return 9;
    }
    std::cout << "out[0]=0x" << std::hex << host[0] << std::dec << "\n";
    std::cout << "out[1]=" << host[1] << "\n";
    size_t tail = 0;
    for (size_t i = 2; i < host.size(); ++i) {
        if (host[i] != 0) ++tail;
    }
    std::cout << "tail_nonzero_dwords=" << tail << "\n";

    error = hipFree(output);
    if (report("hipFree", error) != 0) {
        hipModuleUnload(module);
        return 10;
    }
    error = hipModuleUnload(module);
    if (report("hipModuleUnload", error) != 0) return 11;

    std::cout << "MODULE_PROBE_DONE process_exit=0\n";
    return 0;
}
