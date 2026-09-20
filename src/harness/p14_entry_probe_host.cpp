// Phase 14 entry-contract probe host. ONE launch, block(32,1,1),
// grid(1,1,1). Dumps the whole 4 KiB output buffer back as hex dwords.
#include <hip/hip_runtime.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <vector>

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "usage: p14_entry_probe_host.exe code_object\n";
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<char> image((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
    hipError_t error = hipInit(0);
    if (error != hipSuccess) { std::cout << "hipInit=" << error << "\n"; return 3; }
    hipDeviceProp_t properties{};
    hipGetDeviceProperties(&properties, 0);
    std::cout << "device=" << properties.name << " arch=" << properties.gcnArchName << "\n";

    hipModule_t module = nullptr;
    error = hipModuleLoadData(&module, image.data());
    if (error != hipSuccess) { std::cout << "load=" << error << "\n"; return 4; }
    hipFunction_t function = nullptr;
    error = hipModuleGetFunction(&function, module, "p14_entry_probe");
    if (error != hipSuccess) { std::cout << "getfn=" << error << "\n"; return 5; }

    constexpr size_t allocation = 4096;
    void* output = nullptr;
    if (hipMalloc(&output, allocation) != hipSuccess) return 6;
    if (hipMemset(output, 0, allocation) != hipSuccess) return 6;

    uint64_t ptr = reinterpret_cast<uintptr_t>(output);
    void* kernel_params[] = {&ptr};
    std::cout << "launch_config=grid(1,1,1) block(32,1,1)\n";
    error = hipModuleLaunchKernel(function, 1, 1, 1, 32, 1, 1, 0, nullptr,
                                  kernel_params, nullptr);
    if (error != hipSuccess) { std::cout << "launch=" << error << "\n"; return 7; }
    error = hipGetLastError();
    if (error != hipSuccess) { std::cout << "last=" << error << "\n"; return 7; }

    auto t0 = std::chrono::steady_clock::now();
    hipError_t sync = hipDeviceSynchronize();
    auto t1 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "sync_ms=" << ms << " sync_code=" << static_cast<int>(sync) << "\n";
    if (ms > 5000.0 || sync != hipSuccess) {
        std::cout << "ABNORMAL_SYNC -- no further GPU work\n";
        return 90;
    }
    std::vector<uint32_t> host(allocation / 4, 0);
    error = hipMemcpy(host.data(), output, allocation, hipMemcpyDeviceToHost);
    if (error != hipSuccess) { std::cout << "memcpy=" << error << "\n"; return 8; }

    std::cout << "row_layout: v-rows out+(v0&31)*64 ; s-block out+0x800\n";
    std::cout << "s0..s31 (dwords at 0x800):";
    for (int i = 0; i < 32; ++i) {
        if (i % 8 == 0) std::cout << "\n  s" << i << "..s" << (i + 7 > 31 ? 31 : i + 7) << ":";
        std::printf(" %08X", host[0x800 / 4 + i]);
    }
    std::cout << "\nrow dump (row=16 dwords, 32 rows, 64 B each):\n";
    for (int r = 0; r < 32; ++r) {
        std::printf("row %2d:", r);
        for (int j = 0; j < 16; ++j) {
            std::printf(" %08X", host[(r * 16) + j]);
        }
        std::cout << "\n";
    }
    hipFree(output);
    hipModuleUnload(module);
    std::cout << "ENTRY_PROBE_DONE process_exit=0\n";
    return 0;
}
