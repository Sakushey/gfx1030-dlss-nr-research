// Phase 14 entry-contract probe 2 host: ONE launch grid(2,1,1)
// block(64,1,1) = 2 waves; dumps 8 KiB back as hex.
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
        std::cerr << "usage: p14_entry_probe2_host.exe code_object\n";
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
    error = hipModuleGetFunction(&function, module, "p14_entry_probe2");
    if (error != hipSuccess) { std::cout << "getfn=" << error << "\n"; return 5; }

    constexpr size_t allocation = 8192;
    void* output = nullptr;
    if (hipMalloc(&output, allocation) != hipSuccess) return 6;
    if (hipMemset(output, 0, allocation) != hipSuccess) return 6;

    uint64_t ptr = reinterpret_cast<uintptr_t>(output);
    void* kernel_params[] = {&ptr};
    std::cout << "launch_config=grid(2,1,1) block(64,1,1)\n";
    error = hipModuleLaunchKernel(function, 2, 1, 1, 64, 1, 1, 0, nullptr,
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

    std::cout << "v-rows: out+(v0&63)*64 ; s-blocks at 0x1800 (wave0) / 0x1880 (wave1)\n";
    std::cout << "wave0 s0..s31:";
    for (int i = 0; i < 32; ++i) {
        if (i % 8 == 0) std::cout << "\n  s" << i << "..";
        std::printf(" %08X", host[0x1800 / 4 + i]);
    }
    std::cout << "\nwave1 s0..s31:";
    for (int i = 0; i < 32; ++i) {
        if (i % 8 == 0) std::cout << "\n  s" << i << "..";
        std::printf(" %08X", host[0x1880 / 4 + i]);
    }
    std::cout << "\nrow dump v0..v15 per lane (64 rows):\n";
    for (int r = 0; r < 64; ++r) {
        std::printf("row %2d:", r);
        for (int j = 0; j < 16; ++j) {
            std::printf(" %08X", host[(r * 16) + j]);
        }
        std::cout << "\n";
    }
    hipFree(output);
    hipModuleUnload(module);
    std::cout << "ENTRY_PROBE2_DONE process_exit=0\n";
    return 0;
}
