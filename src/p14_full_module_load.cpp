// Phase 14C: full gfx1030 module load + symbol resolution ONLY.
// Loads the canonical translated module through the HIP 6.4 module API,
// resolves every kernel symbol from a list file, then unloads.
// NO kernel launch of any kind.
#include <hip/hip_runtime.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static std::vector<std::string> read_lines(const char* path)
{
    std::vector<std::string> out;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
            line.pop_back();
        }
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::cerr << "usage: p14_full_module_load.exe module.co symbols.txt [helper_symbol]\n";
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        std::cerr << "cannot open module: " << argv[1] << "\n";
        return 2;
    }
    std::vector<char> image((std::istreambuf_iterator<char>(input)),
                            std::istreambuf_iterator<char>());
    std::vector<std::string> names = read_lines(argv[2]);
    std::cout << "module_bytes=" << image.size() << " symbols=" << names.size() << "\n";

    hipError_t error = hipInit(0);
    if (error != hipSuccess) {
        std::cout << "hipInit=" << error << "\n";
        return 3;
    }
    hipDeviceProp_t properties{};
    error = hipGetDeviceProperties(&properties, 0);
    if (error != hipSuccess) {
        std::cout << "hipGetDeviceProperties=" << error << "\n";
        return 3;
    }
    std::cout << "device=" << properties.name << " arch=" << properties.gcnArchName << "\n";

    auto t0 = std::chrono::steady_clock::now();
    hipModule_t module = nullptr;
    error = hipModuleLoadData(&module, image.data());
    auto t1 = std::chrono::steady_clock::now();
    double load_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << "hipModuleLoadData=" << error << " ms=" << load_ms << "\n";
    if (error != hipSuccess) return 4;

    int ok = 0;
    for (const std::string& name : names) {
        hipFunction_t function = nullptr;
        error = hipModuleGetFunction(&function, module, name.c_str());
        if (error == hipSuccess) ++ok;
        std::cout << "resolve " << name << "=" << error << "\n";
    }
    std::cout << "resolved=" << ok << "/" << names.size() << "\n";

    if (argc >= 4) {
        hipFunction_t function = nullptr;
        error = hipModuleGetFunction(&function, module, argv[3]);
        std::cout << "resolve helper " << argv[3] << "=" << error << "\n";
    }

    auto t2 = std::chrono::steady_clock::now();
    error = hipModuleUnload(module);
    auto t3 = std::chrono::steady_clock::now();
    std::cout << "hipModuleUnload=" << error
              << " ms=" << std::chrono::duration<double, std::milli>(t3 - t2).count()
              << "\n";
    if (error != hipSuccess) return 5;
    if (ok != static_cast<int>(names.size())) {
        std::cout << "SYMBOL_RESOLUTION_FAIL\n";
        return 6;
    }
    std::cout << "FULL_MODULE_LOAD_PASS process_exit=0\n";
    return 0;
}
