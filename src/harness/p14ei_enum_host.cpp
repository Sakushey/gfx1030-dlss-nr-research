// Phase 14EI — post-reboot preflight: HIP6 DEVICE ENUMERATION ONLY.
// NO kernel source, NO launch, NO module load.  Per phase plan §3 the
// first executable after the reboot gate performs enumeration only.
#include <hip/hip_runtime.h>

#include <cstdio>

static const char* ok(hipError_t e) { return e == hipSuccess ? "ok" : hipGetErrorString(e); }

int main()
{
    int nDev = 0;
    hipError_t e = hipInit(0);
    std::printf("hipInit           : %s\n", ok(e));
    e = hipGetDeviceCount(&nDev);
    std::printf("hipGetDeviceCount : %s -> %d\n", ok(e), nDev);

    for (int d = 0; d < nDev; ++d) {
        hipDeviceProp_t p;
        hipError_t pe = hipGetDeviceProperties(&p, d);
        std::printf("--- device %d ---\n", d);
        if (pe != hipSuccess) {
            std::printf("hipGetDeviceProperties: %s\n", hipGetErrorString(pe));
            continue;
        }
        std::printf("name              : %s\n", p.name);
        std::printf("gcnArchName       : %s\n", p.gcnArchName);
        std::printf("warpSize          : %u (wave32 expected on gfx1030)\n", p.warpSize);
        std::printf("sharedMemPerBlock : %zu\n", (size_t)p.sharedMemPerBlock);
        std::printf("maxThreadsPerBlock: %d\n", p.maxThreadsPerBlock);
        std::printf("totalConstMem     : %zu\n", (size_t)p.totalConstMem);
        std::printf("regsPerBlock      : %d\n", p.regsPerBlock);
        std::printf("clockRate         : %d kHz\n", p.clockRate);
        std::printf("major.minor       : %d.%d\n", p.major, p.minor);
        std::printf("cooperativeLaunch : %d\n", p.cooperativeLaunch);
        std::printf("persistingL2CacheMaxSize: %zu\n", (size_t)p.persistingL2CacheMaxSize);
    }

    // No further HIP calls of any kind.
    std::printf("ENUM_DONE (no kernel launched)\n");
    return 0;
}
