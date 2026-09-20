// Phase 14B static reference probe: stock HIP 6.4 clang-compiled gfx1030
// kernel, mirroring p14_diag_hidden's shape (single pointer arg, straight
// line, one global store, no LDS/barrier/WMMA). Compiled DEVICE-ONLY —
// never loaded, never launched, no GPU activity. Purpose: compare kernel
// descriptor + metadata-note conventions against the hand-authored
// diagnostic module (user-SGPR setup, kernarg register, code object
// version, resource fields).
#include <hip/hip_runtime.h>

#include <cstdint>

__global__ void ref_probe(uint64_t* out)
{
    uint64_t v = 0x1122334455667788ULL;
    out[0] = v;
}
