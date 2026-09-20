// k_patA: straight-line; one s_barrier between a global load pair (into
// registers) and a global store that consumes those registers.
// Compiled for gfx1030 and gfx1100 with stock clang++ (no HIP headers).
extern "C" __attribute__((amdgpu_kernel)) void k_patA(
    const float* __restrict g_in, float* __restrict g_out, int n) {
  float a = g_in[0];
  float b = g_in[1];
  __builtin_amdgcn_s_barrier();
  g_out[0] = a + b;
}
