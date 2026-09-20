// k_patB: runtime-trip loop (i < n) with two s_barrier per iteration:
// register-loaded global load -> s_barrier -> global store -> s_barrier.
// Mirrors a software-pipeline / SWIN-style inner loop where global memory
// traffic surrounds each barrier.
extern "C" __attribute__((amdgpu_kernel)) void k_patB(
    const float* __restrict g_in, float* __restrict g_out, int n) {
  for (int i = 0; i < n; ++i) {
    float x = g_in[i];
    __builtin_amdgcn_s_barrier();
    g_out[i] = x;
    __builtin_amdgcn_s_barrier();
  }
}
