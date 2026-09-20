// k_patD: vector (VMEM) load into a VGPR crosses one s_barrier before use
// (tid-indexed so it stays a global_load_dword, vmcnt class), then a vector
// store after the barrier. This is the vmcnt analog of pattern A.
extern "C" __attribute__((amdgpu_kernel)) void k_patD(
    const float* __restrict g_in, float* __restrict g_out, int n) {
  unsigned tid = __builtin_amdgcn_workitem_id_x();
  float a = g_in[tid];
  __builtin_amdgcn_s_barrier();
  g_out[tid] = a;
}
