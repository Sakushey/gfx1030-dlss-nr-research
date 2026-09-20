// k_patC: LDS round-trip around one s_barrier, plus trailing global store.
// Dynamic LDS indexing via workitem-id so LLVM really emits ds_* ops.
// Cross-lane data dependency models a block-reduction step: ds_write by this
// lane must be visible to other lanes after the barrier.
typedef __attribute__((address_space(3))) float lds_float_t;

extern "C" __attribute__((amdgpu_kernel)) void k_patC(
    const float* __restrict g_in, float* __restrict g_out, int n) {
  lds_float_t* s = (lds_float_t*)0;
  unsigned tid = __builtin_amdgcn_workitem_id_x();
  float a = g_in[tid];
  s[tid] = a;
  __builtin_amdgcn_s_barrier();
  float b = s[(tid + 1) & 255];
  g_out[tid] = a + b;
}
