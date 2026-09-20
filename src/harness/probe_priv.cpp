
// P10 probe: force genuine private-segment use.
//  (a) a private array that cannot be promoted to registers, and
//  (b) enough live state to force spilling.
extern "C" __global__ void probe_priv(int *out, int n) {
  float acc[32];
  #pragma unroll
  for (int i = 0; i < 32; ++i) acc[i] = (float)(i + n);
  #pragma unroll
  for (int r = 0; r < 8; ++r)
    #pragma unroll
    for (int i = 0; i < 32; ++i) acc[i] = acc[i] * 1.0001f + (float)r;
  float s = 0.f;
  #pragma unroll
  for (int i = 0; i < 32; ++i) s += acc[i];
  out[__builtin_amdgcn_workitem_id_x()] = (int)s;
}
