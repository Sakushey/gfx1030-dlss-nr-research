
// P9 probe: exercise every hidden-argument kind the module's metadata
// declares -- local/workgroup size, workgroup id, block/grid counts.
extern "C" __global__ void probe_hidden(int *out) {
  int gid = (int)__builtin_amdgcn_workgroup_id_x();
  int lid = (int)__builtin_amdgcn_workitem_id_x();
  int gsz = (int)__builtin_amdgcn_workgroup_size_x();
  out[gid] = lid + gsz;
}
