// Phase 14EI C2 — amdgcn-only ISA form checker (HOST-ONLY, never run on
// the GPU).  Compiled with -mcpu=gfx1030 and disassembled with
// llvm-objdump to verify the exact DS instruction forms used by Probe
// C2 before the real harness is assembled.  No HIP headers.
#define __global__ __attribute__((amdgpu_kernel))
#define __device__ __attribute__((device))

typedef unsigned int u32;
typedef unsigned long long u64;
// Ext-vector types: "v" constraint maps them to contiguous VGPR groups
// (v2 = VReg_64 pair, v4 = VReg_128 quad), which is what ds_read_b64 /
// ds_read_b128 / read2 need.
typedef u32 v2u __attribute__((ext_vector_type(2)));
typedef u32 v4u __attribute__((ext_vector_type(4)));

__device__ inline u32 c2_ds_read_b32(u32 a)
{
    u32 v;
    __asm__ volatile("ds_read_b32 %0, %1" : "=v"(v) : "v"(a) : "memory");
    return v;
}
__device__ inline u32 c2_ds_read_u16(u32 a)
{
    u32 v;
    __asm__ volatile("ds_read_u16 %0, %1" : "=v"(v) : "v"(a) : "memory");
    return v;
}
__device__ inline void c2_ds_read_b64(u32 a, u32* o0, u32* o1)
{
    v2u v;
    __asm__ volatile("ds_read_b64 %0, %1" : "=v"(v) : "v"(a) : "memory");
    o0[0] = v.x; o1[0] = v.y;
}
__device__ inline void c2_ds_read_b128(u32 a, u32* out4)
{
    v4u v;
    __asm__ volatile("ds_read_b128 %0, %1" : "=v"(v) : "v"(a) : "memory");
    out4[0] = v.x; out4[1] = v.y; out4[2] = v.z; out4[3] = v.w;
}
__device__ inline void c2_ds_read2_b32(u32 a, u32* o0, u32* o1)
{
    v2u v;
    __asm__ volatile("ds_read2_b32 %0, %1 offset0:0 offset1:1"
                     : "=v"(v) : "v"(a) : "memory");
    o0[0] = v.x; o1[0] = v.y;
}
__device__ inline void c2_ds_read2_b64(u32 a, u32* o0, u32* o1, u32* o2, u32* o3)
{
    v4u v;
    __asm__ volatile("ds_read2_b64 %0, %1 offset0:0 offset1:1"
                     : "=v"(v) : "v"(a) : "memory");
    o0[0] = v.x; o1[0] = v.y; o2[0] = v.z; o3[0] = v.w;
}
__device__ inline void c2_ds_write_b32(u32 a, u32 d)
{
    __asm__ volatile("ds_write_b32 %1, %0" : : "v"(d), "v"(a) : "memory");
}
__device__ inline void c2_ds_write_b16(u32 a, u32 d)
{
    __asm__ volatile("ds_write_b16 %1, %0" : : "v"(d), "v"(a) : "memory");
}
__device__ inline void c2_wait()
{
    __asm__ volatile("s_waitcnt lgkmcnt(0)" : : : "memory");
}

// Kernel touching every form so nothing is dead-code eliminated.  All
// lanes perform the same ops (value path irrelevant here — this file is
// only disassembled, never run).
__global__ void c2_form_check_kernel(u32* out)
{
    u32 a = out ? 0x80002400u : 0x2400u;   // high composite in the real kernel
    u32 r0 = c2_ds_read_b32(a);
    u32 r1 = c2_ds_read_u16(a);
    u32 b0, b1;
    c2_ds_read_b64(a, &b0, &b1);
    u32 r4[4];
    c2_ds_read_b128(a, r4);
    u32 s0 = 0, s1 = 0;
    c2_ds_read2_b32(a, &s0, &s1);
    u32 t0, t1, t2, t3;
    c2_ds_read2_b64(a, &t0, &t1, &t2, &t3);
    c2_ds_write_b32(0x100u, 0xC0000100u);
    c2_ds_write_b16(0x102u, 0xE102u);
    c2_wait();
    out[0] = r0 + r1 + b0 + b1 + r4[0] + r4[3] + s0 + s1 + t0 + t3;
}
