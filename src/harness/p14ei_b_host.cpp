// Phase 14EI Probe B — EIGHT-WAVE SOFT-WMMA.
// Authorized (phase plan §13): ONLY if Probe A passes. ONE dispatch.
// Goal: prove the exact validated RDNA2 soft-WMMA implementation
// (soft_wmma_fragment_no_lds, phase 7C: per logical WMMA 64 x
// ds_bpermute_b32 + 64 x v_dot2c_f32_f16, zero barriers, zero LDS)
// works physically with 8 simultaneous wave32 waves at SWIN-like
// arithmetic density:
//   grid(1,1,1), block(256,1,1) = 8 waves
//   each wave: 18 successive chained soft-WMMA fragments
//   (18*64 = 1,152 bpermute + 1,152 dot2 per wave == SWIN module scale)
// NO barriers, NO ordinary LDS, NO global traffic beyond the input
// arrays and a compact per-lane checksum.  Deterministic inputs are
// exactly representable in FP16 and make every FP32 product/sum exact,
// so the CPU mirror must match bit-exactly (max abs error == 0).
#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

typedef unsigned int u32;
typedef _Float16 half2v __attribute__((ext_vector_type(2)));

union HalfBits {
    uint16_t bits;
    _Float16 value;
};

__device__ __forceinline__
_Float16 half_from_bits(uint16_t bits)
{
    HalfBits h{};
    h.bits = bits;
    return h.value;
}

__device__ __forceinline__
float rdna2_dot2_half_bits(u32 a, u32 b, float acc)
{
    half2v av = {half_from_bits(static_cast<uint16_t>(a & 0xffffu)),
                 half_from_bits(static_cast<uint16_t>(a >> 16))};
    half2v bv = {half_from_bits(static_cast<uint16_t>(b & 0xffffu)),
                 half_from_bits(static_cast<uint16_t>(b >> 16))};
    return __builtin_amdgcn_fdot2(av, bv, acc, false);
}

// VALIDATED phase-7C fragment (bit-identical source shape): A lane
// source = 2*r + parity (row ownership), B column-owned by the lane,
// D lanes own alternating rows; __shfl lowers to ds_bpermute_b32 on
// gfx1030 (validated: 64 ds_bpermute + 64 v_dot2c per fragment).
__device__ __forceinline__
void soft_wmma_fragment_no_lds(const u32 A[8],
                               const u32 B[8],
                               const float C[8],
                               float D[8])
{
    const int lane = static_cast<int>(threadIdx.x) & 31;
    const int output_parity = lane >= 16 ? 1 : 0;
    #pragma unroll
    for (int r = 0; r < 8; ++r) {
        const int a_source_lane = 2 * r + output_parity;
        float acc = C[r];
        #pragma unroll
        for (int k = 0; k < 16; k += 2) {
            const u32 a = __shfl(A[k / 2], a_source_lane, 32);
            const u32 b = B[k / 2];
            acc = rdna2_dot2_half_bits(a, b, acc);
        }
        D[r] = acc;
    }
}

constexpr u32 kWaves = 8, kLanes = 32, kSteps = 18, kR = 8;

// inA/inB: [wave][step][lane][8] packed fp16 pairs (u32 each).
// seedC:   [wave][lane][8] fp32 exact dyadic seeds.
// out:     per (wave,lane): float sumD + u32 xorBits.
__global__ void b_probe_kernel(const u32* __restrict__ inA,
                               const u32* __restrict__ inB,
                               const float* __restrict__ seedC,
                               float* __restrict__ outF,
                               u32* __restrict__ outX)
{
    const int tid = threadIdx.x;
    const int wave = tid >> 5;
    const int lane = tid & 31;

    u32 a[8], b[8];
    float c[8], d[8];
    const u32 baseW = (u32)(wave * kSteps);

    #pragma unroll
    for (int r = 0; r < kR; ++r) {
        c[r] = seedC[(wave * kLanes + lane) * kR + r];
    }

    #pragma unroll
    for (int s = 0; s < kSteps; ++s) {
        const u32 base = ((baseW + (u32)s) * kLanes + (u32)lane) * kR;
        #pragma unroll
        for (int r = 0; r < kR; ++r) {
            a[r] = inA[base + (u32)r];
            b[r] = inB[base + (u32)r];
        }
        soft_wmma_fragment_no_lds(a, b, c, d);
        #pragma unroll
        for (int r = 0; r < kR; ++r) c[r] = d[r];   // D -> C carry chain
    }

    float sumD = 0.0f;
    u32 xr = 0;
    #pragma unroll
    for (int r = 0; r < kR; ++r) {
        sumD += d[r];
        u32 bits;
        static_assert(sizeof(float) == sizeof(u32), "fp32 == u32");
        __builtin_memcpy(&bits, &d[r], 4);
        xr ^= bits;
    }
    outF[(wave * kLanes + lane)] = sumD;
    outX[(wave * kLanes + lane)] = xr;
}

// ---------------------------------------------------------------------------
static int failures = 0;
#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) printf("PASS: %s\n", what);                               \
        else { printf("FAIL: %s\n", what); ++failures; }                    \
    } while (0)

static u32 lcg(u32& s)
{
    s = s * 1103515245u + 12345u;
    return s;
}

static uint16_t half_bits_of(int v)
{
    // v in [-15,15]; integers are exact in fp16 (<= 2048).  fp16 normal
    // form: value = 1.mant * 2^(e-15), e = 15 + floor(log2|v|).
    uint16_t sign = v < 0 ? 0x8000u : 0;
    int mag = v < 0 ? -v : v;
    if (mag == 0) return sign;
    int e2 = 0;
    for (int m = mag; m > 1; m >>= 1) ++e2;          // floor(log2 mag)
    int mant = ((mag << 10) >> e2) - 1024;           // exact for mag<=15
    return (uint16_t)(sign | ((uint16_t)(15 + e2) << 10) | (uint16_t)mant);
}

static float unpack_f16(uint16_t b)
{
    HalfBits h{};
    h.bits = b;
    return (float)h.value;
}

int main()
{
    hipDeviceProp_t prop;
    CHECK(hipSetDevice(0) == hipSuccess, "hipSetDevice(0)");
    CHECK(hipGetDeviceProperties(&prop, 0) == hipSuccess, "device props");
    printf("device: %s  gcnArchName=%s  warpSize=%u\n", prop.name,
           prop.gcnArchName, prop.warpSize);

    const size_t kA = (size_t)kWaves * kSteps * kLanes * kR;
    std::vector<u32> A(kA), B(kA);
    std::vector<float> C((size_t)kWaves * kLanes * kR);

    u32 rng = 0x51C0FFEEu;
    for (u32 w = 0; w < kWaves; ++w) {
        for (u32 s = 0; s < kSteps; ++s) {
            for (u32 l = 0; l < kLanes; ++l) {
                for (u32 r = 0; r < kR; ++r) {
                    size_t i = ((size_t)w * kSteps + s) * kLanes * kR +
                               (size_t)l * kR + r;
                    int va = (int)(lcg(rng) % 31u) - 15;
                    int vb = (int)(lcg(rng) % 31u) - 15;
                    int va2 = (int)(lcg(rng) % 31u) - 15;
                    int vb2 = (int)(lcg(rng) % 31u) - 15;
                    A[i] = (u32)half_bits_of(va) |
                           ((u32)half_bits_of(va2) << 16);
                    B[i] = (u32)half_bits_of(vb) |
                           ((u32)half_bits_of(vb2) << 16);
                }
            }
        }
    }
    for (u32 w = 0; w < kWaves; ++w)
        for (u32 l = 0; l < kLanes; ++l)
            for (u32 r = 0; r < kR; ++r)
                C[((size_t)w * kLanes + l) * kR + r] =
                    (float)((int)(lcg(rng) % 33u) - 16) / 16.0f;

    // CPU mirror of the fragment procedure (same lane/source rule):
    // for lane l, r: A rows from source lane 2r+(l>=16); B own lane.
    std::vector<float> refSum(kWaves * kLanes, 0.0f);
    std::vector<u32> refXor(kWaves * kLanes, 0u);
    for (u32 w = 0; w < kWaves; ++w) {
        for (u32 l = 0; l < kLanes; ++l) {
            float c[8], d[8];
            for (int r = 0; r < 8; ++r)
                c[r] = C[((size_t)w * kLanes + l) * kR + r];
            int parity = l >= 16 ? 1 : 0;
            for (u32 s = 0; s < kSteps; ++s) {
                size_t sbase =
                    ((size_t)w * kSteps + s) * kLanes * kR;
                // B: this lane's own 8 packed column registers.
                u32 b8[8];
                for (int r = 0; r < 8; ++r) b8[r] = B[sbase + (size_t)l * kR + r];
                // A rows of the SOURCE lanes 0..15 (the lanes the shfl
                // gathers from: 2r+parity).  GPU shuffles A[j] of lane sl.
                u32 aRows[16][8];
                for (int sl = 0; sl < 16; ++sl)
                    for (int j = 0; j < 8; ++j)
                        aRows[sl][j] = A[sbase + (size_t)sl * kR + j];
                for (int r = 0; r < 8; ++r) {
                    int sl = 2 * r + parity;
                    float acc = c[r];
                    for (int j = 0; j < 8; ++j) {
                        float a0 = unpack_f16((uint16_t)(aRows[sl][j] & 0xffffu));
                        float a1 = unpack_f16((uint16_t)(aRows[sl][j] >> 16));
                        float b0 = unpack_f16((uint16_t)(b8[j] & 0xffffu));
                        float b1 = unpack_f16((uint16_t)(b8[j] >> 16));
                        acc += a0 * b0 + a1 * b1;
                    }
                    d[r] = acc;
                }
                for (int r = 0; r < 8; ++r) c[r] = d[r];
            }
            float sum = 0.0f;
            u32 xr = 0;
            for (int r = 0; r < 8; ++r) {
                sum += d[r];
                u32 bits;
                __builtin_memcpy(&bits, &d[r], 4);
                xr ^= bits;
            }
            refSum[w * kLanes + l] = sum;
            refXor[w * kLanes + l] = xr;
        }
    }

    const size_t kOutBytes = kWaves * kLanes * sizeof(float);
    const size_t kGuard = 0x1000;
    const size_t kBuf = kGuard + kOutBytes + kGuard;

    u32 *dA = nullptr, *dB = nullptr, *dX = nullptr;
    float *dC = nullptr, *dF = nullptr;
    CHECK(hipMalloc((void**)&dA, A.size() * sizeof(u32)) == hipSuccess,
          "hipMalloc A");
    CHECK(hipMalloc((void**)&dB, B.size() * sizeof(u32)) == hipSuccess,
          "hipMalloc B");
    CHECK(hipMalloc((void**)&dC, C.size() * sizeof(float)) == hipSuccess,
          "hipMalloc C");
    CHECK(hipMalloc((void**)&dF, kBuf) == hipSuccess, "hipMalloc F(guarded)");
    CHECK(hipMalloc((void**)&dX, kBuf) == hipSuccess, "hipMalloc X(guarded)");
    CHECK(hipMemcpy(dA, A.data(), A.size() * sizeof(u32),
                    hipMemcpyHostToDevice) == hipSuccess, "copy A");
    CHECK(hipMemcpy(dB, B.data(), B.size() * sizeof(u32),
                    hipMemcpyHostToDevice) == hipSuccess, "copy B");
    CHECK(hipMemcpy(dC, C.data(), C.size() * sizeof(float),
                    hipMemcpyHostToDevice) == hipSuccess, "copy C");
    CHECK(hipMemset(dF, 0x5A, kGuard) == hipSuccess, "F guard1");
    CHECK(hipMemset((uint8_t*)dF + kGuard, 0, kOutBytes) == hipSuccess,
          "F payload");
    CHECK(hipMemset((uint8_t*)dF + kGuard + kOutBytes, 0x5A, kGuard)
              == hipSuccess, "F guard2");
    CHECK(hipMemset(dX, 0x5A, kGuard) == hipSuccess, "X guard1");
    CHECK(hipMemset((uint8_t*)dX + kGuard, 0, kOutBytes) == hipSuccess,
          "X payload");
    CHECK(hipMemset((uint8_t*)dX + kGuard + kOutBytes, 0x5A, kGuard)
              == hipSuccess, "X guard2");

    auto t0 = std::chrono::steady_clock::now();
    hipLaunchKernelGGL(b_probe_kernel, dim3(1), dim3(256), 0u, 0,
                       dA, dB, dC, (float*)((uint8_t*)dF + kGuard),
                       (u32*)((uint8_t*)dX + kGuard));
    CHECK(hipGetLastError() == hipSuccess, "launch");
    hipError_t se = hipDeviceSynchronize();
    double ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();
    CHECK(se == hipSuccess, "sync");
    printf("SYNC_ELAPSED_MS=%.3f (5 s boundary; HANG if beyond)\n", ms);
    CHECK(ms < 5000.0, "completion under the 5-s hang boundary");

    std::vector<uint8_t> hF(kBuf), hX(kBuf);
    std::vector<float> gotF(kWaves * kLanes);
    std::vector<u32> gotX(kWaves * kLanes);
    CHECK(hipMemcpy(hF.data(), dF, kBuf, hipMemcpyDeviceToHost)
              == hipSuccess, "copy F");
    CHECK(hipMemcpy(hX.data(), dX, kBuf, hipMemcpyDeviceToHost)
              == hipSuccess, "copy X");
    size_t cF = 0, cX = 0;
    for (size_t i = 0; i < kGuard; ++i) {
        cF += (hF[i] != 0x5A) + (hF[kGuard + kOutBytes + i] != 0x5A);
        cX += (hX[i] != 0x5A) + (hX[kGuard + kOutBytes + i] != 0x5A);
    }
    CHECK(cF == 0 && cX == 0, "output guard canaries intact");
    __builtin_memcpy(gotF.data(), hF.data() + kGuard, kOutBytes);
    __builtin_memcpy(gotX.data(), hX.data() + kGuard, kOutBytes);

    double maxAbs = 0.0, maxRel = 0.0;
    u32 xorBad = 0, sumBad = 0;
    int worst = -1;
    for (u32 i = 0; i < kWaves * kLanes; ++i) {
        double e = std::abs((double)gotF[i] - (double)refSum[i]);
        if (e > maxAbs) { maxAbs = e; worst = (int)i; }
        double denom = std::abs((double)refSum[i]);
        if (denom > 1e-30) {
            double re = e / denom;
            if (re > maxRel) maxRel = re;
        }
        if (gotF[i] != refSum[i]) ++sumBad;
        if (gotX[i] != refXor[i]) ++xorBad;
    }
    printf("max_abs_diff=%.9g max_rel_diff=%.9g  sum_mismatch=%u/256 "
           "xor_mismatch=%u/256\n", maxAbs, maxRel, sumBad, xorBad);
    if (worst >= 0)
        printf("worst lane idx %d: GPU=%.9g CPU=%.9g\n", worst,
               gotF[worst], refSum[worst]);
    CHECK(sumBad == 0 && xorBad == 0, "all 8 waves x 32 lanes: exact match "
          "(18 chained soft-WMMA fragments each)");
    if (sumBad == 0 && xorBad == 0)
        printf("B_VERDICT: PASS — 8-wave soft-WMMA is physically PROVEN "
               "(8 simultaneous wave32 waves, 18 chained fragments/wave, "
               "1,152 ds_bpermute + 1,152 v_dot2c per wave, no barriers)\n");
    else
        printf("B_VERDICT: FAIL\n");

    hipFree(dA); hipFree(dB); hipFree(dC); hipFree(dF); hipFree(dX);
    printf("EXIT failures=%d\n", failures);
    return failures ? 1 : 0;
}
