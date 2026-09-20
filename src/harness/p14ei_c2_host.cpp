// Phase 14EI Probe C2 — HIGH-BIT LDS ADDRESS SEMANTICS on gfx1030.
// Authorized (phase plan §6): ONE launch, tiny diagnostic, ONE wave
// (grid 1 x block 32), FULL 64-KiB group segment request, no barriers,
// no data-dependent loops, no bpermute, no WMMA, no global traffic
// except a tiny result buffer.  Reads through high-composite addresses
// only; NO writes through them.
//
// Question: when ds_read* uses ADDR with high bits set (e.g. 0x80002400)
// while LDS[0x2400] holds a sentinel, does gfx1030 return the sentinel
// (LOW16_ALIAS), zero (OOB_ZERO), or something else?
//
// Build: p14ei_build.ps1 -Source p14ei_c2_host.cpp (clang HIP, gfx1030).
#include <hip/hip_runtime.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

// ---------------------------------------------------------------------------
// Device-side asm helpers (forms verified by p14ei_c2_isa_check.cc objdump:
// ds_read_b32/u16/b64/b128/read2_b64 + s_waitcnt lgkmcnt(0); none of the
// read2_b32 experiments are used in this probe).
// ---------------------------------------------------------------------------
typedef unsigned int u32;
typedef unsigned long long u64;
typedef u32 v2u __attribute__((ext_vector_type(2)));
typedef u32 v4u __attribute__((ext_vector_type(4)));

__device__ __forceinline__ u32 c2_ld_b32(u32 a)
{
    u32 v;
    __asm__ volatile("ds_read_b32 %0, %1" : "=v"(v) : "v"(a) : "memory");
    return v;
}
__device__ __forceinline__ u32 c2_ld_u16(u32 a)
{
    u32 v;
    __asm__ volatile("ds_read_u16 %0, %1" : "=v"(v) : "v"(a) : "memory");
    return v;
}
__device__ __forceinline__ void c2_ld_b64(u32 a, u32* d0, u32* d1)
{
    v2u v;
    __asm__ volatile("ds_read_b64 %0, %1" : "=v"(v) : "v"(a) : "memory");
    d0[0] = v.x; d1[0] = v.y;
}
__device__ __forceinline__ void c2_ld_b128(u32 a, u32* o)
{
    v4u v;
    __asm__ volatile("ds_read_b128 %0, %1" : "=v"(v) : "v"(a) : "memory");
    o[0] = v.x; o[1] = v.y; o[2] = v.z; o[3] = v.w;
}
__device__ __forceinline__ void c2_ld_read2_b64(u32 a, u32* o)
{
    // offset0:0 offset1:1  ->  [a, a+8) and [a+8, a+16)  (units of 8 B)
    v4u v;
    __asm__ volatile("ds_read2_b64 %0, %1 offset0:0 offset1:1"
                     : "=v"(v) : "v"(a) : "memory");
    o[0] = v.x; o[1] = v.y; o[2] = v.z; o[3] = v.w;
}
__device__ __forceinline__ void c2_st_b32(u32 a, u32 d)
{
    __asm__ volatile("ds_write_b32 %1, %0" : : "v"(d), "v"(a) : "memory");
}
__device__ __forceinline__ void c2_wait_lds()
{
    __asm__ volatile("s_waitcnt lgkmcnt(0)" : : : "memory");
}

// ---------------------------------------------------------------------------
// Probe table (compile-time constant; identical on the host below).
// form: 0=b32(1 dw) 1=u16(1 dw) 2=b64(2 dw) 3=b128(4 dw) 4=read2_b64(4 dw)
// ---------------------------------------------------------------------------
struct Group { u32 form; u32 high; };

// Sentinel plan.  "std" dword slots get S(dw) = 0xC0000000 | dw.
// Standalone u16 windows (byte addr a, in the HIGH half of dw base b=a-2)
// get S(b) = (exp16 << 16) | 0x5AA5 with exp16 = 0x8000 | a.
static constexpr u32 kStdSlots[] = {
    0x0000, 0x0020, 0x0024, 0x0028, 0x0068, 0x00F0, 0x0100, 0x0178,
    0x0200, 0x0288, 0x0310, 0x0398, 0x2200, 0x2400, 0x2404, 0x2408,
    0x240C, 0x2838, 0x3E00, 0x7C00, 0xFF00
};
static constexpr u32 kU16Base[] = { 0x002C, 0x003C, 0x243C };   // dw bases
static constexpr u32 kU16Exp16(u32 b) { return 0x8000u | (b + 2u); }
static constexpr u32 kStdSent(u32 dw) { return 0xC0000000u | dw; }
static constexpr u32 kU16Sent(u32 b)
{
    return (kU16Exp16(b) << 16) | 0x5AA5u;
}

static constexpr u32 kNGroups = 62;
static constexpr Group kGroups[kNGroups] = {
    // ---- baseline groups 0..26 (low addresses only) ----
    {0, 0x00000000}, {0, 0x00000020}, {0, 0x00000024}, {0, 0x00000028},
    {0, 0x00000068}, {0, 0x000000F0}, {0, 0x00000100}, {0, 0x00000178},
    {0, 0x00000200}, {0, 0x00000288}, {0, 0x00000310}, {0, 0x00000398},
    {0, 0x00002200}, {0, 0x00002400}, {0, 0x00002404}, {0, 0x00002408},
    {0, 0x0000240C}, {0, 0x00002838}, {0, 0x00003E00}, {0, 0x00007C00},
    {0, 0x0000FF00},
    {1, 0x0000002E}, {1, 0x0000003E}, {1, 0x0000243E},          // u16 windows
    {2, 0x00002400},                                             // b64 @0x2400
    {3, 0x00002400},                                             // b128 @0x2400
    {4, 0x00002400},                                             // read2_b64
    // ---- high-composite groups 27..61 ----
    // b32 @ observed/representative high addresses (low16 in brackets)
    {0, 0x00010000}, {0, 0x00010068}, {0, 0x000100F0}, {0, 0x00010100},
    {0, 0x00010178}, {0, 0x00010200}, {0, 0x00010288}, {0, 0x00010310},
    {0, 0x00010398}, {0, 0x00012200}, {0, 0x00012400}, {0, 0x00012838},
    {0, 0x00022200}, {0, 0x00022400}, {0, 0x000A0020}, {0, 0x000A0028},
    {0, 0x00280020}, {0, 0x00280024}, {0, 0x00280028}, {0, 0x7FFF2400},
    {0, 0x80002400}, {0, 0x80003E00}, {0, 0x80007C00}, {0, 0x8000FF00},
    // u16 @ high composites
    {1, 0x000A002A}, {1, 0x0028002E}, {1, 0x0001243E}, {1, 0x14003E},
    {1, 0x50003E},  {1, 0x80002400},
    // wide forms @ high composites (start dword 0x2400 both)
    {2, 0x00012400}, {2, 0x80002400},                            // b64
    {3, 0x00012400}, {3, 0x80002400},                            // b128
    {4, 0x80002400},                                             // read2_b64
};

static constexpr u32 c2_width(u32 f)
{
    return f == 0 || f == 1 ? 1 : (f == 2 ? 2 : 4);
}
template <u32 G> __device__ __forceinline__ u32 c2_out_ofs()
{
    // Offset of group G's output dwords inside the result stream.
    u32 s = 0;
    for (u32 i = 0; i < G; ++i) s += c2_width(kGroups[i].form);
    return s;
}
// Compile-time fold executes every group once, straight-line.
// ORDER MATTERS: the ds read must be fully drained (s_waitcnt) BEFORE the
// C++ global stores consume the registers; storing first races the LDS
// latency and captures stale register contents (observed 2026-09-07).
template <u32 G> __device__ __forceinline__ void c2_exec_group(u32* o)
{
    constexpr Group g = kGroups[G];
    u32 a = g.high;
    u32 t[4];
    switch (g.form) {
        case 0: t[0] = c2_ld_b32(a); break;
        case 1: t[0] = c2_ld_u16(a); break;
        case 2: c2_ld_b64(a, &t[0], &t[1]); break;
        case 3: c2_ld_b128(a, t); break;
        case 4: c2_ld_read2_b64(a, t); break;
    }
    c2_wait_lds();                 // drain before any store
    for (u32 s = 0; s < c2_width(g.form); ++s) o[s] = t[s];
}
template <u32... Gs> __device__ __forceinline__ void c2_run_seq(
    std::integer_sequence<u32, Gs...>, u32* o)
{
    (c2_exec_group<Gs>(o + c2_out_ofs<Gs>()), ...);
}

__global__ void c2_probe_kernel(u32* res)
{
    if (threadIdx.x != 0) return;
    // 1) sentinel writes (all low, in-allocation addresses only)
    c2_st_b32(0x0000, kStdSent(0x0000));
    c2_st_b32(0x0020, kStdSent(0x0020));
    c2_st_b32(0x0024, kStdSent(0x0024));
    c2_st_b32(0x0028, kStdSent(0x0028));
    c2_st_b32(0x0068, kStdSent(0x0068));
    c2_st_b32(0x00F0, kStdSent(0x00F0));
    c2_st_b32(0x0100, kStdSent(0x0100));
    c2_st_b32(0x0178, kStdSent(0x0178));
    c2_st_b32(0x0200, kStdSent(0x0200));
    c2_st_b32(0x0288, kStdSent(0x0288));
    c2_st_b32(0x0310, kStdSent(0x0310));
    c2_st_b32(0x0398, kStdSent(0x0398));
    c2_st_b32(0x2200, kStdSent(0x2200));
    c2_st_b32(0x2400, kStdSent(0x2400));
    c2_st_b32(0x2404, kStdSent(0x2404));
    c2_st_b32(0x2408, kStdSent(0x2408));
    c2_st_b32(0x240C, kStdSent(0x240C));
    c2_st_b32(0x2838, kStdSent(0x2838));
    c2_st_b32(0x3E00, kStdSent(0x3E00));
    c2_st_b32(0x7C00, kStdSent(0x7C00));
    c2_st_b32(0xFF00, kStdSent(0xFF00));
    c2_st_b32(0x002C, kU16Sent(0x002C));
    c2_st_b32(0x003C, kU16Sent(0x003C));
    c2_st_b32(0x243C, kU16Sent(0x243C));
    c2_wait_lds();

    // 2) group reads -> result stream
    u32* o = res + 4;
    c2_run_seq(std::make_integer_sequence<u32, kNGroups>{}, o);

    // 3) header
    res[0] = 0xC2C2C2C2u;
    res[1] = kNGroups;
    res[2] = 80u;   // output dwords
    res[3] = 1u;    // completed
}

// ---------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------
struct Row {
    u32 group, sub, form;
    u32 high, ea_dw, expected, actual;
};

static int failures = 0;
#define CHECK(cond, what)                                                   \
    do {                                                                    \
        if (cond) printf("PASS: %s\n", what);                               \
        else { printf("FAIL: %s\n", what); ++failures; }                    \
    } while (0)

static const char* form_name(u32 f)
{
    switch (f) {
        case 0: return "b32";
        case 1: return "u16";
        case 2: return "b64";
        case 3: return "b128";
        case 4: return "read2_b64";
    }
    return "?";
}

int main()
{
    int dev = 0;
    hipDeviceProp_t prop;
    CHECK(hipSetDevice(dev) == hipSuccess, "hipSetDevice(0)");
    CHECK(hipGetDeviceProperties(&prop, dev) == hipSuccess,
          "hipGetDeviceProperties(0)");
    printf("device: %s  gcnArchName=%s  warpSize=%u  sharedMemPerBlock=%zu\n",
           prop.name, prop.gcnArchName, prop.warpSize,
           (size_t)prop.sharedMemPerBlock);

    // Guarded result buffer: [0x1000 0x5A][payload][0x1000 0x5A]
    const size_t kGuard = 0x1000, kPayload = 0x2000;
    const size_t kTotal = kGuard + kPayload + kGuard;
    std::vector<uint8_t> host(kTotal, 0x5A);
    std::fill(host.begin() + kGuard, host.begin() + kGuard + kPayload, 0x00);

    uint8_t* devb = nullptr;
    CHECK(hipMalloc((void**)&devb, kTotal) == hipSuccess, "hipMalloc");
    CHECK(hipMemset(devb, 0x5A, kGuard) == hipSuccess, "memset guard");
    CHECK(hipMemset(devb + kGuard, 0x00, kPayload) == hipSuccess,
          "memset payload");
    CHECK(hipMemset(devb + kGuard + kPayload, 0x5A, kGuard) == hipSuccess,
          "memset guard2");

    auto t0 = std::chrono::steady_clock::now();
    hipLaunchKernelGGL(c2_probe_kernel, dim3(1), dim3(32),
                       /* dynamic group segment */ 65536u, 0,
                       (u32*)(devb + kGuard));
    hipError_t le = hipGetLastError();
    CHECK(le == hipSuccess, "launch (hipGetLastError)");
    hipError_t se = hipDeviceSynchronize();
    auto ms = std::chrono::duration<double, std::milli>(
                  std::chrono::steady_clock::now() - t0).count();
    CHECK(se == hipSuccess, "hipDeviceSynchronize");
    printf("SYNC_ELAPSED_MS=%.3f (5 s boundary; HANG if beyond)\n", ms);

    CHECK(hipMemcpy(host.data(), devb, kTotal, hipMemcpyDeviceToHost)
              == hipSuccess,
          "hipMemcpy back");

    // canaries
    size_t g1 = 0, g2 = 0;
    for (size_t i = 0; i < kGuard; ++i) g1 += (host[i] != 0x5A);
    for (size_t i = kGuard + kPayload; i < kTotal; ++i) g2 += (host[i] != 0x5A);
    CHECK(g1 == 0 && g2 == 0, "guard canaries intact");

    const u32* r = (const u32*)(host.data() + kGuard);
    CHECK(r[0] == 0xC2C2C2C2u, "result magic");
    printf("groups=%u outwords=%u done=%u\n", r[1], r[2], r[3]);
    CHECK(r[1] == kNGroups && r[2] == 80u && r[3] == 1u, "result header sane");

    // Build expectation table (host copy of the sentinel plan).
    // Every dword base that any read touches carries one stored dword:
    // kStdSlots -> 0xC0000000|dw ; kU16Base -> (exp16<<16)|0x5AA5.
    auto stdSent = [](u32 dw) { return 0xC0000000u | dw; };
    auto u16sent = [](u32 b) { return (u32)(((0x8000u | (b + 2u)) << 16) | 0x5AA5u); };
    auto expDw = [&](u32 dwA) {
        for (u32 dw : kStdSlots)
            if (dw == dwA) return stdSent(dw);
        for (u32 b : kU16Base)
            if (b == dwA) return u16sent(b);
        return (u32)-2;   // unknown slot: no sentinel stored there
    };
    // u16 read at byteA: byteA%4==0 -> low half of S(byteA);
    // byteA%4==2 -> high half of S(byteA-2).
    auto expU16 = [&](u32 byteA) {
        u32 base = byteA & ~3u;
        u32 S = expDw(base);
        return (byteA & 3u) == 0 ? (S & 0xFFFFu) : (S >> 16);
    };

    std::vector<Row> rows;
    u32 ofs = 0;
    for (u32 g = 0; g < kNGroups; ++g) {
        u32 form = kGroups[g].form;
        u32 high = kGroups[g].high;
        u32 n = c2_width(form);
        u32 base16 = high & 0xFFFFu;
        for (u32 s = 0; s < n; ++s) {
            u32 ea_dw;
            if (form == 2)      ea_dw = (base16 & ~7u) + s * 4u;
            else if (form == 3) ea_dw = (base16 & ~15u) + s * 4u;
            else if (form == 4) ea_dw = (base16 & ~7u) + (s < 2 ? s * 4u : 8u + (s - 2) * 4u);
            else                ea_dw = base16;   // b32/u16: s == 0
            u32 expected = (form == 1) ? expU16(ea_dw) : expDw(ea_dw);
            u32 actual = r[4 + ofs + s];
            rows.push_back({g, s, form, high, ea_dw, expected, actual});
        }
        ofs += n;
    }
    CHECK(ofs == 80u, "output stream size consistent");

    int nAlias = 0, nZero = 0, nOther = 0, nBaseFail = 0;
    for (const Row& x : rows) {
        bool isBase = (x.high < 0x10000u);
        u32 exp = (x.form == 1) ? (x.expected & 0xFFFFu) : x.expected;
        const char* cls;
        if (x.form == 1 && x.actual != 0u &&
            (x.actual & 0xFFFFu) == (x.expected & 0xFFFFu)) {
            cls = (x.actual >> 16) == 0 ? "LOW16_ALIAS" : "LOW16_ALIAS_HIBITS";
            nAlias++;
        } else if (x.form == 1 && (x.actual & 0xFFFFu) == 0u &&
                   x.actual == 0u) {
            cls = "OOB_ZERO"; nZero++;
        } else if (x.form != 1 && x.actual == exp) {
            cls = "LOW16_ALIAS"; nAlias++;
        } else if (x.form != 1 && x.actual == 0u) {
            cls = "OOB_ZERO"; nZero++;
        } else {
            cls = "OTHER"; nOther++;
        }
        if (isBase && x.actual != exp) {
            cls = "BASELINE_FAIL"; nBaseFail++;
        }
        printf("g%02u s%u %-9s high=0x%08X ea_dw=0x%04X exp=0x%08X "
               "act=0x%08X %s%s\n",
               x.group, x.sub, form_name(x.form), x.high, x.ea_dw,
               x.form == 1 ? (x.expected & 0xFFFFu) : x.expected,
               x.actual, cls, isBase ? " [BASELINE]" : "");
    }

    printf("---- C2 summary ----\n");
    printf("baseline_failures=%d low16_alias=%d oob_zero=%d other=%d\n",
           nBaseFail, nAlias, nZero, nOther);
    CHECK(nBaseFail == 0, "all baseline reads returned their sentinels");
    if (nBaseFail == 0) {
        if (nZero == 0 && nOther == 0)
            printf("C2_VERDICT: CASE C2-A (LOW16_ALIAS — hardware consumes "
                   "low address bits for these forms)\n");
        else if (nAlias == 0)
            printf("C2_VERDICT: CASE C2-B (OOB_ZERO/OTHER — no low16 alias)\n");
        else
            printf("C2_VERDICT: CASE C2-C (mixed by form — build per-opcode map)\n");
    } else {
        printf("C2_VERDICT: PROBE FAIL (baseline broken)\n");
    }

    hipFree(devb);
    printf("EXIT failures=%d\n", failures);
    return failures ? 1 : 0;
}
