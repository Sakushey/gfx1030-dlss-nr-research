// Phase 16J -- self-contained SHA-256, shared by the J3 harness and by a
// host-only verifier so the hash function can be checked against known
// vectors WITHOUT the harness ever reaching the GPU.
#ifndef P16J_SHA256_H
#define P16J_SHA256_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

namespace sha256 {

struct Ctx {
    uint32_t h[8];
    uint64_t nbits;
    uint8_t buf[64];
    size_t buflen;
};

static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

inline uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

inline void block(Ctx& c, const uint8_t* p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) |
               ((uint32_t)p[4*i+2] << 8) | (uint32_t)p[4*i+3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c.h[0], b=c.h[1], cc=c.h[2], d=c.h[3];
    uint32_t e=c.h[4], f=c.h[5], g=c.h[6], hh=c.h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c.h[0]+=a; c.h[1]+=b; c.h[2]+=cc; c.h[3]+=d;
    c.h[4]+=e; c.h[5]+=f; c.h[6]+=g; c.h[7]+=hh;
}

inline void init(Ctx& c)
{
    c.h[0]=0x6a09e667u; c.h[1]=0xbb67ae85u; c.h[2]=0x3c6ef372u;
    c.h[3]=0xa54ff53au; c.h[4]=0x510e527fu; c.h[5]=0x9b05688cu;
    c.h[6]=0x1f83d9abu; c.h[7]=0x5be0cd19u;
    c.nbits = 0; c.buflen = 0;
}

inline void update(Ctx& c, const uint8_t* p, size_t n)
{
    c.nbits += (uint64_t)n * 8;
    while (n) {
        size_t take = std::min(n, (size_t)64 - c.buflen);
        std::memcpy(c.buf + c.buflen, p, take);
        c.buflen += take; p += take; n -= take;
        if (c.buflen == 64) { block(c, c.buf); c.buflen = 0; }
    }
}

inline std::string hex(const uint8_t* data, size_t n)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += d[data[i] >> 4]; s += d[data[i] & 15]; }
    return s;
}

inline std::string digest(Ctx& c)
{
    uint64_t bits = c.nbits;
    uint8_t pad = 0x80;
    update(c, &pad, 1);
    uint8_t z = 0;
    while (c.buflen != 56) { update(c, &z, 1); }
    uint8_t len[8];
    for (int i = 0; i < 8; ++i) { len[i] = (uint8_t)(bits >> (56 - 8*i)); }
    c.nbits -= 64;                       // the length field is not hashed data
    update(c, len, 8);
    uint8_t out[32];
    for (int i = 0; i < 8; ++i) {
        out[4*i]   = (uint8_t)(c.h[i] >> 24);
        out[4*i+1] = (uint8_t)(c.h[i] >> 16);
        out[4*i+2] = (uint8_t)(c.h[i] >> 8);
        out[4*i+3] = (uint8_t)(c.h[i]);
    }
    return hex(out, 32);
}

inline std::string of(const void* data, size_t n)
{
    Ctx c; init(c);
    update(c, reinterpret_cast<const uint8_t*>(data), n);
    return digest(c);
}

}  // namespace sha256

#endif  // P16J_SHA256_H
