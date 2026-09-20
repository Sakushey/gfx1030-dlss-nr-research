// Phase 11E implementation: fail-closed fatbin identity + substitution.
// See registry_ident.h for the contract. Host-only; no GPU.
#include "registry_ident.h"

#include <windows.h>

#include <cstdio>
#include <cstring>

namespace bridge_registry {

// ------------------------------------------------------------------
// SHA-256 (FIPS 180-4), compact implementation.
// ------------------------------------------------------------------
namespace {

constexpr uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline uint32_t rotr(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

}  // namespace

void sha256(const unsigned char* data, size_t len, unsigned char out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    // Per-block message source: data blocks first, then the tail block(s)
    // holding the remainder + 0x80 + zeros + 64-bit bit length.
    unsigned char tail[128];
    const size_t rem = len % 64;
    const size_t full = len / 64;
    size_t t = 0;
    for (size_t i = 0; i < rem; ++i) {
        tail[t++] = data[full * 64 + i];
    }
    tail[t++] = 0x80;
    while (t % 64 != 56) {
        tail[t++] = 0;
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 7; i >= 0; --i) {
        tail[t++] = (unsigned char)(bits >> (8 * i));
    }
    const size_t blocks = full + t / 64;

    for (size_t b = 0; b < blocks; ++b) {
        const unsigned char* src =
            (b < full) ? data + b * 64 : tail + (b - full) * 64;
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            const unsigned char* p = src + i * 4;
            w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                   ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b2 = h[1], c = h[2], dd = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + kK[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b2) ^ (a & c) ^ (b2 & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = dd + t1;
            dd = c; c = b2; b2 = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b2; h[2] += c; h[3] += dd;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = (unsigned char)(h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)h[i];
    }
}

// ------------------------------------------------------------------
// Identity
// ------------------------------------------------------------------
namespace {

// Layout mirrors the decoded upstream bundle (see
// phase11_original_fatbin_layout.md).
const char kBundleMagic[] = "__CLANG_OFFLOAD_BUNDLE__";  // 24 chars + NUL

bool hex_eq(const unsigned char digest[32], const char* hex)
{
    for (int i = 0; i < 32; ++i) {
        auto nib = [](unsigned v) { return v < 10 ? char('0' + v) : char('a' + v - 10); };
        char hi = nib(digest[i] >> 4);
        char lo = nib(digest[i] & 0xf);
        if (hex[i * 2] != hi || hex[i * 2 + 1] != lo) {
            return false;
        }
    }
    return hex[64] == '\0';
}

}  // namespace

Identity identify(const void* data, char* why, size_t whyLen)
{
    auto fail = [&](const char* msg) {
        if (why && whyLen) {
            std::snprintf(why, whyLen, "%s", msg);
        }
        return Identity::kNotOurs;
    };
    if (data == nullptr) {
        return fail("null payload");
    }
    const unsigned char* p = (const unsigned char*)data;
    // magic + version u64
    if (std::memcmp(p, kBundleMagic, sizeof(kBundleMagic) - 1) != 0) {
        return fail("bundle magic mismatch");
    }
    uint64_t version;
    std::memcpy(&version, p + 24, 8);
    if (version != kBundleVersion) {
        return fail("bundle version mismatch");
    }
    // entries
    const char* archSeen[kExpectedArchCount] = {nullptr, nullptr, nullptr, nullptr};
    size_t seenHost = 0;
    size_t spanEnd = 0;
    size_t pos = 32;
    size_t entries = 0;
    for (;;) {
        if (pos + 24 > kMaxSpan) {
            return fail("entry table overrun cap");
        }
        uint64_t off, size, idLen;
        std::memcpy(&off, p + pos, 8);
        std::memcpy(&size, p + pos + 8, 8);
        std::memcpy(&idLen, p + pos + 16, 8);
        if (off == 0 && size == 0 && idLen == 0) {
            break;  // table terminator
        }
        if (++entries > kMaxEntries) {
            return fail("too many entries");
        }
        if (idLen == 0 || idLen > 256 || pos + 24 + idLen > kMaxSpan) {
            return fail("entry id length out of bounds");
        }
        if (off > kMaxSpan || size > kMaxSpan || off + size > kMaxSpan) {
            return fail("entry span out of bounds");
        }
        if (off + size > spanEnd) {
            spanEnd = (size_t)(off + size);
        }
        char id[257];
        std::memcpy(id, p + pos + 24, (size_t)idLen);
        id[idLen > 256 ? 256 : (size_t)idLen] = '\0';
        // strip the common bundle prefix
        const char* suffix = id;
        if (std::strncmp(id, "host-", 5) == 0) {
            seenHost += 1;
            if (size != 0) {
                return fail("host entry non-empty");
            }
        } else if (std::strncmp(id, "hipv4-amdgcn-amd-amdhsa--", 25) == 0) {
            suffix = id + 25;
            bool known = false;
            for (size_t i = 0; i < kExpectedArchCount; ++i) {
                if (std::strcmp(suffix, kExpectedArch[i]) == 0) {
                    if (archSeen[i] != nullptr) {
                        return fail("duplicate arch entry");
                    }
                    archSeen[i] = suffix;
                    known = true;
                    break;
                }
            }
            if (!known) {
                return fail("unknown arch entry");
            }
        } else {
            return fail("unexpected entry id");
        }
        pos += 24 + (size_t)idLen;
    }
    if (seenHost != 1) {
        return fail("host entry count != 1");
    }
    for (size_t i = 0; i < kExpectedArchCount; ++i) {
        if (archSeen[i] == nullptr) {
            return fail("missing expected arch entry");
        }
    }
    if (spanEnd == 0 || spanEnd > kMaxSpan) {
        return fail("bad content span");
    }
    // content hash gate
    unsigned char digest[32];
    sha256(p, spanEnd, digest);
    if (!hex_eq(digest, kExpectedFatbinSha256)) {
        return fail("content hash mismatch");
    }
    return Identity::kMatch;
}

bool substitution_enabled()
{
    char value[2] = {0, 0};
    DWORD len = GetEnvironmentVariableA("DLSSNR_GFX1030_USE_GFX1030_FATBIN",
                                        value, sizeof(value));
    return len == 1 && value[0] == '1';
}

const unsigned char* gfx1030_bundle()
{
    return g_gfx1030_fatbin;
}

size_t gfx1030_bundle_size()
{
    return g_gfx1030_fatbin_size;
}

}  // namespace bridge_registry
