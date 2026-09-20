// Phase 11E: fail-closed identification of the supported upstream
// DLSS-NR HIP fatbin at __hipRegisterFatBinary time, and substitution of
// the canonical gfx1030 bundle.
//
// Identification combines (ALL required):
//   * __CLANG_OFFLOAD_BUNDLE__ magic + version 5
//   * bundle entries: host + exactly {hipv4-amdgcn-amd-amdhsa--gfx1100,
//     gfx1101, gfx1102, gfx1201} (the upstream DLSS-NR arch set)
//   * bounded structural parse (no reads past entry span; cap 16 MiB,
//     16 entries)
//   * SHA-256 of the full entry span equals the exact upstream fatbin
//     content hash (computed from the vendor static copy)
//
// Any mismatch -> forward the ORIGINAL registration unchanged (fail-safe:
// never substitute an arbitrary application's payload).
//
// Substitution is additionally gated by the environment variable
// DLSSNR_GFX1030_USE_GFX1030_FATBIN == "1" (default off). When active and
// identity matches, the backend receives a wrapper whose data pointer is
// the static canonical gfx1030 bundle embedded in this DLL (lifetime =
// process lifetime, 11F).
#pragma once

#include <cstdint>
#include <cstddef>

#include "bridge_gfx1030_fatbin.h"

namespace bridge_registry {

// ---------------- known upstream payload identity ----------------
// Decoded from phase5_exact_fragment/version.dll.static_copy (.hip_fat).
constexpr uint64_t kBundleVersion = 5;
constexpr size_t kMaxSpan = 16u * 1024u * 1024u;   // structural cap
constexpr size_t kMaxEntries = 16;
// SHA-256 of the exact upstream fatbin content span (computed from the
// vendor static copy; see phase11_fatbin_audit.md):
const char kExpectedFatbinSha256[] =
    "13018cbe95e2652fcccf1b958c0bf09e54172d03fa262a0c86539b8351300a54";
// Expected arch-id suffixes of the upstream bundle:
const char* const kExpectedArch[] = {"gfx1100", "gfx1101", "gfx1102", "gfx1201"};
constexpr size_t kExpectedArchCount = 4;

// __hip_fatbin wrapper layout: magic u32 ('HIPF'), version u32,
// data pointer u64, unused u32 (see phase11_original_fatbin_layout.md).
struct HipFatbinWrapper {
    uint32_t magic;
    uint32_t version;
    const void* data;
    uint32_t unused;
};

enum class Identity {
    kNotOurs,       // structural or hash mismatch -> forward original
    kMatch,         // exact supported upstream payload
};

// sha256 over span; writes 32 bytes to out. Pure host-side C (keeps the
// bridge import set at KERNEL32 only).
void sha256(const unsigned char* data, size_t len, unsigned char out[32]);

// Bounded structural parse + identity decision. data points at the
// __CLANG_OFFLOAD_BUNDLE__ payload (wrapper->data).
Identity identify(const void* data, char* why, size_t whyLen);

bool substitution_enabled();

// Static canonical gfx1030 bundle (embedded; process-lifetime storage).
const unsigned char* gfx1030_bundle();
size_t gfx1030_bundle_size();

}  // namespace bridge_registry
