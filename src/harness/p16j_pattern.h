// Phase 16J -- the deterministic nontrivial input pattern.
//
// Shared by the J3 physical harness and by a host-only parity dump so the
// C++ generator and the Python one (`p16j_input.pattern_at`) can be proved
// identical rather than assumed identical.  If they ever disagreed, a
// physical result and its host reference would be compared across different
// inputs, and the comparison would be meaningless in a way that looks fine.
#ifndef P16J_PATTERN_H
#define P16J_PATTERN_H

#include <cstdint>

// A byte at region-relative offset i.  Depends only on the OFFSET, never on
// the allocation or on how much of the region was filled, so a partial fill
// and a full fill agree wherever they overlap.  Never zero, so "unwritten"
// stays distinguishable from "written".
static inline uint8_t pattern_at(uint64_t i)
{
    uint32_t x = (uint32_t)(i & 0xFFFFFFFFu);
    x = x * 1664525u + 1013904223u;
    x ^= x >> 13;
    x = x * 1664525u + 1013904223u;
    uint8_t b = (uint8_t)(x >> 16);
    return b ? b : (uint8_t)1;
}

// A second, independent legal nontrivial pattern: a multiply-shift hash
// rather than an LCG, so a result that survives both is not an artefact of
// one generator's correlations.
static inline uint8_t pattern_b(uint64_t i)
{
    uint32_t x = (uint32_t)(i & 0xFFFFFFFFu);
    x = x * 2654435761u + 0x9E3779B9u;
    x ^= (x >> 15);
    x = x * 2246822519u;
    x ^= (x >> 13);
    uint8_t b = (uint8_t)(x >> 11);
    return b ? b : (uint8_t)1;
}

#endif  // P16J_PATTERN_H
