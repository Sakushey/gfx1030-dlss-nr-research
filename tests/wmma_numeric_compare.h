// Shared finite-aware numerical comparator for the gfx1030 fixtures.
//
// One utility, three consumers: tests/soft_wmma_test.cpp (dense arithmetic),
// tests/soft_wmma_bench.cpp (bounded throughput), and
// tests/soft_wmma_fragment_test.cpp (wave32 fragment ownership).
//
// Why this is not `max(abs(got - ref)) <= tol`:
//
//   * NaN compares unequal to everything, so a `>` test silently reports the
//     smallest error for an element that produced a NaN. A NaN result is not
//     "small error", it is a broken arithmetic path, and it must be its own
//     verdict.
//   * +/-Inf behaves differently again. `inf - finite == inf`, so an infinity
//     in `got` trips a tolerance test, but an infinity in `ref` makes every
//     element compare as a non-error. Neither is a correctness statement.
//   * An element the kernel never wrote is indistinguishable from an element
//     it wrote correctly if the pre-launch pattern happens to be close to the
//     reference. The buffers are pre-filled with a sentinel and the sentinel
//     is a graded failure, not a value.
//   * A comparison over a shorter buffer than the caller believes it has
//     reports a perfect match over the part it happened to look at. Length is
//     checked, not assumed.
//   * Out-of-range writes are the failure mode a length check cannot see: the
//     graded region is correct and something past the end changed. Guard
//     elements are graded too.
//
// Host-only *and* device compilable: no allocation, no I/O, no exceptions.
// That is what lets a plain host C++ driver exercise every rejection path
// with no GPU, which is the only way the negative controls can actually run.
#ifndef WMMA_NUMERIC_COMPARE_H
#define WMMA_NUMERIC_COMPARE_H

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace wmma_check {

// Ordered so a caller can print `verdict_name(r.verdict)` and get one word.
enum class Verdict {
    PASS = 0,
    LENGTH_MISMATCH,      // declared count does not match the buffer lengths
    NONFINITE_REFERENCE,  // the reference itself is not finite: the test is void
    NAN_MISMATCH,         // NaN in the result where the reference is finite
    INF_MISMATCH,         // +/-Inf in the result where the reference is finite
    SENTINEL_UNTOUCHED,   // a graded element still holds the pre-launch pattern
    TOLERANCE_EXCEEDED,   // |got - ref| > tolerance at some graded element
    GUARD_CORRUPTED,      // an element outside the graded region changed
};

inline const char* verdict_name(Verdict v)
{
    switch (v) {
        case Verdict::PASS:                 return "PASS";
        case Verdict::LENGTH_MISMATCH:      return "LENGTH_MISMATCH";
        case Verdict::NONFINITE_REFERENCE:  return "NONFINITE_REFERENCE";
        case Verdict::NAN_MISMATCH:         return "NAN_MISMATCH";
        case Verdict::INF_MISMATCH:         return "INF_MISMATCH";
        case Verdict::SENTINEL_UNTOUCHED:   return "SENTINEL_UNTOUCHED";
        case Verdict::TOLERANCE_EXCEEDED:   return "TOLERANCE_EXCEEDED";
        case Verdict::GUARD_CORRUPTED:      return "GUARD_CORRUPTED";
    }
    return "UNKNOWN";
}

// The pre-launch fill pattern.
//
// A quiet-NaN payload, chosen so that no value this project's kernels can
// produce equals it: the fixtures' arithmetic canonicalises every NaN result
// to 0x7FC00000 (see `QNAN_F32` in src/emulator/emu.py), so 0x7FC0DEAD is
// unreachable from a correct computation and a surviving sentinel is
// unambiguously "this element was never written". It is also a NaN, so a
// comparison that forgets to check the sentinel first still cannot pass it.
inline uint32_t sentinel_bits() { return 0x7FC0DEADu; }

inline float sentinel_value()
{
    const uint32_t b = sentinel_bits();
    float f;
    std::memcpy(&f, &b, sizeof(f));
    return f;
}

inline uint32_t bits_of(float f)
{
    uint32_t b;
    std::memcpy(&b, &f, sizeof(b));
    return b;
}

struct Config {
    // Absolute tolerance applied to graded elements.
    float tolerance;
    // Number of graded elements. The graded region is [0, count).
    std::size_t count;
    // Trailing guard elements at [count, count + guard_count). They are
    // outside the graded region and must still hold the sentinel.
    std::size_t guard_count;

    Config() : tolerance(1.0e-3f), count(0), guard_count(0) {}
    Config(float tol, std::size_t n, std::size_t guards = 0)
        : tolerance(tol), count(n), guard_count(guards) {}
};

struct Result {
    Verdict     verdict;
    // Offending element. For LENGTH_MISMATCH it is the length that was
    // actually observed; for GUARD_CORRUPTED it is the guard's absolute
    // index; otherwise it is the first offending graded index.
    std::size_t index;
    // Largest |got - ref| over the elements examined before the verdict was
    // reached. Recorded even on failure so a report can show how far off the
    // run was.
    double      max_abs;
    // Graded elements actually compared before the verdict was reached.
    std::size_t n_compared;
};

namespace detail {

inline bool is_nan(float f) { return std::isnan(f); }
inline bool is_inf(float f) { return std::isinf(f); }

// Returns true and records the verdict when the element is not a finite
// number that the tolerance test can be applied to.
//
// Order matters, and the sentinel is checked before the NaN test rather than
// after: the sentinel is itself a NaN, so a NaN test first would report every
// untouched element as NAN_MISMATCH and lose the distinction the sentinel
// exists to draw. An exact bit-pattern match is the more specific claim, so
// it wins.
inline bool classify(float got, float ref, std::size_t i, Result& r)
{
    if (is_nan(ref) || is_inf(ref)) {
        r.verdict = Verdict::NONFINITE_REFERENCE;
        r.index = i;
        return true;
    }
    if (bits_of(got) == sentinel_bits()) {
        r.verdict = Verdict::SENTINEL_UNTOUCHED;
        r.index = i;
        return true;
    }
    if (is_nan(got)) {
        r.verdict = Verdict::NAN_MISMATCH;
        r.index = i;
        return true;
    }
    if (is_inf(got)) {
        r.verdict = Verdict::INF_MISMATCH;
        r.index = i;
        return true;
    }
    return false;
}

}  // namespace detail

// Grade `got` against `ref`.
//
// The two buffers have different required lengths, and that asymmetry is the
// point:
//
//   got_len must equal count + guard_count -- the graded region plus the
//   trailing guards that must survive untouched;
//   ref_len must equal count exactly -- there is no reference for a guard,
//   because a guard has no expected value, only an expected *absence of
//   writes*. Requiring the reference to carry guards too would force every
//   caller to invent values for elements nothing computes.
//
// Anything else is a LENGTH_MISMATCH, because a comparison over a buffer
// shorter than the caller believes reports a match over the part it happened
// to look at. A zero-length comparison is also a LENGTH_MISMATCH rather than
// a vacuous PASS.
inline Result compare(const float* got, std::size_t got_len,
                      const float* ref, std::size_t ref_len,
                      const Config& cfg)
{
    Result r{};
    r.verdict = Verdict::PASS;
    r.index = 0;
    r.max_abs = 0.0;
    r.n_compared = 0;

    const std::size_t total = cfg.count + cfg.guard_count;
    if (got == nullptr || ref == nullptr) {
        r.verdict = Verdict::LENGTH_MISMATCH;
        r.index = 0;
        return r;
    }
    if (got_len != total || ref_len != cfg.count || cfg.count == 0) {
        r.verdict = Verdict::LENGTH_MISMATCH;
        r.index = got_len;
        return r;
    }

    // Guards first: an out-of-range write is a different defect from a wrong
    // value, and it must not be masked by an earlier tolerance failure.
    for (std::size_t i = cfg.count; i < total; ++i) {
        if (bits_of(got[i]) != sentinel_bits()) {
            r.verdict = Verdict::GUARD_CORRUPTED;
            r.index = i;
            return r;
        }
    }

    for (std::size_t i = 0; i < cfg.count; ++i) {
        if (detail::classify(got[i], ref[i], i, r)) {
            return r;
        }
        const double e = std::fabs(static_cast<double>(got[i]) -
                                   static_cast<double>(ref[i]));
        if (e > r.max_abs) {
            r.max_abs = e;
        }
        ++r.n_compared;
        if (e > static_cast<double>(cfg.tolerance)) {
            r.verdict = Verdict::TOLERANCE_EXCEEDED;
            r.index = i;
            return r;
        }
    }
    return r;
}

// Fill a buffer with the sentinel. Host-side helper so the fixtures and the
// negative-control driver agree on the pattern by construction rather than by
// both hardcoding it.
inline void fill_sentinel(float* buf, std::size_t n)
{
    const float s = sentinel_value();
    for (std::size_t i = 0; i < n; ++i) {
        buf[i] = s;
    }
}

}  // namespace wmma_check

#endif  // WMMA_NUMERIC_COMPARE_H
