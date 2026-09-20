// Host-only driver for tests/wmma_numeric_compare.h.
//
// Every rejection class the comparator claims to implement is constructed
// here as a real input, together with the known-good case. The driver does
// not decide anything: it prints `CASE <name> EXPECT <verdict> GOT <verdict>`
// and the caller (tests/host/test_numeric_compare.py) asserts the verdicts.
// That split is deliberate -- a driver that also judged itself would be
// checking its own arithmetic.
//
// Two cases are negative controls on the *comparator* rather than on the
// data: they run the naive `max_abs <= tol` check over the same buffers the
// comparator rejects, and report whether the naive check accepted them. If
// the naive check ever stops accepting them, the data cases have gone stale
// and the file says so instead of reporting a hollow pass.
#include "wmma_numeric_compare.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

using wmma_check::Config;
using wmma_check::Result;
using wmma_check::Verdict;

static int g_failures = 0;

static void report(const char* name, Verdict expect, const Result& r)
{
    const bool ok = (r.verdict == expect);
    if (!ok) {
        ++g_failures;
    }
    std::printf("CASE %s EXPECT %s GOT %s INDEX %zu MAXABS %.9g COMPARED %zu %s\n",
                name, wmma_check::verdict_name(expect),
                wmma_check::verdict_name(r.verdict), r.index, r.max_abs,
                r.n_compared, ok ? "OK" : "BAD");
}

// The naive comparison this utility replaces. Kept here so the driver can
// show, on the very inputs the comparator rejects, that the naive form
// accepts them -- which is the whole reason the utility exists.
static bool naive_accepts(const std::vector<float>& got,
                          const std::vector<float>& ref,
                          std::size_t count, float tol,
                          double* max_abs_out)
{
    double m = 0.0;
    for (std::size_t i = 0; i < count; ++i) {
        const double e = std::fabs(static_cast<double>(got[i]) -
                                   static_cast<double>(ref[i]));
        if (e > m) {
            m = e;
        }
    }
    if (max_abs_out) {
        *max_abs_out = m;
    }
    return m <= static_cast<double>(tol);
}

static void report_naive(const char* name, const std::vector<float>& got,
                         const std::vector<float>& ref, std::size_t count,
                         float tol, bool expect_naive_accepts)
{
    double m = 0.0;
    const bool accepts = naive_accepts(got, ref, count, tol, &m);
    const bool ok = (accepts == expect_naive_accepts);
    if (!ok) {
        ++g_failures;
    }
    std::printf("NAIVE %s EXPECT_ACCEPTS %d GOT_ACCEPTS %d MAXABS %.9g %s\n",
                name, expect_naive_accepts ? 1 : 0, accepts ? 1 : 0, m,
                ok ? "OK" : "BAD");
}

int main()
{
    const float kTol = 1.0e-3f;
    const std::size_t kN = 16;
    const std::size_t kGuards = 4;

    // ---------------------------------------------------------------- good
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = static_cast<float>(i) / 4.0f;
            got[i] = ref[i];
        }
        report("known_good_exact", Verdict::PASS,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
    }
    {
        // Exact inside tolerance, and not bit-equal: the tolerance must be a
        // tolerance, not an equality test.
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = static_cast<float>(i) / 4.0f;
            got[i] = ref[i] + kTol / 2.0f;
        }
        report("known_good_within_tolerance", Verdict::PASS,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
    }

    // ------------------------------------------------------------ rejections
    // NaN where the reference is finite.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        got[5] = std::numeric_limits<float>::quiet_NaN();
        const Result r = wmma_check::compare(got.data(), got.size(), ref.data(),
                                             ref.size(), Config(kTol, kN, kGuards));
        report("nan_in_result", Verdict::NAN_MISMATCH, r);
        report_naive("nan_in_result", got, ref, kN, kTol, true);
    }
    // +Inf where the reference is finite.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        got[7] = std::numeric_limits<float>::infinity();
        report("pos_inf_in_result", Verdict::INF_MISMATCH,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
    }
    // -Inf where the reference is finite.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        got[9] = -std::numeric_limits<float>::infinity();
        report("neg_inf_in_result", Verdict::INF_MISMATCH,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
    }
    // A non-finite reference voids the test rather than passing it.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        ref[3] = std::numeric_limits<float>::infinity();
        report("nonfinite_reference_is_void", Verdict::NONFINITE_REFERENCE,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
    }
    // An element the kernel never wrote. Its value is deliberately chosen to
    // be *inside* tolerance of the reference, so a comparator that skipped the
    // sentinel check would call this a pass.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        got[11] = wmma_check::sentinel_value();
        report("untouched_sentinel", Verdict::SENTINEL_UNTOUCHED,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
        report_naive("untouched_sentinel", got, ref, kN, kTol, true);
    }
    // Buffer shorter than the declared count: the comparison must not silently
    // grade the prefix it happens to have.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        report("wrong_length_got", Verdict::LENGTH_MISMATCH,
               wmma_check::compare(got.data(), kN + kGuards - 1, ref.data(),
                                   ref.size(), Config(kTol, kN, kGuards)));
    }
    // Reference shorter than the graded count. The graded region is correct,
    // so only the length rule can catch this: grading the prefix it happens to
    // have would report a perfect match.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        report("wrong_length_ref", Verdict::LENGTH_MISMATCH,
               wmma_check::compare(got.data(), got.size(), ref.data(), kN - 1,
                                   Config(kTol, kN, kGuards)));
    }
    // Reference LONGER than the graded count -- specifically, count + guards.
    // This is the exact mistake a caller makes when it assumes the reference
    // is shaped like the result buffer, and it is a regression control for the
    // rule that the reference carries the graded region only, with no guard
    // values invented for it. Under the wrong rule this is a PASS.
    {
        std::vector<float> ref(kN + kGuards, 1.0f);
        std::vector<float> got(kN + kGuards, 1.0f);
        report("ref_shaped_like_got_is_length_mismatch", Verdict::LENGTH_MISMATCH,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
    }
    // One element over tolerance, and only one.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        got[13] = 1.0f + kTol * 4.0f;
        report("one_element_over_tolerance", Verdict::TOLERANCE_EXCEEDED,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
    }
    // An out-of-range write. The graded region is perfect; only a guard moved.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f;
        }
        got[kN + 1] = 1.0f;
        report("corrupted_guard", Verdict::GUARD_CORRUPTED,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, kN, kGuards)));
        // The naive check never looks past `count`, so it cannot see this at
        // all. Accepting here is the point.
        report_naive("corrupted_guard", got, ref, kN, kTol, true);
    }
    // Zero graded elements is a length error, not a vacuous pass.
    {
        std::vector<float> ref, got;
        report("empty_comparison_is_not_a_pass", Verdict::LENGTH_MISMATCH,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol, 0, 0)));
    }
    // A tolerance tighter than the data: proves the tolerance is load-bearing
    // rather than decorative.
    {
        std::vector<float> ref(kN), got(kN + kGuards, wmma_check::sentinel_value());
        for (std::size_t i = 0; i < kN; ++i) {
            ref[i] = 1.0f;
            got[i] = 1.0f + kTol / 2.0f;
        }
        report("tightened_tolerance_rejects", Verdict::TOLERANCE_EXCEEDED,
               wmma_check::compare(got.data(), got.size(), ref.data(), ref.size(),
                                   Config(kTol / 100.0f, kN, kGuards)));
    }

    std::printf("DRIVER_FAILURES %d\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
