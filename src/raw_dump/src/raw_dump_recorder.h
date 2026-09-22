// Phase 16AT RAW_DUMP -- the recorder.
//
// WHAT THIS IS
// ------------
// A capture-only recorder for the COMPLETE host by-value parameter image that
// the launch path hands to a kernel launch, captured at one exact point in the
// project's HIP telemetry bridge:
//
//   phase16_bridge_telemetry/src/amdhip64_7.cpp :: hipLaunchKernel
//       -> immediately after the existing decode_launch_args(name, args);
//
// At that statement the caller's by-value parameter images already exist (the
// caller materialised them before entering the bridge) and nothing in the
// bridge has written to them. The two operations that could change the
// representation -- the fail-closed gate's early return and the backend
// submission fn(...) -- both come later in the same function. So a capture
// taken here sees the bytes as the application built them, before packing and
// before submission.
//
// WHAT THIS IS NOT
// ----------------
// It is not a resolver. It records bytes; it interprets none. The 15
// scalar_constants fields stay UNRESOLVED until a record taken at a real
// launch is read. No GPU is touched by any code in this directory.
//
// HOST-ONLY: this file and its header include <windows.h> and the C runtime
// only. They import nothing from any HIP runtime.
#pragma once

#include <cstddef>

namespace raw_dump {

// ---------------------------------------------------------------- identity
constexpr const char* kRecordSchema = "p16at/raw-dump-record/1";
// The one line this recorder is wired to. Recorded verbatim in every record so
// a record can be tied to the source revision that emitted it.
constexpr const char* kSourceCallsite =
    "phase16_bridge_telemetry/src/amdhip64_7.cpp:hipLaunchKernel:after "
    "decode_launch_args(name,args):before the launch gate and before the "
    "backend submission fn(...)";

// ---------------------------------------------------------------- request
struct Request {
    unsigned launch_ordinal;         // the bridge's per-process launch counter
    const char* kernel_identity;     // the registered device (mangled) name
    const void* blob;                // args[0]: the by-value parameter image
    std::size_t blob_length;         // declared by-value size (see the table)
    const unsigned* requested_offsets;  // BLOB-relative offsets of interest
    std::size_t n_requested_offsets;
};

struct Outcome {
    bool capture_site_reached;    // the wired-in call executed
    bool enabled;                 // RAW_DUMP gate was ON
    bool emission_point_reached;  // the recorder was ENABLED and reached emit()
    bool record_written;          // a complete record reached the disk
    bool refused;                 // declined to write, with a reason
    bool clobber_refused;         // a CREATE_NEW collided (write-once honoured)
    char reason[224];
    char record_path[600];
    char sidecar_path[600];
    char trace_path[600];
};

// ---------------------------------------------------------------- control
// Fail-closed. All are process-local reads of the environment; nothing is
// persisted, no file is created to remember state.
//   RAW_DUMP_DIR  : where records go. Unset/empty -> the recorder is inert.
//   RAW_DUMP      : exactly "1" -> records are written. Anything else (unset,
//                   "0", "true", "yes", "") -> traces still happen, records
//                   do not. This is the OFF arm of the rehearsal and the
//                   "recorder disabled" control; it is deliberately NOT the
//                   same thing as being unconfigured.
//   RAW_DUMP_KERNELS : "all" (default) or a comma list of identities.
//   RAW_DUMP_FRAME_ID : integer override for frame_id.
//
// Both copy into the caller's buffer. Returning a pointer into a shared
// internal buffer was the first thing this recorder got wrong: `dir` was
// captured, then a later read of a DIFFERENT variable reused the same buffer
// and the directory became the string "1". Every caller now owns its copy.
bool out_dir(char* buf, std::size_t cap);       // false when unset/empty
bool records_enabled();
bool kernel_filter(char* buf, std::size_t cap);
bool frame_id_override(long* out);

// Append one trace event to <out_dir>/_raw_dump_trace.log. The trace is what
// makes reach measurable: a control that never reaches a point emits no line
// for it, and the arm's runner reads the file rather than assuming. Never
// throws; returns false if the line could not be written.
bool trace(const char* event, const char* detail);

// The capture. Writes one record and one side-car, both with CREATE_NEW, so an
// existing file is never overwritten.
Outcome emit(const Request& r);

// ------------------------------------------------------------------ selftest
// Drives emit() against a caller-supplied directory with synthetic blobs and
// reports, per case, whether the recorder behaved. Used by the control runner;
// it is the "prove it can fail and prove it passes" instrument for the
// recorder's OWN checks, as distinct from the eight controls over the capture.
struct SelfTestStep {
    const char* name;
    bool ok;
    char detail[256];
};
std::size_t self_test(const char* dir, SelfTestStep* steps, std::size_t cap);

}  // namespace raw_dump
