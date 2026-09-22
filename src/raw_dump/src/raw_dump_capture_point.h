// Phase 16AT RAW_DUMP -- THE CAPTURE POINT.
//
// This header is the entire wiring change. p16at_apply_capture_point.py
// inserts two lines into phase16_bridge_telemetry/src/amdhip64_7.cpp:
//
//   (1) near the top,  #include "raw_dump_capture_point.h"
//   (2) in hipLaunchKernel, immediately AFTER the existing statement
//           decode_launch_args(name, args);
//       and therefore BEFORE the fail-closed launch gate's early return and
//       BEFORE the backend submission fn(function_address, ..., args, ...):
//
//           raw_dump_at_launch_capture_point(name, function_address, args,
//                                            launch_ordinal);
//
// The original file is never modified. The transformer writes a transformed
// copy under p16at/raw_dump/_work/ and proves that deleting the inserted
// lines reproduces the original byte-for-byte.
//
// WHY THIS POINT AND NOT ANOTHER
//   * The caller has already materialised every by-value parameter into host
//     memory and built the void** args array before it entered the bridge, so
//     the complete image exists here.
//   * `decode_launch_args` only reads (it memcpys out); it cannot have altered
//     the image. Placing the capture after it therefore still sees the
//     application's own bytes.
//   * The gate's early return and the backend call `fn(...)` both come later.
//     Those are the only two operations in the bridge that could change the
//     representation of the arguments (the backend is free to pack them into
//     its own kernarg buffer, and the caller is free to reuse the stack
//     storage the moment the call returns).
//   * Capturing BEFORE the gate matters in deployment: with the gate OFF -- the
//     only mode this project is authorised to run -- the launch never reaches
//     the backend at all, so nothing downstream of this line can have touched
//     the image. The capture is of bytes that no packing step has seen.
//
// ORDERING GUARANTEE
//   The adapter traces CAPTURE_SITE_REACHED, then either traces a named
//   non-emission outcome or calls raw_dump::emit(). Inside emit() the recorder
//   traces RECORDER_ENTERED before its enable gate, and EMISSION_POINT_REACHED
//   only once the gate has passed and it is about to validate -- so the trace
//   file distinguishes all four states for every arm: "the wired line ran",
//   "the recorder was entered", "the emission point was reached", "nothing
//   happened". A control that cannot show EMISSION_POINT_REACHED is recorded as
//   INVALID_CONTROL, never as a successful rejection.
#pragma once

#include <cstdio>
#include <cstring>

#include "raw_dump_recorder.h"
#include "raw_dump_blob_table.h"

static void raw_dump_at_launch_capture_point(const char* kernel_name,
                                             const void* function_address,
                                             void** args,
                                             unsigned launch_ordinal)
{
    char dir[600];
    if (!raw_dump::out_dir(dir, sizeof(dir))) {
        // Unconfigured: inert, exactly like the bridge's other optional
        // telemetry. No trace, no record, no file.
        return;
    }

    char detail[640];
    std::snprintf(detail, sizeof(detail),
                  "ordinal=%u kernel=\"%s\" function=%p args=%p args0=%p",
                  launch_ordinal, kernel_name ? kernel_name : "?",
                  function_address, (void*)args,
                  (args != nullptr) ? args[0] : nullptr);
    raw_dump::trace("CAPTURE_SITE_REACHED", detail);

    const raw_dump::BlobRow* row = raw_dump::blob_lookup(kernel_name);
    if (row == nullptr) {
        // Not one of the 15 identities whose by-value blob is unread. There is
        // no declared length for it, so there is nothing safe to read.
        raw_dump::trace("NOT_A_TARGET_KERNEL", detail);
        return;
    }
    if (args == nullptr || args[0] == nullptr) {
        // The by-value image was never constructed for this launch. The
        // emission point is NOT reached: this is the mutation-before-the-
        // emission-point control, and it must be recorded as INVALID, not as a
        // rejection.
        raw_dump::trace("REFUSED_NO_BY_VALUE_IMAGE", detail);
        return;
    }

    raw_dump::Request r;
    r.launch_ordinal = launch_ordinal;
    r.kernel_identity = row->identity;
    r.blob = args[0];
    r.blob_length = row->blob_bytes;
    r.requested_offsets = row->offsets;
    r.n_requested_offsets = row->n_offsets;
    raw_dump::emit(r);
}
