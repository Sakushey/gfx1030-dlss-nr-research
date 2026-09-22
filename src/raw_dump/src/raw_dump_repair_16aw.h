// Phase 16AW RAW_DUMP -- THE REPAIRED CAPTURE LAYER.
//
// WHAT WAS WRONG (brief PART VI section 37 and PART VII section 44)
// ----------------------------------------------------------------
// The capture layer this replaces (p16at/raw_dump/src/raw_dump_capture_point.h)
// did, for EVERY identity:
//
//     r.blob = args[0];
//     r.blob_length = row->blob_bytes;
//
// where row->blob_bytes is the identity's WHOLE declared by-value size. That is
// two separate defects:
//
//   * ARGUMENT CAPTURE -- the caller's void** array has ONE ENTRY PER PARAMETER,
//     each pointing at that parameter's own host storage. The entries are not
//     guaranteed to be contiguous. So for an identity whose first host argument
//     is not the by-value one, args[0] is the WRONG argument, and every other
//     argument is never read at all.
//   * FRAME SEMANTICS -- the frame id was minted at k_flag_set and applied
//     retrospectively, so the frame's own launches carried the PREVIOUS frame's
//     number. The authentic launch DB opens a frame at k_flag_wait.
//
// WHAT THIS FILE DOES INSTEAD
// ---------------------------
//   1. ARGUMENT-SPEC TABLE (section 38). Each identity declares its EXPLICIT
//      HOST ARGUMENTS with host_arg_index, byte size, semantic kind, alignment
//      and canonical kernarg offset. The table is GENERATED from the original
//      module's code object metadata by p16aw_author_argspec.py -- this file
//      only consumes it, so the capture cannot invent a layout.
//   2. INDEPENDENT CAPTURE (section 39). For argument i the layer reads the
//      pointer AT args[i] and copies exactly explicit_byte_size bytes from THAT
//      pointer. It NEVER derives the address of args[i+1] from args[i], and
//      NEVER reads past the declared size. For k_flag_set it reads args[0] and
//      args[1] as two separate captures; for k_flag_wait, args[0], args[1] and
//      args[2].
//   3. CANONICAL KERNARG RECORD (section 40). Each captured argument is placed
//      at its canonical explicit-kernarg offset in a RECONSTRUCTION that is
//      labelled, in every record, as a reconstruction and NOT as host-memory
//      adjacency.
//   4. HIDDEN ARGUMENTS (section 41). Runtime-provided arguments are listed with
//      provenance RUNTIME_PROVIDED_NOT_HOST_ARG_ARRAY and captured=false. They
//      are never synthesised into a claim of captured host bytes.
//   5. FRAME STATE MACHINE (sections 45-46). Frames are opened by the validated
//      opener and closed by the validated closer, per stream. An explicit
//      environment-supplied id is a DECLARED_OVERRIDE and is recorded beside the
//      derived interval, never instead of it.
//   6. EVERY INVOCATION INSTANCE (section 48) gets its own record: instance id,
//      frame id and its source, launch ordinal, symbol, per-argument bytes,
//      resource identities.
//
// HOST-ONLY. This file includes the C runtime and a call into <windows.h> only
// for file creation. It imports nothing from any HIP runtime.
#pragma once

#include <cstddef>

namespace rd16aw {

// ------------------------------------------------------------------ mutations
// The whole mutation surface of the control set (brief section 43). Selected at
// run time by RAW_DUMP_16AW_MUTATION so that one build carries all arms, and
// READ BACK into every record and trace line, so an arm whose mutation did not
// take effect reports "NONE" and is recorded INVALID rather than as a rejection.
enum Mutation {
    MUT_NONE = 0,
    MUT_SWAPPED_ARG_INDEX,              // read args[i+1] for argument i
    MUT_WRONG_SIZE,                     // copy size-4 for every aggregate
    MUT_CONTIGUOUS_MEMORY_ASSUMPTION,   // assume args[i+1] lives at args[i]+size
    MUT_OFF_BY_ONE_KERNARG,             // +1 on the canonical destination offset
    MUT_WRONG_POINTER_SCALAR_KIND,      // report a POINTER as a SCALAR
    MUT_OVERREAD_INTO_CANARY,           // copy size+4
    MUT_LEGACY_BLOB_ONLY,               // the code being replaced
    MUT_COUNT
};

const char* mutation_name(Mutation m);
Mutation mutation_from_env();

// ------------------------------------------------------------- frame machine
constexpr const char* kOpenerSymbol = "_Z11k_flag_waitPjjj";
constexpr const char* kCloserSymbol = "_Z10k_flag_setPjj";

constexpr const char* kSrcOpener = "MARKER_K_FLAG_WAIT";
constexpr const char* kSrcOverride = "ENV_OVERRIDE_RAW_DUMP_FRAME_ID";
constexpr const char* kSrcNone = "NO_OPENER_SEEN_YET";
constexpr const char* kProvInferred = "INFERRED_FROM_VALIDATED_EVENT_PROTOCOL";
constexpr const char* kProvDeclared = "DECLARED_OVERRIDE";

struct FrameAssignment {
    unsigned    frame_id;        // 0 == no frame
    const char* source;
    const char* provenance;
    const char* event_role;      // OPENER | CLOSER | WORK
    const char* anomaly;         // nullptr when none
    char        anomaly_detail[192];
};

class FrameMachine {
public:
    FrameMachine();

    // declared_override == 0 means "no environment override". A non-zero value
    // is a DECLARED_OVERRIDE: it is reported as frame_id with provenance
    // DECLARED_OVERRIDE, and the DERIVED interval is reported beside it.
    void reset(long declared_override);
    FrameAssignment on_event(const char* symbol, const void* stream,
                             unsigned launch_ordinal);

    unsigned n_frames_opened() const { return n_opened_; }
    unsigned n_frames_complete() const { return n_complete_; }
    unsigned n_frames_incomplete() const { return n_incomplete_; }
    unsigned n_anatomy_pre_opener() const { return n_pre_opener_; }
    unsigned n_unmatched_closer() const { return n_unmatched_closer_; }
    unsigned n_duplicate_closer() const { return n_duplicate_closer_; }
    unsigned n_post_close_stray() const { return n_post_close_stray_; }
    unsigned n_streams_seen() const { return n_streams_; }
    // Streams whose frame was still open when the event stream ended: an
    // incomplete job is reported, never closed by assumption.
    unsigned n_frames_left_open() const;
    bool     override_active() const { return declared_override_ != 0; }

    // The interval the machine DERIVED for the last event, independent of any
    // declared override. Used to prove the two are never conflated.
    unsigned last_derived_frame_id() const { return last_derived_; }
    unsigned last_derived_source_is_opener() const { return last_derived_src_opener_; }

private:
    struct Slot {
        bool     used;
        unsigned long long sid;
        bool     open;
        bool     closing_seen;
        unsigned frame_id;
    };
    static const unsigned kMaxStreams = 32;
    Slot       slots_[kMaxStreams];
    unsigned   n_streams_;
    unsigned   next_frame_id_;
    unsigned   n_opened_, n_complete_, n_incomplete_, n_pre_opener_;
    unsigned   n_unmatched_closer_, n_duplicate_closer_, n_post_close_stray_;
    unsigned   last_derived_;
    unsigned   last_derived_src_opener_;
    long       declared_override_;
};

void  frame_machine_reset(long declared_override);
FrameMachine& frame_machine();

// --------------------------------------------------------------------- capture
struct CaptureOutcome {
    bool        capture_site_reached;
    bool        emission_point_reached;   // the layer was entered and is emitting
    bool        record_written;
    bool        refused;
    char        reason[224];
    unsigned    instance_seq;
    unsigned    launch_ordinal;
    unsigned    frame_id;
    const char* frame_id_source;
    const char* frame_id_provenance;
    const char* frame_event_role;
    const char* frame_anomaly;
    const char* mutation;                 // "NONE" when no mutation was active
    unsigned    n_explicit_declared;
    unsigned    n_args_captured;
    unsigned    n_args_missing;           // args[i] was null
    unsigned    n_args_dropped;           // never read (the legacy defect)
    unsigned    n_canonical_records;
    unsigned    n_hidden_listed;
    unsigned    n_resource_identities;
    char        record_path[600];
};

// THE CAPTURE POINT. Wired into hipLaunchKernel immediately after
// decode_launch_args(name, args) -- the same statement the defective layer sat
// after, so the two layers are compared on identical bytes.
//
// Returns without touching the disk when out_dir is null or empty: exactly like
// the bridge's other optional telemetry, an unconfigured capture is inert.
CaptureOutcome capture_at_launch_point(const char* identity,
                                       const void* function_address,
                                       void** args,
                                       unsigned launch_ordinal,
                                       const void* stream,
                                       unsigned instance_seq,
                                       const char* out_dir,
                                       Mutation mut);

// The WIRED entry point. It reads RAW_DUMP_DIR itself, mints the process-wide
// instance sequence, and reads the active mutation back from the environment --
// so the injected line into the bridge is a single statement that cannot
// half-configure the capture.
void capture_from_env(const char* identity, const void* function_address,
                      void** args, unsigned launch_ordinal, const void* stream);

// Test-only: the sequence counter, so a driver can predict instance ids.
unsigned instance_seq_value();

// ------------------------------------------------------------------- selftest
struct SelfTestStep {
    const char* name;
    bool        ok;
    char        detail[320];
};
// The layer's OWN checks, in both directions: a known-good table accepted, four
// known-bad tables refused. Returns the number of steps written.
std::size_t self_test(SelfTestStep* steps, std::size_t cap);

}  // namespace rd16aw
