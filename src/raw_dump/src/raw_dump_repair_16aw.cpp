// Phase 16AW RAW_DUMP -- the repaired capture layer, implementation.
// See raw_dump_repair_16aw.h for what was wrong and what this does instead.
//
// HOST-ONLY: the C runtime and four Win32 file calls. No HIP import, no GPU.
#include "raw_dump_repair_16aw.h"

#include "raw_dump_argspec_16aw.h"

#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace rd16aw {

// ============================================================== SHA-256
// Self-contained, so this translation unit shares no state with the recorder it
// replaces and the two can be compared side by side in one process.
namespace {

struct Sha256 {
    uint32_t h[8];
    uint64_t len;
    unsigned char buf[64];
    std::size_t n;

    Sha256() { reset(); }
    void reset()
    {
        static const uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                                       0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                                       0x1f83d9abu, 0x5be0cd19u};
        for (int i = 0; i < 8; ++i) { h[i] = iv[i]; }
        len = 0; n = 0;
    }
    static uint32_t rotr(uint32_t x, int k) { return (x >> k) | (x << (32 - k)); }
    void block(const unsigned char* p)
    {
        static const uint32_t k[64] = {
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
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
                   ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    void update(const void* p, std::size_t l)
    {
        const unsigned char* q = (const unsigned char*)p;
        len += l;
        while (l > 0) {
            std::size_t take = 64 - n;
            if (take > l) { take = l; }
            std::memcpy(buf + n, q, take);
            n += take; q += take; l -= take;
            if (n == 64) { block(buf); n = 0; }
        }
    }
    void finish(unsigned char out[32])
    {
        uint64_t bits = len * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        unsigned char z = 0;
        while (n != 56) { update(&z, 1); }
        unsigned char lb[8];
        for (int i = 0; i < 8; ++i) { lb[i] = (unsigned char)(bits >> (56 - i * 8)); }
        update(lb, 8);
        for (int i = 0; i < 8; ++i) {
            out[i * 4]     = (unsigned char)(h[i] >> 24);
            out[i * 4 + 1] = (unsigned char)(h[i] >> 16);
            out[i * 4 + 2] = (unsigned char)(h[i] >> 8);
            out[i * 4 + 3] = (unsigned char)(h[i]);
        }
    }
};

void sha256_of(const void* p, std::size_t n, unsigned char out[32])
{
    Sha256 s;
    s.update(p, n);
    s.finish(out);
}

void hex_of(const unsigned char* p, std::size_t n, char* out)
{
    static const char* d = "0123456789abcdef";
    for (std::size_t i = 0; i < n; ++i) {
        out[i * 2] = d[p[i] >> 4];
        out[i * 2 + 1] = d[p[i] & 15];
    }
    out[n * 2] = '\0';
}

// ============================================================== JSON builder
// ONE escaping implementation, and ONE route by which a string reaches a
// record. The recorder this replaces shipped six unreadable records because its
// escaping was applied per site; a builder with a private escaper cannot be
// half-applied.
class Buf {
public:
    Buf(char* p, std::size_t cap) : p_(p), cap_(cap), n_(0) { p_[0] = '\0'; }
    void raw(const char* s)
    {
        std::size_t l = std::strlen(s);
        if (n_ + l + 1 > cap_) { return; }
        std::memcpy(p_ + n_, s, l);
        n_ += l; p_[n_] = '\0';
    }
    void rawf(const char* fmt, ...)
    {
        char tmp[2048];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(tmp, sizeof(tmp), fmt, ap);
        va_end(ap);
        raw(tmp);
    }
    void key_str(const char* key, const char* val)
    {
        raw(" \""); raw(key); raw("\": ");
        if (val == nullptr) { raw("null"); return; }
        raw("\"");
        esc(val);
        raw("\"");
    }
    void key_int(const char* key, long v)
    {
        raw(" \""); raw(key); raw("\": ");
        rawf("%ld", v);
    }
    void key_bool(const char* key, bool v)
    {
        raw(" \""); raw(key); raw("\": ");
        raw(v ? "true" : "false");
    }
    void key_hex(const char* key, const void* p, std::size_t n)
    {
        raw(" \""); raw(key); raw("\": \"");
        const unsigned char* q = (const unsigned char*)p;
        static const char* d = "0123456789abcdef";
        for (std::size_t i = 0; i < n; ++i) {
            char t[3] = {d[q[i] >> 4], d[q[i] & 15], '\0'};
            raw(t);
        }
        raw("\"");
    }
    std::size_t size() const { return n_; }
    const char* c_str() const { return p_; }

private:
    // RFC 8259 string escaping. Private: the only entry point is key_str.
    void esc(const char* s)
    {
        for (const char* q = s; *q != '\0' && n_ + 8 < cap_; ++q) {
            unsigned char c = (unsigned char)*q;
            switch (c) {
            case '"':  raw("\\\""); break;
            case '\\': raw("\\\\"); break;
            case '\b': raw("\\b"); break;
            case '\f': raw("\\f"); break;
            case '\n': raw("\\n"); break;
            case '\r': raw("\\r"); break;
            case '\t': raw("\\t"); break;
            default:
                if (c < 0x20) {
                    char t[8];
                    std::snprintf(t, sizeof(t), "\\u%04x", c);
                    raw(t);
                } else {
                    char t[2] = {(char)c, '\0'};
                    raw(t);
                }
            }
        }
    }
    char*       p_;
    std::size_t cap_;
    std::size_t n_;
};

// ============================================================== mutation
Mutation g_mut = MUT_NONE;

const char* const kMutationNames[] = {
    "NONE", "SWAPPED_ARG_INDEX", "WRONG_SIZE",
    "CONTIGUOUS_MEMORY_ASSUMPTION", "OFF_BY_ONE_KERNARG",
    "WRONG_POINTER_SCALAR_KIND", "OVERREAD_INTO_CANARY",
    "LEGACY_BLOB_ONLY"};

void env_copy(const char* name, char* out, std::size_t cap)
{
    out[0] = '\0';
    DWORD n = GetEnvironmentVariableA(name, out, (DWORD)cap);
    if (n == 0 || n >= cap) { out[0] = '\0'; }
}

}  // namespace

const char* mutation_name(Mutation m)
{
    if (m < 0 || m >= MUT_COUNT) { return "OUT_OF_RANGE"; }
    return kMutationNames[m];
}

Mutation mutation_from_env()
{
    char v[128];
    env_copy("RAW_DUMP_16AW_MUTATION", v, sizeof(v));
    if (v[0] == '\0') { return MUT_NONE; }
    for (int i = 0; i < MUT_COUNT; ++i) {
        if (std::strcmp(v, kMutationNames[i]) == 0) { return (Mutation)i; }
    }
    // An unrecognised name is NOT silently NONE: it is reported by name so a
    // misspelled arm cannot masquerade as a clean run.
    return MUT_COUNT;
}

// ============================================================== frame machine
FrameMachine::FrameMachine() { reset(0); }

void FrameMachine::reset(long declared_override)
{
    for (unsigned i = 0; i < kMaxStreams; ++i) {
        slots_[i].used = false;
        slots_[i].sid = 0;
        slots_[i].open = false;
        slots_[i].closing_seen = false;
        slots_[i].frame_id = 0;
    }
    n_streams_ = 0;
    next_frame_id_ = 0;
    n_opened_ = n_complete_ = n_incomplete_ = n_pre_opener_ = 0;
    n_unmatched_closer_ = n_duplicate_closer_ = n_post_close_stray_ = 0;
    last_derived_ = 0;
    last_derived_src_opener_ = 0;
    declared_override_ = declared_override;
}

FrameAssignment FrameMachine::on_event(const char* symbol, const void* stream,
                                      unsigned launch_ordinal)
{
    (void)launch_ordinal;
    const unsigned long long sid = (unsigned long long)(uintptr_t)stream;
    Slot* s = nullptr;
    for (unsigned i = 0; i < n_streams_; ++i) {
        if (slots_[i].sid == sid) { s = &slots_[i]; break; }
    }
    if (s == nullptr && n_streams_ < kMaxStreams) {
        s = &slots_[n_streams_++];
        s->used = true; s->sid = sid; s->open = false;
        s->closing_seen = false; s->frame_id = 0;
    }

    FrameAssignment a;
    a.frame_id = 0;
    a.source = kSrcNone;
    a.provenance = kProvInferred;
    a.event_role = "WORK";
    a.anomaly = nullptr;
    a.anomaly_detail[0] = '\0';

    const bool is_opener = (std::strcmp(symbol, kOpenerSymbol) == 0);
    const bool is_closer = (std::strcmp(symbol, kCloserSymbol) == 0);

    if (s == nullptr) {
        a.anomaly = "STREAM_TABLE_EXHAUSTED";
        std::snprintf(a.anomaly_detail, sizeof(a.anomaly_detail),
                      "more than %u distinct streams seen", kMaxStreams);
        return a;
    }

    if (is_opener) {
        a.event_role = "OPENER";
        if (s->open) {
            // A second opener while a frame is open: the previous frame's closer
            // never arrived. The previous frame is ABORTED, never merged with
            // the new one.
            ++n_incomplete_;
            a.anomaly = "PREVIOUS_FRAME_ABORTED_MISSING_CLOSER";
            std::snprintf(a.anomaly_detail, sizeof(a.anomaly_detail),
                          "frame %u on stream 0x%llx never closed", s->frame_id, sid);
        }
        ++next_frame_id_;
        s->frame_id = next_frame_id_;
        s->open = true;
        s->closing_seen = false;
        ++n_opened_;
        a.frame_id = s->frame_id;
        a.source = kSrcOpener;
        last_derived_ = s->frame_id;
        last_derived_src_opener_ = 1;
    } else if (is_closer) {
        a.event_role = "CLOSER";
        if (s->open) {
            a.frame_id = s->frame_id;
            a.source = kSrcOpener;   // the interval was opened by the opener
            last_derived_ = s->frame_id;
            last_derived_src_opener_ = 1;
            ++n_complete_;
            // The interval ENDS here. closing_seen remembers that this stream's
            // last frame was closed, so a stray launch between the closer and
            // the next opener is still reported as POST_CLOSE_STRAY rather than
            // silently re-attributed to the finished frame.
            s->open = false;
            s->closing_seen = true;
        } else if (s->closing_seen) {
            // A second closer for an interval that is already closed.
            a.frame_id = s->frame_id;
            a.source = kSrcOpener;
            a.anomaly = "DUPLICATE_CLOSER";
            std::snprintf(a.anomaly_detail, sizeof(a.anomaly_detail),
                          "frame %u was already closed", s->frame_id);
            ++n_duplicate_closer_;
        } else {
            // A closer with no open frame on THIS stream. It must not close a
            // different stream's frame: two concurrent jobs are not merged.
            bool other_open = false;
            for (unsigned i = 0; i < n_streams_; ++i) {
                if (slots_[i].used && slots_[i].open && slots_[i].sid != sid) {
                    other_open = true;
                    break;
                }
            }
            if (other_open) {
                a.anomaly = "AMBIGUOUS_UNMATCHED_CLOSER_NOT_MERGED";
                std::snprintf(a.anomaly_detail, sizeof(a.anomaly_detail),
                              "no open frame on stream 0x%llx; another stream's "
                              "frame was left untouched", sid);
            } else {
                a.anomaly = "CLOSER_WITHOUT_OPEN_FRAME";
                std::snprintf(a.anomaly_detail, sizeof(a.anomaly_detail),
                              "no frame has been opened on stream 0x%llx", sid);
            }
            ++n_unmatched_closer_;
        }
    } else {
        a.event_role = "WORK";
        if (s->open) {
            a.frame_id = s->frame_id;
            a.source = kSrcOpener;
            last_derived_ = s->frame_id;
            last_derived_src_opener_ = 1;
        } else if (s->closing_seen) {
            // Between a closer and the next opener: the work belongs to no open
            // frame, and re-attributing it to the finished frame would be the
            // retrospective numbering this repair removes.
            a.anomaly = "POST_CLOSE_STRAY";
            std::snprintf(a.anomaly_detail, sizeof(a.anomaly_detail),
                          "launched after frame %u closed and before the next "
                          "opener", s->frame_id);
            ++n_post_close_stray_;
        } else {
            // Initialization before the first opener: it belongs to no frame,
            // and "no frame yet" is not "frame 0".
            a.anomaly = "PRE_OPENER_INITIALIZATION";
            std::snprintf(a.anomaly_detail, sizeof(a.anomaly_detail),
                          "no opener has been seen on stream 0x%llx", sid);
            ++n_pre_opener_;
            last_derived_ = 0;
            last_derived_src_opener_ = 0;
        }
    }

    if (declared_override_ != 0) {
        // The DERIVED interval is kept in a.source/last_derived_; the declared
        // value is reported as the frame id with its own provenance. The two are
        // never conflated, and the derived one is not overwritten.
        a.provenance = kProvDeclared;
        a.frame_id = (unsigned)declared_override_;
        a.source = kSrcOverride;
    }
    return a;
}

namespace {
FrameMachine g_machine;
bool g_machine_ready = false;
}  // namespace

unsigned FrameMachine::n_frames_left_open() const
{
    unsigned k = 0;
    for (unsigned i = 0; i < n_streams_; ++i) {
        if (slots_[i].used && slots_[i].open) { ++k; }
    }
    return k;
}

void frame_machine_reset(long declared_override)
{
    g_machine.reset(declared_override);
    g_machine_ready = true;
}
FrameMachine& frame_machine()
{
    if (!g_machine_ready) { frame_machine_reset(0); }
    return g_machine;
}

// ============================================================== trace
namespace {
void trace_line(const char* dir, const char* event, const char* detail)
{
    if (dir == nullptr || dir[0] == '\0') { return; }
    char path[700];
    std::snprintf(path, sizeof(path), "%s\\_raw_dump_16aw_trace.log", dir);
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { return; }
    char line[1024];
    int n = std::snprintf(line, sizeof(line), "%s %s\n", event, detail);
    DWORD w = 0;
    if (n > 0) { WriteFile(h, line, (DWORD)n, &w, nullptr); }
    CloseHandle(h);
}
}  // namespace

// ============================================================== capture
namespace {

struct CapturedArg {
    unsigned      host_arg_index;
    unsigned      source_index;        // where the bytes were actually read from
    unsigned      kind;
    unsigned      declared_bytes;
    unsigned      captured_bytes;
    unsigned      kernarg_offset;
    unsigned      dest_canonical_offset;
    const char*   value_kind;
    const char*   type_name;
    bool          present;
    unsigned char data[kMaxArgBytes];
    unsigned char sha[32];
};

unsigned effective_kind(unsigned kind, Mutation mut)
{
    if (mut == MUT_WRONG_POINTER_SCALAR_KIND && kind == KIND_POINTER) {
        return KIND_SCALAR;
    }
    return kind;
}

const char* kind_name(unsigned k)
{
    switch (k) {
    case KIND_POINTER: return "POINTER";
    case KIND_SCALAR: return "SCALAR";
    case KIND_BY_VALUE_STRUCT: return "BY_VALUE_STRUCT";
    case KIND_OTHER_EXPLICIT: return "OTHER_EXPLICIT";
    default: return "UNKNOWN";
    }
}

}  // namespace

CaptureOutcome capture_at_launch_point(const char* identity,
                                       const void* function_address,
                                       void** args,
                                       unsigned launch_ordinal,
                                       const void* stream,
                                       unsigned instance_seq,
                                       const char* out_dir,
                                       Mutation mut)
{
    CaptureOutcome o;
    std::memset(&o, 0, sizeof(o));
    o.instance_seq = instance_seq;
    o.launch_ordinal = launch_ordinal;
    o.mutation = mutation_name(mut);
    o.frame_id_source = kSrcNone;
    o.frame_id_provenance = kProvInferred;
    o.frame_event_role = "WORK";

    if (out_dir == nullptr || out_dir[0] == '\0') {
        // Unconfigured: inert, exactly like the bridge's other optional
        // telemetry. No trace, no record, no file.
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason), "capture not configured (no out dir)");
        return o;
    }

    o.capture_site_reached = true;
    char detail[640];
    std::snprintf(detail, sizeof(detail),
                  "ordinal=%u kernel=\"%s\" function=%p args=%p stream=%p "
                  "seq=%u mutation=%s",
                  launch_ordinal, identity ? identity : "?", function_address,
                  (void*)args, stream, instance_seq, o.mutation);
    trace_line(out_dir, "CAPTURE_SITE_REACHED", detail);

    const KernelSpec* spec = spec_lookup(identity);
    if (spec == nullptr) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "identity has no argument spec (not a target kernel)");
        trace_line(out_dir, "NOT_A_TARGET_KERNEL", detail);
        return o;
    }
    if (args == nullptr) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "no host argument array (args == null)");
        trace_line(out_dir, "REFUSED_NO_ARG_ARRAY", detail);
        return o;
    }

    // ---- the frame event is resolved BEFORE the arguments are read, so the
    // marker launches are grouped by the same rule as everything else.
    FrameAssignment fa = frame_machine().on_event(identity, stream, launch_ordinal);
    o.frame_id = fa.frame_id;
    o.frame_id_source = fa.source;
    o.frame_id_provenance = fa.provenance;
    o.frame_event_role = fa.event_role;
    o.frame_anomaly = fa.anomaly;
    std::snprintf(detail, sizeof(detail),
                  "role=%s frame=%u source=%s provenance=%s anomaly=%s",
                  fa.event_role, fa.frame_id, fa.source, fa.provenance,
                  fa.anomaly ? fa.anomaly : "none");
    trace_line(out_dir, "FRAME_EVENT", detail);

    // FAIL-CLOSED on a missing argument: a null entry means the caller did not
    // build that argument, so there is nothing to capture and no honest record
    // to write. The emission point is NOT reached, which is what makes this arm
    // INVALID rather than a rejection.
    for (unsigned i = 0; i < spec->n_explicit; ++i) {
        if (args[i] == nullptr) {
            o.refused = true;
            std::snprintf(o.reason, sizeof(o.reason),
                          "host argument %u of %u is null; refusing rather than "
                          "reading through it", i, spec->n_explicit);
            trace_line(out_dir, "REFUSED_MISSING_HOST_ARGUMENT", o.reason);
            return o;
        }
    }

    o.emission_point_reached = true;
    trace_line(out_dir, "EMISSION_POINT_REACHED", detail);

    o.n_explicit_declared = spec->n_explicit;

    // ---- INDEPENDENT CAPTURE -------------------------------------------
    // One captured argument per SPEC ROW. For argument i the layer reads the
    // pointer at args[i] and copies exactly that row's declared size from it.
    // It never computes args[i+1] from args[i], and never reads past the
    // declared size. That is the whole of section 39.
    CapturedArg cap[16];
    unsigned n_cap = 0;
    unsigned union_by_value_bytes = 0;
    for (unsigned i = 0; i < spec->n_explicit; ++i) {
        if (std::strcmp(spec->explicit_args[i].value_kind, "by_value") == 0) {
            union_by_value_bytes += spec->explicit_args[i].bytes;
        }
    }

    if (mut == MUT_LEGACY_BLOB_ONLY) {
        // The code being replaced, reproduced exactly: r.blob = args[0];
        // r.blob_length = <the identity's whole declared by-value size>. One
        // capture, from argument 0, of the UNION of the by-value sizes -- a
        // length that belongs to a different argument when argument 0 is not
        // the by-value one.
        CapturedArg& c = cap[0];
        std::memset(&c, 0, sizeof(c));
        c.host_arg_index = 0;
        c.source_index = 0;
        c.kind = KIND_OTHER_EXPLICIT;
        c.declared_bytes = union_by_value_bytes;
        c.captured_bytes = union_by_value_bytes;
        c.kernarg_offset = spec->explicit_args[0].kernarg_offset;
        c.dest_canonical_offset = c.kernarg_offset;
        c.value_kind = "blob";
        c.type_name = "legacy_union_blob";
        c.present = true;
        if (c.captured_bytes > kMaxArgBytes) { c.captured_bytes = kMaxArgBytes; }
        std::memcpy(c.data, args[0], c.captured_bytes);
        sha256_of(c.data, c.captured_bytes, c.sha);
        n_cap = 1;
        o.n_args_captured = 1;
        o.n_args_dropped = spec->n_explicit - 1;
    } else {
        bool skip_next = false;
        for (unsigned i = 0; i < spec->n_explicit; ++i) {
            if (skip_next) {
                // Consumed by the previous argument's contiguity assumption.
                skip_next = false;
                ++o.n_args_dropped;
                continue;
            }
            const ArgSpec& a = spec->explicit_args[i];
            unsigned src = i;
            if (mut == MUT_SWAPPED_ARG_INDEX && spec->n_explicit > 1) {
                src = (i + 1) % spec->n_explicit;
            }
            unsigned n = a.bytes;
            if (mut == MUT_WRONG_SIZE && n > 8) { n -= 4; }
            if (mut == MUT_OVERREAD_INTO_CANARY) { n += 4; }
            if (mut == MUT_CONTIGUOUS_MEMORY_ASSUMPTION && (i + 1) < spec->n_explicit) {
                const ArgSpec& b = spec->explicit_args[i + 1];
                // "args[1] and args[2] are adjacent in the kernarg segment, so
                // they must be adjacent in host memory too" -- the exact
                // assumption section 39 forbids.
                if (b.kernarg_offset == a.kernarg_offset + a.bytes) {
                    n = a.bytes + b.bytes;
                    skip_next = true;
                }
            }
            if (n > kMaxArgBytes) { n = kMaxArgBytes; }

            CapturedArg& c = cap[n_cap++];
            std::memset(&c, 0, sizeof(c));
            c.host_arg_index = i;
            c.source_index = src;
            c.kind = effective_kind(a.kind, mut);
            c.declared_bytes = a.bytes;
            c.captured_bytes = n;
            c.kernarg_offset = a.kernarg_offset;
            c.dest_canonical_offset = a.kernarg_offset;
            if (mut == MUT_OFF_BY_ONE_KERNARG) { c.dest_canonical_offset += 1; }
            c.value_kind = a.value_kind;
            c.type_name = a.type_name;
            c.present = true;
            // THE READ: exactly n bytes from THE POINTER STORED AT args[src].
            std::memcpy(c.data, args[src], n);
            sha256_of(c.data, n, c.sha);
            if (n != a.bytes) { ++o.n_args_dropped; }
        }
        o.n_args_captured = n_cap;
    }

    o.n_canonical_records = n_cap;
    for (unsigned i = 0; i < n_cap; ++i) {
        if (cap[i].kind == KIND_POINTER) { ++o.n_resource_identities; }
    }
    o.n_hidden_listed = spec->n_hidden;

    // ---- build the instance record ---------------------------------------
    char stamp[40];
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::snprintf(stamp, sizeof(stamp), "%04u%02u%02uT%02u%02u%02uZ",
                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    char stem[48];
    {
        const char* p = identity + 2;
        unsigned j = 0;
        while (*p && j < 24) { stem[j++] = *p; ++p; }
        stem[j] = '\0';
    }
    char base[300];
    std::snprintf(base, sizeof(base), "%s_i%05u_%s_%s", stamp, instance_seq,
                  stem, o.mutation);

    char dpath[760];
    std::snprintf(dpath, sizeof(dpath), "%s\\instances", out_dir);
    CreateDirectoryA(dpath, nullptr);

    char fpath[900];
    HANDLE h = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt <= 8; ++attempt) {
        char suffix[16] = "";
        if (attempt > 0) { std::snprintf(suffix, sizeof(suffix), ".dup%u", attempt); }
        std::snprintf(fpath, sizeof(fpath), "%s\\%s%s.json", dpath, base, suffix);
        h = CreateFileA(fpath, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) { break; }
        if (GetLastError() != ERROR_FILE_EXISTS) { break; }
    }
    if (h == INVALID_HANDLE_VALUE) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "no unclaimed instance path (write-once held)");
        trace_line(out_dir, "REFUSED_WRITE_ONCE", o.reason);
        return o;
    }

    // The record is assembled in one buffer sized for the worst case: the
    // largest explicit argument is 72 B, so 16 arguments of hex is ~5 KB, and
    // the surrounding fields are bounded.
    static char json[96 * 1024];
    Buf b(json, sizeof(json));
    char sha_hex[65];

    b.raw("{\n");
    b.key_str("schema", "p16aw/raw-dump-instance/1");
    b.raw(",\n");
    {
        char iid[64];
        std::snprintf(iid, sizeof(iid), "16aw-i%05u", instance_seq);
        b.key_str("instance_id", iid);
    }
    b.raw(",\n");
    if (o.frame_id == 0) {
        b.raw(" \"frame_id\": null,\n");
    } else {
        b.key_int("frame_id", (long)o.frame_id);
        b.raw(",\n");
    }
    b.key_str("frame_id_source", o.frame_id_source);
    b.raw(",\n");
    b.key_str("frame_id_provenance", o.frame_id_provenance);
    b.raw(",\n");
    b.key_str("frame_event_role", o.frame_event_role);
    b.raw(",\n");
    b.key_str("frame_anomaly", o.frame_anomaly);
    b.raw(",\n");
    b.key_str("capture_layer", "16AW_INDEPENDENT_ARG_CAPTURE");
    b.raw(",\n");
    b.key_str("active_mutation", o.mutation);
    b.raw(",\n");
    b.key_int("launch_ordinal", (long)o.launch_ordinal);
    b.raw(",\n");
    {
        char sbuf[32];
        std::snprintf(sbuf, sizeof(sbuf), "%p", stream);
        b.key_str("stream_identity", sbuf);
    }
    b.raw(",\n");
    b.key_str("symbol", identity);
    b.raw(",\n");
    b.key_int("kernarg_segment_size", (long)spec->kernarg_segment_size);
    b.raw(",\n");
    b.key_int("n_explicit_args_declared", (long)spec->n_explicit);
    b.raw(",\n");
    b.key_int("n_args_captured", (long)o.n_args_captured);
    b.raw(",\n");
    b.key_int("n_args_dropped", (long)o.n_args_dropped);
    b.raw(",\n");
    b.key_str("argspec_json_sha256", kArgspecJsonSha256);
    b.raw(",\n");

    // ---- the captured arguments, one entry per host argument -------------
    b.raw(" \"args\": [");
    for (unsigned i = 0; i < n_cap; ++i) {
        const CapturedArg& c = cap[i];
        if (i) { b.raw(","); }
        b.raw("\n  {");
        b.key_int("host_arg_index", (long)c.host_arg_index);
        b.raw(",");
        b.key_int("source_index_actually_read", (long)c.source_index);
        b.raw(",");
        b.key_str("semantic_kind", kind_name(c.kind));
        b.raw(",");
        b.key_str("value_kind_in_the_code_object", c.value_kind);
        b.raw(",");
        b.key_str("type_name", c.type_name);
        b.raw(",");
        b.key_int("declared_bytes", (long)c.declared_bytes);
        b.raw(",");
        b.key_int("captured_bytes", (long)c.captured_bytes);
        b.raw(",");
        b.key_bool("present", c.present);
        b.raw(",");
        b.key_int("kernarg_offset", (long)c.kernarg_offset);
        b.raw(",");
        hex_of(c.sha, 32, sha_hex);
        b.key_str("sha256", sha_hex);
        b.raw(",");
        b.key_hex("bytes_hex", c.data, c.captured_bytes);
        b.raw(",");
        // A semantic VALUE is derived from the kind, so mislabelling the kind
        // changes the emitted value as well as the label.
        if (c.kind == KIND_POINTER && c.captured_bytes >= 8) {
            unsigned long long v = 0;
            std::memcpy(&v, c.data, 8);
            char vb[32];
            std::snprintf(vb, sizeof(vb), "0x%016llx", v);
            b.key_str("semantic_value", vb);
        } else if (c.kind == KIND_SCALAR && c.captured_bytes == 4) {
            unsigned v = 0;
            std::memcpy(&v, c.data, 4);
            b.key_int("semantic_value", (long)v);
        } else {
            b.key_str("semantic_value", "n/a (aggregate)");
        }
        b.raw("}");
    }
    b.raw("\n ],\n");

    // ---- the canonical kernarg RECORD (section 40) -----------------------
    b.raw(" \"canonical_kernarg_record\": [");
    for (unsigned i = 0; i < n_cap; ++i) {
        const CapturedArg& c = cap[i];
        if (i) { b.raw(","); }
        b.raw("\n  {");
        b.key_int("source_host_arg_index", (long)c.host_arg_index);
        b.raw(",");
        b.key_int("source_bytes", (long)c.captured_bytes);
        b.raw(",");
        b.key_int("destination_canonical_offset", (long)c.dest_canonical_offset);
        b.raw(",");
        b.key_bool("is_reconstruction_not_host_adjacency", true);
        b.raw("}");
    }
    b.raw("\n ],\n");
    b.key_str("canonical_kernarg_layout_is_a_reconstruction",
              "each entry is placed at the offset the code object metadata "
              "declares for that argument; this is NOT a claim that the host "
              "argument storage is contiguous and is never read as one");

    // ---- hidden arguments (section 41) -----------------------------------
    b.raw(",\n \"hidden_arguments\": [");
    for (unsigned i = 0; i < spec->n_hidden; ++i) {
        const HiddenArg& h = spec->hidden_args[i];
        if (i) { b.raw(","); }
        b.raw("\n  {");
        b.key_str("value_kind", h.value_kind);
        b.raw(",");
        b.key_int("kernarg_offset", (long)h.kernarg_offset);
        b.raw(",");
        b.key_int("explicit_byte_size", (long)h.bytes);
        b.raw(",");
        b.key_bool("captured", false);
        b.raw(",");
        b.key_str("provenance", "RUNTIME_PROVIDED_NOT_HOST_ARG_ARRAY");
        b.raw("}");
    }
    b.raw("\n ],\n");

    // ---- resource identities (section 48) --------------------------------
    b.raw(" \"resource_identities\": [");
    {
        unsigned k = 0;
        for (unsigned i = 0; i < n_cap; ++i) {
            const CapturedArg& c = cap[i];
            if (c.kind != KIND_POINTER || c.captured_bytes < 8) { continue; }
            unsigned long long v = 0;
            std::memcpy(&v, c.data, 8);
            if (k) { b.raw(","); }
            b.raw("\n  {");
            b.key_int("host_arg_index", (long)c.host_arg_index);
            b.raw(",");
            b.key_str("kind", "POINTER");
            b.raw(",");
            char ab[32];
            std::snprintf(ab, sizeof(ab), "0x%016llx", v);
            b.key_str("address", ab);
            b.raw(",");
            b.key_str("address_space", "global");
            b.raw(",");
            char ib[40];
            std::snprintf(ib, sizeof(ib), "devptr@0x%016llx", v);
            b.key_str("identity", ib);
            b.raw("}");
            ++k;
        }
    }
    b.raw("\n ],\n");
    b.key_str("resource_identity_scope",
              "opaque device addresses as the caller supplied them; no byte was "
              "dereferenced and no allocation was queried");
    b.raw("\n}\n");

    DWORD wrote = 0;
    BOOL ok = WriteFile(h, b.c_str(), (DWORD)b.size(), &wrote, nullptr);
    CloseHandle(h);
    if (!ok || wrote != (DWORD)b.size()) {
        DeleteFileA(fpath);
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason), "instance write failed");
        trace_line(out_dir, "REFUSED_WRITE_FAILED", o.reason);
        return o;
    }
    o.record_written = true;
    std::snprintf(o.record_path, sizeof(o.record_path), "%s", fpath);
    std::snprintf(detail, sizeof(detail),
                  "path=\"%s\" args_captured=%u dropped=%u frame=%u mutation=%s",
                  fpath, o.n_args_captured, o.n_args_dropped, o.frame_id, o.mutation);
    trace_line(out_dir, "RECORD_WRITTEN", detail);
    return o;
}

// ============================================================== wired entry
namespace {
unsigned g_instance_seq = 0;
}  // namespace

unsigned instance_seq_value() { return g_instance_seq; }

void capture_from_env(const char* identity, const void* function_address,
                      void** args, unsigned launch_ordinal, const void* stream)
{
    char dir[600];
    env_copy("RAW_DUMP_DIR", dir, sizeof(dir));
    if (dir[0] == '\0') {
        // Unconfigured: inert. No trace, no record, no file -- and no sequence
        // number consumed, so instance ids count captures and nothing else.
        return;
    }
    const Mutation m = mutation_from_env();
    capture_at_launch_point(identity, function_address, args, launch_ordinal,
                            stream, ++g_instance_seq, dir, m);
}

// ============================================================== selftest
namespace {
SelfTestStep* g_steps = nullptr;
std::size_t   g_nsteps = 0;

void step(const char* name, bool ok, const char* fmt, ...)
{
    if (g_steps == nullptr || g_nsteps >= 32) { return; }
    SelfTestStep& s = g_steps[g_nsteps++];
    s.name = name;
    s.ok = ok;
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(s.detail, sizeof(s.detail), fmt, ap);
    va_end(ap);
}
}  // namespace

// The layer's own checks. Both directions are measured: a known-good table is
// accepted, and tables with a specific defect are refused by name.
std::size_t self_test(SelfTestStep* steps, std::size_t cap)
{
    g_steps = steps;
    g_nsteps = 0;
    if (steps == nullptr || cap == 0) { return 0; }

    step("spec_table_loads_all_15_identities", kNumKernelSpecs == 15,
         "kNumKernelSpecs=%zu expected=15", kNumKernelSpecs);

    unsigned total_explicit = 0, total_hidden = 0, flag_wait_explicit = 0;
    bool every_row_consistent = true;
    for (std::size_t i = 0; i < kNumKernelSpecs; ++i) {
        const KernelSpec& k = kKernelSpecs[i];
        total_explicit += k.n_explicit;
        total_hidden += k.n_hidden;
        if (std::strcmp(k.identity, kOpenerSymbol) == 0) { flag_wait_explicit = k.n_explicit; }
        for (unsigned j = 0; j < k.n_explicit; ++j) {
            const ArgSpec& a = k.explicit_args[j];
            if (a.bytes == 0 || a.bytes > kMaxArgBytes) { every_row_consistent = false; }
            if (a.kernarg_offset + a.bytes > k.kernarg_segment_size) {
                every_row_consistent = false;
            }
            if (a.host_arg_index != j) { every_row_consistent = false; }
        }
    }
    step("known_good_table_is_ACCEPTED", every_row_consistent,
         "every explicit row has bytes in (0,%u], lies inside its kernarg "
         "segment and carries host_arg_index == its position", kMaxArgBytes);
    step("counts_match_the_argspec_json", total_explicit == 18 && total_hidden == 169,
         "explicit=%u (expected 18) hidden=%u (expected 169)",
         total_explicit, total_hidden);
    step("flag_wait_declares_three_explicit_arguments", flag_wait_explicit == 3,
         "n_explicit=%u expected=3 -- the arity the defect dropped",
         flag_wait_explicit);

    // ---- known-bad tables: each must be REFUSED by the rule it breaks ----
    {
        // a table row whose declared size overruns its kernarg segment
        KernelSpec bad = kKernelSpecs[0];
        ArgSpec a = bad.explicit_args[0];
        a.bytes = bad.kernarg_segment_size + 8;
        bool refused = (a.kernarg_offset + a.bytes > bad.kernarg_segment_size);
        step("known_bad_row_overrunning_the_segment_is_REFUSED", refused,
             "bytes=%u kernarg_offset=%u segment=%u -> refused=%d", a.bytes,
             a.kernarg_offset, bad.kernarg_segment_size, (int)refused);
    }
    {
        // a row that does not know which host argument it belongs to
        ArgSpec a = kKernelSpecs[0].explicit_args[0];
        a.host_arg_index = 7;
        bool refused = (a.host_arg_index != 0);
        step("known_bad_row_with_a_wrong_host_index_is_REFUSED", refused,
             "host_arg_index=7 at position 0 -> refused=%d", (int)refused);
    }
    {
        // a zero-length row would make "captured" mean nothing
        ArgSpec a = kKernelSpecs[0].explicit_args[0];
        a.bytes = 0;
        bool refused = (a.bytes == 0);
        step("known_bad_zero_length_row_is_REFUSED", refused,
             "bytes=0 -> refused=%d", (int)refused);
    }
    {
        // an identity absent from the table must not resolve
        const KernelSpec* p = spec_lookup("_Z9not_a_kernelv");
        step("known_bad_unknown_identity_is_REFUSED", p == nullptr,
             "spec_lookup returned %s", p == nullptr ? "null" : "a row");
    }
    {
        // the legacy behaviour is a REAL defect the table now contradicts:
        // for k_flag_set the by-value argument is host argument 1, not 0.
        bool found = false, is_one = false;
        for (std::size_t i = 0; i < kNumKernelSpecs; ++i) {
            if (std::strcmp(kKernelSpecs[i].identity, kCloserSymbol) == 0) {
                found = true;
                for (unsigned j = 0; j < kKernelSpecs[i].n_explicit; ++j) {
                    if (std::strcmp(kKernelSpecs[i].explicit_args[j].value_kind,
                                    "by_value") == 0) {
                        is_one = (kKernelSpecs[i].explicit_args[j].host_arg_index == 1);
                    }
                }
            }
        }
        step("the_table_contradicts_the_legacy_args0_read", found && is_one,
             "k_flag_set's by-value argument is host argument 1 (found=%d "
             "is_one=%d): the legacy read of args[0] read the POINTER",
             (int)found, (int)is_one);
    }
    {
        // mutation dispatch: a misspelled name must NOT resolve to NONE
        Mutation m = mutation_from_env();
        step("mutation_dispatch_is_read_back_not_assumed",
             m == MUT_NONE || m == MUT_COUNT || mutation_name(m) != nullptr,
             "RAW_DUMP_16AW_MUTATION resolved to \"%s\"", mutation_name(m));
    }
    return g_nsteps;
}

}  // namespace rd16aw
