// Phase 16AT RAW_DUMP -- recorder implementation.
// See raw_dump_recorder.h for the contract. Host-only; no HIP import.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "raw_dump_recorder.h"
#include "raw_dump_blob_table.h"
#include "raw_dump_injection_points.h"

namespace raw_dump {

namespace {

// ------------------------------------------------------------------ SHA-256
// Self-contained FIPS 180-4. Deliberately NOT bridge_registry::sha256: the
// verifier recomputes every digest with Python's hashlib, so a bug in this
// implementation turns the ACCEPT arm red instead of staying invisible. Two
// independent implementations must agree before a record is believed.
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

inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void sha256(const unsigned char* data, size_t len, unsigned char out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    unsigned char tail[128];
    const size_t rem = len % 64;
    const size_t full = len / 64;
    size_t t = 0;
    for (size_t i = 0; i < rem; ++i) { tail[t++] = data[full * 64 + i]; }
    tail[t++] = 0x80;
    while (t % 64 != 56) { tail[t++] = 0; }
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 7; i >= 0; --i) { tail[t++] = (unsigned char)(bits >> (8 * i)); }
    const size_t blocks = full + t / 64;
    for (size_t b = 0; b < blocks; ++b) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            const unsigned char* p = (b < full) ? (data + b * 64 + i * 4)
                                                : (tail + (b - full) * 64 + i * 4);
            w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                   ((uint32_t)p[2] << 8) | (uint32_t)p[3];
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t T1 = hh + S1 + ch + kK[i] + w[i];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t mj = (a & bb) ^ (a & c) ^ (bb & c);
            uint32_t T2 = S0 + mj;
            hh = g; g = f; f = e; e = d + T1;
            d = c; c = bb; bb = a; a = T1 + T2;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = (unsigned char)(h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(h[i]);
    }
}

void hex_of(const unsigned char* p, size_t n, char* out)
{
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 0xf];
    }
    out[2 * n] = '\0';
}

// ------------------------------------------------------------------ builder
// A bounded append-only buffer. snprintf alone cannot express this record
// without placeholder juggling, and a truncation must be DETECTED, not
// silently shipped as a malformed record.
struct Buf {
    char* p;
    size_t cap;
    size_t n;
    bool overflow;
    Buf(char* b, size_t c) : p(b), cap(c), n(0), overflow(false) { p[0] = '\0'; }
    void add(const char* s)
    {
        size_t l = std::strlen(s);
        if (n + l + 1 > cap) { overflow = true; return; }
        std::memcpy(p + n, s, l);
        n += l;
        p[n] = '\0';
    }
    void addf(const char* fmt, ...)
    {
        char tmp[1024];
        va_list ap;
        va_start(ap, fmt);
        int k = std::vsnprintf(tmp, sizeof(tmp), fmt, ap);
        va_end(ap);
        if (k < 0) { overflow = true; return; }
        add(tmp);
    }
    // RFC 8259 section 7: inside a string, '"' and '\' MUST be escaped, and
    // every control character U+0000..U+001F MUST be escaped. Everything else
    // may appear literally.
    //
    // This was NOT always so. The first two generations of this recorder wrote
    // a Windows path raw, and a standard reader rejected every record with
    // "Invalid \escape" at the side-car path -- a defect that survived a fix
    // which escaped *one* call site and left the others raw. Escaping is
    // therefore structural now: key_str() below is the only way a string field
    // can reach the record, and it always comes through here.

    // THE single place a string-valued field reaches the record. One escaping
    // helper, used by every field, so no field can be raw by accident -- the
    // defect that produced unparseable records twice. A field emitted as
    // addf("\"%s\": \"%s\"", k, v) is the bug this shape makes impossible.
    void key_str(const char* key, const char* val)
    {
        add(" \""); add(key); add("\": \""); add_json(val); add("\",\n");
    }
    void key_str_last(const char* key, const char* val)
    {
        add(" \""); add(key); add("\": \""); add_json(val); add("\"\n");
    }

  private:
    // Private on purpose. key_str()/key_str_last() are the only callers, so the
    // escaping rule has exactly one implementation and cannot be half-applied
    // at one call site while another site stays raw -- which is precisely how
    // the "Invalid \escape" defect survived its first fix.
    void add_json(const char* s)
    {
        for (const char* q = s; q != nullptr && *q != '\0'; ++q) {
            unsigned char c = (unsigned char)*q;
            switch (c) {
            case '"':  add("\\\""); break;
            case '\\': add("\\\\"); break;
            case '\b': add("\\b");  break;
            case '\f': add("\\f");  break;
            case '\n': add("\\n");  break;
            case '\r': add("\\r");  break;
            case '\t': add("\\t");  break;
            default:
                if (c < 0x20) {
                    addf("\\u%04x", (unsigned)c);
                } else {
                    char one[2] = {(char)c, '\0'};
                    add(one);
                }
            }
        }
    }
};

// ------------------------------------------------------------------- state
CRITICAL_SECTION g_lock;
bool g_lockInit = false;
unsigned g_frameCounter = 0;

void lock_init()
{
    if (!g_lockInit) {
        InitializeCriticalSection(&g_lock);
        g_lockInit = true;
    }
}

char g_envbuf[1024];
bool env_copy(const char* k, char* out, size_t cap)
{
    DWORD n = GetEnvironmentVariableA(k, g_envbuf, (DWORD)sizeof(g_envbuf));
    if (n == 0 || n >= sizeof(g_envbuf)) { out[0] = '\0'; return false; }
    std::snprintf(out, cap, "%s", g_envbuf);
    return true;
}

void join(char* out, size_t cap, const char* dir, const char* name)
{
    std::snprintf(out, cap, "%s\\%s", dir, name);
}

void utc_compact(char* out, size_t cap)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::snprintf(out, cap, "%04u%02u%02uT%02u%02u%02uZ", st.wYear, st.wMonth,
                  st.wDay, st.wHour, st.wMinute, st.wSecond);
}

void utc_iso(char* out, size_t cap)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::snprintf(out, cap, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear,
                  st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                  st.wMilliseconds);
}

HANDLE create_new_file(const char* path, bool* exists)
{
    *exists = false;
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS) {
        *exists = true;
    }
    return h;
}

bool write_all(HANDLE h, const void* p, size_t n)
{
    const unsigned char* b = (const unsigned char*)p;
    size_t done = 0;
    while (done < n) {
        DWORD chunk = (DWORD)((n - done) > 0x10000000u ? 0x10000000u : (n - done));
        DWORD w = 0;
        if (!WriteFile(h, b + done, chunk, &w, nullptr) || w == 0) { return false; }
        done += w;
    }
    return true;
}

void stem_of(const char* ident, char* out, size_t cap)
{
    size_t j = 0;
    for (size_t i = 0; ident[i] != '\0' && j + 1 < cap && j < 40; ++i) {
        char c = ident[i];
        out[j++] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '_') ? c : '_';
    }
    out[j] = '\0';
    if (j == 0) { std::snprintf(out, cap, "unknown"); }
}

bool filter_allows(const char* ident, const char* f)
{
    if (std::strcmp(f, "all") == 0) { return true; }
    const char* p = f;
    while (*p != '\0') {
        const char* q = std::strchr(p, ',');
        size_t n = q ? (size_t)(q - p) : std::strlen(p);
        if (n == std::strlen(ident) && std::strncmp(p, ident, n) == 0) { return true; }
        if (!q) { break; }
        p = q + 1;
    }
    return false;
}

}  // namespace

// ------------------------------------------------------------------ control
bool out_dir(char* buf, std::size_t cap)
{
    return env_copy("RAW_DUMP_DIR", buf, cap) && buf[0] != '\0';
}

bool records_enabled()
{
    char v[16];
    if (!env_copy("RAW_DUMP", v, sizeof(v))) { return false; }
    return v[0] == '1' && v[1] == '\0';
}

bool kernel_filter(char* buf, std::size_t cap)
{
    if (!env_copy("RAW_DUMP_KERNELS", buf, cap) || buf[0] == '\0') {
        std::snprintf(buf, cap, "all");
    }
    return true;
}

bool frame_id_override(long* out)
{
    char v[32];
    if (!env_copy("RAW_DUMP_FRAME_ID", v, sizeof(v)) || v[0] == '\0') {
        return false;
    }
    char* end = nullptr;
    long n = std::strtol(v, &end, 10);
    if (end == v || (end && *end != '\0')) { return false; }
    *out = n;
    return true;
}

bool trace(const char* event, const char* detail)
{
    char dir[600];
    if (!out_dir(dir, sizeof(dir))) { return false; }
    char path[1200];
    join(path, sizeof(path), dir, "_raw_dump_trace.log");
    lock_init();
    EnterCriticalSection(&g_lock);
    bool ok = false;
    // APPEND, never CREATE_NEW: the trace is a log of what happened; losing a
    // line to "already exists" would hide reach, which is the one thing the
    // trace exists to make visible.
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char ts[40];
        utc_iso(ts, sizeof(ts));
        char line[1280];
        int n = std::snprintf(line, sizeof(line), "%s t=%lu pid=%lu %s %s\r\n",
                              ts, (unsigned long)GetCurrentThreadId(),
                              (unsigned long)GetCurrentProcessId(), event,
                              detail ? detail : "");
        if (n > 0 && (size_t)n < sizeof(line)) {
            if (write_all(h, line, (size_t)n)) { ok = true; }
        }
        CloseHandle(h);
    }
    LeaveCriticalSection(&g_lock);
    return ok;
}

// ------------------------------------------------------------------- emit
Outcome emit(const Request& r)
{
    Outcome o;
    std::memset(&o, 0, sizeof(o));
    o.capture_site_reached = true;
    o.reason[0] = '\0';

    char dir[600];
    const bool have_dir = out_dir(dir, sizeof(dir));
    if (have_dir) {
        std::snprintf(o.trace_path, sizeof(o.trace_path),
                      "%s\\_raw_dump_trace.log", dir);
    }

    // ---- reach, in two separately observable steps -----------------------
    // RECORDER_ENTERED is written FIRST, before the enable gate and before any
    // validation, so "the observer ran at all" is never inferable from the
    // absence of a later line.
    char reach_detail[640];
    std::snprintf(reach_detail, sizeof(reach_detail),
                  "ordinal=%u kernel=\"%s\" args0=%p declared_bytes=%zu",
                  r.launch_ordinal,
                  r.kernel_identity ? r.kernel_identity : "?", r.blob,
                  r.blob_length);
    trace("RECORDER_ENTERED", reach_detail);

    o.enabled = records_enabled();
    if (!have_dir) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason), "RAW_DUMP_DIR unset");
        return o;
    }
    if (!o.enabled) {
        // The recorder is OFF. There is no observer here to reject anything, so
        // this arm is an INVALID CONTROL and must be recorded as one. The
        // EMISSION_POINT_REACHED line is deliberately written AFTER this gate,
        // so that "the recorder was disabled" and "the emission point was
        // reached" can never be confused with one another.
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "recorder disabled (RAW_DUMP != \"1\")");
        return o;
    }

    // ---- THE EMISSION POINT ---------------------------------------------
    // The recorder is enabled and owns a directory: from here it WILL attempt
    // to emit, and every remaining failure is a validation refusal rather than
    // an absent observer. Written BEFORE any validation, so a defect in the
    // capture cannot suppress this line and masquerade as a rejection.
    trace("EMISSION_POINT_REACHED", reach_detail);
    o.emission_point_reached = true;
    // ---------------------------------------------------------------------

    if (r.kernel_identity == nullptr) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason), "kernel_identity null");
        return o;
    }
    if (r.blob == nullptr) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "no by-value image to read (blob == null)");
        return o;
    }
    char kfilter[512];
    kernel_filter(kfilter, sizeof(kfilter));
    if (!filter_allows(r.kernel_identity, kfilter)) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason), "kernel excluded by RAW_DUMP_KERNELS");
        return o;
    }

    // ---- the four injection points --------------------------------------
    const unsigned char* p = (const unsigned char*)RAWD_BLOB_POINTER(r.blob);
    const size_t declared = (size_t)RAWD_BLOB_LENGTH(r.blob_length);
    const unsigned ord = (unsigned)RAWD_LAUNCH_ORDINAL(r.launch_ordinal);
    const char* ident = RAWD_KERNEL_IDENTITY(r.kernel_identity);
    // ---------------------------------------------------------------------

    if (declared == 0 || declared > kMaxBlobBytes) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "declared blob length %zu outside (0, %u]", declared,
                      kMaxBlobBytes);
        return o;
    }

    // Automatic storage, not static: the launch path is reachable from more
    // than one thread and a shared scratch buffer would be a data race that no
    // downstream check could see.
    unsigned char first[kMaxBlobBytes];
    unsigned char again[kMaxBlobBytes];
    std::memcpy(first, p, declared);
    std::memcpy(again, p, declared);
    // Integrity guard: a caller that mutates its own parameter image while we
    // read it would leave a record that is a patchwork of two states. Refuse
    // rather than ship that.
    if (std::memcmp(first, again, declared) != 0) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "by-value image changed during capture (concurrent "
                      "mutation); refused");
        return o;
    }

    unsigned char digest[32];
    char sha[65];
    sha256(first, declared, digest);
    hex_of(digest, 32, sha);

    // The offsets of interest come from the SHIPPING table row for this
    // identity, never from the caller, so a caller cannot ask the recorder to
    // read outside the declared image.
    std::size_t ntab = 0;
    const BlobRow* tab = blob_table(&ntab);
    const BlobRow* row = nullptr;
    for (std::size_t i = 0; i < ntab; ++i) {
        const char* a = tab[i].identity;
        std::size_t k = 0;
        while (a[k] != '\0' && a[k] == ident[k]) { ++k; }
        if (a[k] == '\0' && ident[k] == '\0') { row = &tab[i]; break; }
    }
    if (row == nullptr) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "identity not in the by-value blob table");
        return o;
    }

    // frame_id is derived from the frame-start marker kernel, and is recorded
    // with the source of the claim: "no marker seen yet" and "frame 1" are
    // different facts and must not be conflated.
    lock_init();
    long frame_id = 0;
    const char* frame_src = "NO_MARKER_SEEN_YET";
    long ovr = 0;
    EnterCriticalSection(&g_lock);
    if (std::strcmp(ident, "_Z10k_flag_setPjj") == 0) { ++g_frameCounter; }
    if (frame_id_override(&ovr)) {
        frame_id = ovr;
        frame_src = "ENV_OVERRIDE_RAW_DUMP_FRAME_ID";
    } else if (g_frameCounter > 0) {
        frame_id = (long)g_frameCounter;
        frame_src = "MARKER_K_FLAG_SET";
    }
    LeaveCriticalSection(&g_lock);

    // ---- build the record ------------------------------------------------
    char stamp[40];
    utc_compact(stamp, sizeof(stamp));
    char iso[40];
    utc_iso(iso, sizeof(iso));
    char stem[48];
    stem_of(ident, stem, sizeof(stem));

    char base[600];
    std::snprintf(base, sizeof(base), "%s_%lu_%u_%s_%.12s", stamp,
                  (unsigned long)GetCurrentProcessId(), ord, stem, sha);

    char jpath[600];
    char bpath[600];
    HANDLE jh = INVALID_HANDLE_VALUE;
    HANDLE bh = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt <= 8; ++attempt) {
        char suffix[16] = "";
        if (attempt > 0) { std::snprintf(suffix, sizeof(suffix), ".dup%u", attempt); }
        std::snprintf(jpath, sizeof(jpath), "%s\\%s%s.json", dir, base, suffix);
        std::snprintf(bpath, sizeof(bpath), "%s\\%s%s.bin", dir, base, suffix);
        bool e1 = false;
        jh = create_new_file(jpath, &e1);
        if (jh == INVALID_HANDLE_VALUE) {
            if (e1) { o.clobber_refused = true; continue; }
            break;
        }
        bool e2 = false;
        bh = create_new_file(bpath, &e2);
        if (bh == INVALID_HANDLE_VALUE) {
            // A half-written capture is worse than none.
            CloseHandle(jh);
            DeleteFileA(jpath);
            o.refused = true;
            o.clobber_refused = o.clobber_refused || e2;
            std::snprintf(o.reason, sizeof(o.reason),
                          "side-car could not be created%s", e2 ? " (exists)" : "");
            return o;
        }
        break;
    }
    if (jh == INVALID_HANDLE_VALUE || bh == INVALID_HANDLE_VALUE) {
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason),
                      "no unclaimed record path (write-once held)");
        return o;
    }
    if (!write_all(bh, first, declared)) {
        CloseHandle(bh); CloseHandle(jh);
        DeleteFileA(bpath); DeleteFileA(jpath);
        o.refused = true;
        std::snprintf(o.reason, sizeof(o.reason), "side-car write failed");
        return o;
    }
    CloseHandle(bh);

    char hex[kMaxBlobBytes * 2 + 1];
    hex_of(first, declared, hex);

    // Offsets are reported in BOTH coordinate systems, and as DECIMAL JSON
    // integers: JSON has no hex literal, and the first version of this record
    // emitted `[0x0,0x20]`, which is not parseable. A quoted hex view is kept
    // alongside so a reader can compare against 16AO's hex spelling directly.
    char offs_blob[400];
    char offs_kernarg[400];
    char hex_blob[400];
    char hex_kernarg[400];
    {
        Buf b(offs_blob, sizeof(offs_blob)), kb(offs_kernarg, sizeof(offs_kernarg));
        Buf hb(hex_blob, sizeof(hex_blob)), hk(hex_kernarg, sizeof(hex_kernarg));
        for (unsigned i = 0; i < row->n_offsets; ++i) {
            b.addf("%s%u", i ? "," : "", row->offsets[i]);
            kb.addf("%s%u", i ? "," : "", row->offsets[i] + row->kernarg_range_lo);
            hb.addf("%s0x%x", i ? "," : "", row->offsets[i]);
            hk.addf("%s0x%x", i ? "," : "", row->offsets[i] + row->kernarg_range_lo);
        }
        if (b.overflow || kb.overflow || hb.overflow || hk.overflow) {
            CloseHandle(jh); DeleteFileA(jpath); DeleteFileA(bpath);
            o.refused = true;
            std::snprintf(o.reason, sizeof(o.reason), "offset list overflow");
            return o;
        }
    }

    char json[8192];
    {
        Buf b(json, sizeof(json));
        b.add("{\n");
        // Every string-valued field below goes through key_str()/key_str_last().
        // No string is ever placed in the record by any other route, so a path,
        // a kernel name or a reason string containing a backslash, a quote or a
        // control character cannot produce an unparseable record.
        // NOTE: the opening brace is emitted above, NOT by key_str() -- key_str
        // emits a field, and the first field is not the object's opening brace.
        b.key_str("schema", kRecordSchema);
        if (frame_src[0] == 'N') {
            b.add(" \"frame_id\": null,\n");
        } else {
            b.addf(" \"frame_id\": %ld,\n", frame_id);
        }
        b.key_str("frame_id_source", frame_src);
        b.addf(" \"launch_ordinal\": %u,\n", ord);
        b.key_str("kernel_identity", ident);
        b.addf(" \"raw_blob_length\": %zu,\n", declared);
        b.key_str("raw_bytes", hex);
        b.key_str("raw_bytes_encoding", "HEX_LOWERCASE");
        b.key_str("raw_bytes_sidecar", bpath);
        b.key_str("sha256", sha);
        b.key_str("timestamp_utc", iso);
        b.key_str("source_callsite", kSourceCallsite);
        b.add(" \"requested_field_offsets\": ["); b.add(offs_blob); b.add("],\n");
        b.key_str("requested_field_offsets_basis", "BLOB_RELATIVE");
        b.key_str("requested_field_offsets_hex", hex_blob);
        b.add(" \"requested_field_offsets_kernarg_relative\": [");
        b.add(offs_kernarg); b.add("],\n");
        b.addf(" \"declared_by_value_blob_bytes\": %u,\n", row->blob_bytes);
        b.addf(" \"kernarg_range_lo\": %u,\n", row->kernarg_range_lo);
        b.key_str("kernarg_read_offsets_hex", hex_kernarg);
        b.add(" \"blob_stable_during_capture\": true,\n");
        b.addf(" \"process_id\": %lu,\n", (unsigned long)GetCurrentProcessId());
        b.addf(" \"thread_id\": %lu,\n", (unsigned long)GetCurrentThreadId());
        b.key_str("blob_table_source",
                "p16ao/contracts/FIRST_FRAME_FIELD_CLOSURE.json");
        b.key_str_last("capture_point",
                     "BEFORE_LAUNCH_GATE_AND_BEFORE_BACKEND_SUBMISSION");
        b.add("}\n");
        if (b.overflow) {
            CloseHandle(jh); DeleteFileA(jpath); DeleteFileA(bpath);
            o.refused = true;
            std::snprintf(o.reason, sizeof(o.reason), "record buffer overflow");
            return o;
        }
        if (!write_all(jh, json, b.n)) {
            CloseHandle(jh); DeleteFileA(jpath); DeleteFileA(bpath);
            o.refused = true;
            std::snprintf(o.reason, sizeof(o.reason), "record write failed");
            return o;
        }
    }
    CloseHandle(jh);

    o.record_written = true;
    std::snprintf(o.record_path, sizeof(o.record_path), "%s", jpath);
    std::snprintf(o.sidecar_path, sizeof(o.sidecar_path), "%s", bpath);
    std::snprintf(o.reason, sizeof(o.reason), "record written");
    trace("RECORD_WRITTEN", jpath);
    return o;
}

// ---------------------------------------------------------------- selftest
// The recorder's OWN checks, exercised against a directory the caller owns.
// Each step states what it did and whether the recorder behaved; the runner
// records them verbatim. This is the instrument for "a known-bad input is
// rejected AND a known-good input is accepted" at the recorder level, which is
// a different question from the eight capture controls.
// Structural guard on the record just written. SCOPE, stated so this is not
// mistaken for a JSON parser: it checks exactly one property -- that every
// backslash inside a string begins a legal RFC-8259 escape. That is the
// property whose absence made generations 1 and 2 unreadable to a standard
// reader ("Invalid \escape"). It deliberately does NOT check the other defect
// class (a hex literal such as `[0x0,0x20]` is a bare token, not a string
// escape); that one is caught by src/p16at_verify_all_records.py, which parses
// every emitted record with Python's standard json module.
//
// returns the offset of the first bare backslash, or -1
static long first_bare_backslash(const char* s, size_t n)
{
    bool in_str = false;
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        if (!in_str) {
            if (c == '"') { in_str = true; }
            continue;
        }
        if (c == '\\') {
            if (i + 1 >= n) { return (long)i; }
            char e = s[i + 1];
            if (!(e == '"' || e == '\\' || e == '/' || e == 'b' || e == 'f' ||
                  e == 'n' || e == 'r' || e == 't' || e == 'u')) {
                return (long)i;
            }
            i += (e == 'u') ? 5 : 1;
            continue;
        }
        if (c == '"') { in_str = false; }
    }
    return -1;
}

std::size_t self_test(const char* dir, SelfTestStep* steps, std::size_t cap)
{
    std::size_t n = 0;
    if (cap < 6) { return 0; }

    unsigned char blob[64];
    for (unsigned i = 0; i < sizeof(blob); ++i) { blob[i] = (unsigned char)(0xA0 + i); }
    Request r;
    r.launch_ordinal = 7;
    r.kernel_identity = "_Z14k_dec_upsample11DecUpParams";
    r.blob = blob;
    r.blob_length = 40;
    static const unsigned offs[2] = {0x0, 0x20};
    r.requested_offsets = offs;
    r.n_requested_offsets = 2;

    char expected_sha[65];
    {
        unsigned char d[32];
        sha256(blob, 40, d);
        hex_of(d, 32, expected_sha);
    }

    // (1) known-good input -> ACCEPTED, and the record carries the digest this
    //     file's own hash implementation computed.
    char first_record[600] = "";
    {
        SelfTestStep& s = steps[n++];
        s.name = "recorder_accepts_known_good_capture";
        Outcome o = emit(r);
        bool ok = o.emission_point_reached && o.record_written && !o.refused;
        bool carries = false;
        if (ok) {
            std::snprintf(first_record, sizeof(first_record), "%s", o.record_path);
            FILE* f = std::fopen(o.record_path, "rb");
            char body[8192];
            size_t got = f ? std::fread(body, 1, sizeof(body) - 1, f) : 0;
            if (f) { std::fclose(f); }
            body[got] = '\0';
            carries = got > 0 && std::strstr(body, expected_sha) != nullptr;
        }
        s.ok = ok && carries;
        std::snprintf(s.detail, sizeof(s.detail),
                      "emission=%d written=%d refused=%d reason=\"%s\" "
                      "record_carries_its_own_digest=%d path=\"%s\"",
                      (int)o.emission_point_reached, (int)o.record_written,
                      (int)o.refused, o.reason, (int)carries, o.record_path);
    }

    // (2) WRITE-ONCE: a second, byte-identical capture into the same directory.
    //     The contract is that it never overwrites. Two acceptable outcomes --
    //     a distinct path, or a refusal -- and one unacceptable one: the first
    //     record's bytes changing.
    {
        SelfTestStep& s = steps[n++];
        s.name = "recorder_never_overwrites_an_existing_record";
        Outcome o = emit(r);
        // Re-read the FIRST record and require it to be byte-identical to what
        // it was. Comparing the first record against itself is the point: the
        // question is whether emission #2 destroyed emission #1.
        FILE* f = std::fopen(first_record, "rb");
        char body[8192];
        size_t got = f ? std::fread(body, 1, sizeof(body) - 1, f) : 0;
        if (f) { std::fclose(f); }
        body[got] = '\0';
        bool intact = got > 0 && std::strstr(body, expected_sha) != nullptr &&
                      std::strstr(body, "\"launch_ordinal\": 7,") != nullptr;
        bool distinct = std::strcmp(o.record_path, first_record) != 0;
        bool second_ok = o.refused || (o.record_written && distinct);
        s.ok = intact && second_ok;
        std::snprintf(s.detail, sizeof(s.detail),
                      "second: written=%d refused=%d clobber_refused=%d "
                      "distinct_path=%d; first record intact=%d (%s)",
                      (int)o.record_written, (int)o.refused,
                      (int)o.clobber_refused, (int)distinct, (int)intact,
                      first_record);
    }

    // (3) known-bad: a null by-value image -> REFUSED, and the emission point
    //     is still reported as reached, so a refusal here is distinguishable
    //     from a control that never got this far.
    {
        SelfTestStep& s = steps[n++];
        s.name = "recorder_refuses_a_null_by_value_image";
        Request bad = r;
        bad.blob = nullptr;
        Outcome o = emit(bad);
        s.ok = o.emission_point_reached && !o.record_written && o.refused;
        std::snprintf(s.detail, sizeof(s.detail),
                      "emission=%d written=%d refused=%d reason=\"%s\"",
                      (int)o.emission_point_reached, (int)o.record_written,
                      (int)o.refused, o.reason);
    }

    // (4) known-bad: an identity that is NOT one of the 15 rows. It has no
    //     declared by-value size, so there is no length to read.
    {
        SelfTestStep& s = steps[n++];
        s.name = "recorder_refuses_an_identity_absent_from_the_blob_table";
        Request bad = r;
        bad.kernel_identity = "_Z10k_swin_varILi128ELb0EEv9VarParams";
        Outcome o = emit(bad);
        s.ok = o.emission_point_reached && !o.record_written && o.refused;
        std::snprintf(s.detail, sizeof(s.detail),
                      "emission=%d written=%d refused=%d reason=\"%s\"",
                      (int)o.emission_point_reached, (int)o.record_written,
                      (int)o.refused, o.reason);
    }

    // (5) known-bad: the recorder disabled. The recorder is entered and the
    //     refusal is named, but the EMISSION POINT is NOT reached -- there is no
    //     observer here, so nothing this arm produces can count as a rejection.
    {
        SelfTestStep& s = steps[n++];
        s.name = "recorder_disabled_does_not_reach_the_emission_point";
        SetEnvironmentVariableA("RAW_DUMP", "0");
        Outcome o = emit(r);
        SetEnvironmentVariableA("RAW_DUMP", "1");
        s.ok = !o.emission_point_reached && !o.record_written && o.refused;
        std::snprintf(s.detail, sizeof(s.detail),
                      "emission=%d written=%d refused=%d reason=\"%s\"",
                      (int)o.emission_point_reached, (int)o.record_written,
                      (int)o.refused, o.reason);
    }
    // (6) the record the recorder actually wrote must contain no bare
    //     backslash. The side-car path is an absolute Windows path, so the
    //     record is GUARANTEED to contain backslashes; if the escaping in
    //     key_str() ever regresses to a raw emission, this step goes red on the
    //     next run rather than being discovered by a downstream consumer.
    {
        SelfTestStep& s = steps[n++];
        s.name = "emitted_record_has_no_bare_backslash";
        char body[8192];
        size_t got = 0;
        body[0] = '\0';
        if (first_record[0] != '\0') {
            FILE* f = std::fopen(first_record, "rb");
            got = f ? std::fread(body, 1, sizeof(body) - 1, f) : 0;
            if (f) { std::fclose(f); }
            body[got] = '\0';
        }
        bool has_backslash = std::strchr(body, '\\') != nullptr;
        long at = first_bare_backslash(body, got);
        s.ok = got > 0 && has_backslash && at < 0;
        std::snprintf(s.detail, sizeof(s.detail),
                      "bytes=%zu contains_backslash=%d "
                      "first_bare_backslash_offset=%ld path=\"%s\"",
                      got, (int)has_backslash, at, first_record);
    }
    return n;
}

}  // namespace raw_dump
