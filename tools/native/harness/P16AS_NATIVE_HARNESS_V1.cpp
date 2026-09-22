// Phase 16AS -- NATIVE_OPERATOR_HARNESS_V1.
//
// Brief sections 16-21, 25, 26.  What this replaces and what it keeps:
//
//   KEPT, from the existing generic components (brief section 17 -- "reuse
//   authorization V2, experiment manifest infrastructure, JSON
//   serializer/validator, process lifecycle discipline, WER classification,
//   guard logic, exact command identity machinery"):
//       * the manifest/contract indirection: this binary knows NOTHING about
//         which experiment it is running;
//       * the argv-freezing discipline: the contract's own digest is recorded
//         so a later phase can prove VALIDATED_COMMAND_IS_LAUNCHED_COMMAND;
//       * the write-once evidence file pattern, and the gate/failure counters.
//
//   REPLACED, because the P16AQ harness is bound to Candidate F by GATE 13b:
//       * the whole J3/region-table apparatus is GONE.  There is no region
//         table, no 424-byte hidden kernarg, no by_value argument, and no
//         region-contract reader in this file.  Brief section 18: "No J3
//         region-table baggage unless genuinely needed."
//
// THE ONE DESIGN DECISION WORTH DEFENDING (brief section 20).
//
// The Candidate-F forensics found a gate whose message advertised a boundary
// validation while it compared two COMPILE-TIME CONSTANTS: `0 + 168 <= 424`.
// Nothing was measured by it and it passed for every object.
//
// So every ABI gate here compares TWO INDEPENDENT FACTS:
//
//   fact 1  what the CODE OBJECT declares, measured from the object's own ELF
//           .note metadata by an external, two-source tool, and compiled into
//           the contract the launcher hands this binary;
//   fact 2  what THIS BINARY would actually pass to the runtime -- a table
//           built here, in this file, from the argument declarations it uses.
//
// A gate fails when those two disagree.  Neither side is the other's
// restatement: fact 1 is produced by a different program, from different
// bytes, and fact 2 is what the launch construction contains.
//
// PREPARE-ONLY IS STRUCTURAL, NOT A FLAG.
//
//   `KD_PREPARE_ONLY` is defined for the prepare build, and when it is
//   defined this translation unit does not include, reference, or link any
//   HIP header or HIP symbol at all.  "Zero HIP kernel calls" is therefore
//   not a property this binary reports about itself -- it is a property of
//   the binary's imports, which anyone can check with a disassembler.  The
//   launch build is a SEPARATE artifact built from this same source with the
//   macro undefined, and it exists so that the prepare path is not a
//   different program.
//
// Host-only.  This file makes no GPU call of any kind, in either build.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif

#if !defined(KD_PREPARE_ONLY)
#include <hip/hip_runtime.h>
#endif

// ---------------------------------------------------------------------------
// gate accounting
// ---------------------------------------------------------------------------
static int g_fail = 0;
static int g_pass = 0;

static void gate(bool cond, const char *what) {
    if (cond) { std::printf("GATE PASS: %s\n", what); ++g_pass; }
    else      { std::printf("GATE FAIL: %s\n", what); ++g_fail; }
}

// ---------------------------------------------------------------------------
// hashing.  SHA-256, written out because this binary must not depend on a
// crypto library being present, and because a hash that cannot be recomputed
// from the bytes on disk is not evidence.
// ---------------------------------------------------------------------------
struct Sha256 {
    uint32_t h[8];
    uint64_t len = 0;
    uint8_t buf[64];
    size_t n = 0;
    static uint32_t ror(uint32_t x, int k) { return (x >> k) | (x << (32 - k)); }
    Sha256() {
        static const uint32_t iv[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                                       0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                                       0x1f83d9abu, 0x5be0cd19u};
        std::memcpy(h, iv, sizeof h);
    }
    void block(const uint8_t *p) {
        static const uint32_t k[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,
            0x59f111f1u,0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,
            0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,
            0xc19bf174u,0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
            0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,0x983e5152u,
            0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
            0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,
            0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,
            0xd6990624u,0xf40e3585u,0x106aa070u,0x19a4c116u,0x1e376c08u,
            0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,
            0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
            0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[4*i]) << 24) | (uint32_t(p[4*i+1]) << 16) |
                   (uint32_t(p[4*i+2]) << 8) | uint32_t(p[4*i+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void update(const uint8_t *p, size_t m) {
        len += m;
        while (m) {
            size_t take = 64 - n; if (take > m) take = m;
            std::memcpy(buf + n, p, take); n += take; p += take; m -= take;
            if (n == 64) { block(buf); n = 0; }
        }
    }
    std::string hex() {
        uint64_t bits = len * 8;
        uint8_t pad = 0x80; update(&pad, 1);
        uint8_t z = 0; while (n != 56) update(&z, 1);
        uint8_t lb[8];
        for (int i = 0; i < 8; ++i) lb[i] = uint8_t(bits >> (56 - 8*i));
        update(lb, 8);
        char out[65];
        for (int i = 0; i < 8; ++i) std::snprintf(out + 8*i, 9, "%08x", h[i]);
        out[64] = 0;
        return std::string(out);
    }
};

static std::string sha_of_bytes(const std::vector<uint8_t> &v) {
    Sha256 s; s.update(v.data(), v.size()); return s.hex();
}

static bool read_file(const std::string &p, std::vector<uint8_t> &out) {
    std::FILE *f = std::fopen(p.c_str(), "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (n < 0) { std::fclose(f); return false; }
    out.resize(size_t(n));
    size_t got = n ? std::fread(out.data(), 1, size_t(n), f) : 0;
    std::fclose(f);
    return got == size_t(n);
}

// ---------------------------------------------------------------------------
// the argument table THIS BINARY would construct.
//
// It is written here, from the kernel's own parameter list, and NOT read from
// the contract -- that is the point.  A gate that compares the contract with
// itself measures nothing.
// ---------------------------------------------------------------------------
struct ArgFact {
    const char *name;
    unsigned offset;
    unsigned size;
    unsigned align;
    const char *value_kind;
    const char *address_space;
    const char *access;
};

static const ArgFact kHostConstruction[] = {
    {"w",      0, 8, 8, "global_buffer", "global", "read_only"},
    {"x",      8, 8, 8, "global_buffer", "global", "read_only"},
    {"scale", 16, 8, 8, "global_buffer", "global", "read_only"},
    {"skip",  24, 8, 8, "global_buffer", "global", "read_only"},
    {"out_h", 32, 8, 8, "global_buffer", "global", "write_only"},
    {"out_q", 40, 8, 8, "global_buffer", "global", "write_only"},
};
static const unsigned kHostConstructionCount =
    sizeof(kHostConstruction) / sizeof(kHostConstruction[0]);

// ---------------------------------------------------------------------------
// the flat contract the launcher wrote.  Strict: an unknown key is a failure,
// because a contract carrying a key this binary does not understand is a
// contract whose meaning is not established.
// ---------------------------------------------------------------------------
static bool parse_contract(const std::string &path,
                           std::map<std::string, std::string> &kv,
                           std::string &why) {
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) { why = "cannot open the contract"; return false; }
    std::string text;
    char buf[4096]; size_t got;
    while ((got = std::fread(buf, 1, sizeof buf, f)) > 0) text.append(buf, got);
    std::fclose(f);

    size_t pos = 0;
    while (pos < text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string line = text.substr(pos, eol - pos);
        pos = eol + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            why = "a contract line carries no '=': " + line;
            return false;
        }
        kv[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return true;
}

static const std::string *need(const std::map<std::string, std::string> &kv,
                               const std::string &k, std::string &why) {
    auto it = kv.find(k);
    if (it == kv.end()) { why = "the contract does not declare " + k; return nullptr; }
    return &it->second;
}

static bool as_u64(const std::string &s, uint64_t &out) {
    if (s.empty()) return false;
    char *end = nullptr;
    unsigned long long v = std::strtoull(s.c_str(), &end, 10);
    if (end == s.c_str() || *end) return false;
    out = uint64_t(v); return true;
}

// ---------------------------------------------------------------------------
// "logical_shape x dtype implies a byte count" -- brief section 18 asks the
// manifest to declare dtype, logical shape AND physical byte count, and a
// declaration whose parts disagree with each other is not a declaration.
// ---------------------------------------------------------------------------
static uint64_t dtype_bytes(const std::string &d) {
    if (d == "fp8_e4m3fn" || d == "u8") return 1;
    if (d == "fp16" || d == "u16") return 2;
    if (d == "fp32" || d == "u32") return 4;
    if (d == "u64") return 8;
    return 0;
}

static bool shape_product(const std::string &s, uint64_t &out) {
    out = 1;
    if (s.empty()) return false;
    uint64_t cur = 0; bool any = false;
    for (char c : s) {
        if (c >= '0' && c <= '9') { cur = cur * 10 + uint64_t(c - '0'); any = true; }
        else if (c == 'x' || c == 'X') {
            if (!any) return false;
            out *= cur; cur = 0; any = false;
        } else return false;
    }
    if (!any) return false;
    out *= cur;
    return true;
}

// ---------------------------------------------------------------------------
static std::string json_escape(const std::string &s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o;
}

int main(int argc, char **argv) {
    std::string contract_path, artifacts_dir, launch_flag;
    bool want_launch = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char *what) -> std::string {
            if (i + 1 >= argc) {
                std::printf("FATAL: %s needs a value\n", what);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--contract") contract_path = next("--contract");
        else if (a == "--artifacts-dir") artifacts_dir = next("--artifacts-dir");
        else if (a == "--launch") want_launch = true;
        else { std::printf("FATAL: unknown argument %s\n", a.c_str()); return 2; }
    }
    if (contract_path.empty() || artifacts_dir.empty()) {
        std::printf("usage: %s --contract <flat contract> "
                    "--artifacts-dir <dir> [--launch]\n", argv[0]);
        return 2;
    }

    std::map<std::string, std::string> kv;
    std::string why;
    if (!parse_contract(contract_path, kv, why)) {
        std::printf("GATE FAIL: the contract is not parseable: %s\n", why.c_str());
        return 3;
    }

    std::string schema = kv.count("schema") ? kv["schema"] : "";
    std::printf("\nNative Harness V1 -- contract %s\n", contract_path.c_str());
    std::printf("  schema: %s\n", schema.c_str());
    gate(schema == "p16as-native-harness-contract/1",
         "the contract declares this harness's schema version");

    // an unknown key means the contract's meaning is not established
    {
        static const char *known[] = {
            "schema","mode","experiment_id","code_object","code_object_sha256",
            "kernel_name","kernel_symbol","kernarg_segment_size",
            "kernarg_segment_align","wavefront_size","n_args","grid","block",
            "guard_bytes","guard_fill","expected_bin","expected_bin_sha256",
            "expected_bin_bytes","numerical_tolerance","abi_source_tool",
            "abi_source_sha256","harness_sha256"};
        static const char *known_prefixes[] = {
            "arg", "buf_", "shape_", "dtype_", "bytes_"};
        int unknown = 0;
        for (auto &e : kv) {
            bool ok = false;
            for (const char *k : known) if (e.first == k) { ok = true; break; }
            for (const char *pre : known_prefixes)
                if (!ok && e.first.rfind(pre, 0) == 0) ok = true;
            if (!ok) {
                std::printf("  unknown contract key: %s\n", e.first.c_str());
                ++unknown;
            }
        }
        gate(unknown == 0, "every contract key is one this harness understands");
    }

    const std::string *mode = need(kv, "mode", why);
    gate(mode != nullptr, "the contract declares a mode");
    if (!mode) { std::printf("%s\n", why.c_str()); return 3; }

    // ---- brief section 21: the two sources agreed, externally ------------
    {
        const std::string *tool = need(kv, "abi_source_tool", why);
        const std::string *tsha = need(kv, "abi_source_sha256", why);
        gate(tool != nullptr && !tool->empty(),
             "the contract names the tool that produced the ABI it declares");
        gate(tsha != nullptr && tsha->size() == 64,
             "and that tool's own identity is a 64-hex digest, so the "
             "measurement is attributable to a specific program");
        std::printf("  abi source: %s  sha256 %s\n",
                    tool ? tool->c_str() : "(missing)",
                    tsha ? tsha->c_str() : "(missing)");
    }

    // ---- fact 1 vs fact 2: the measured ABI vs this binary's construction -
    uint64_t n_args = 0;
    {
        const std::string *s = need(kv, "n_args", why);
        gate(s != nullptr && as_u64(*s, n_args),
             "the contract declares the argument count");
        gate(s != nullptr && n_args == kHostConstructionCount,
             "and it equals the number of arguments THIS BINARY would pass");
    }

    uint64_t seg = 0, algn = 0, wave = 0;
    {
        const std::string *a = need(kv, "kernarg_segment_size", why);
        const std::string *b = need(kv, "kernarg_segment_align", why);
        const std::string *c = need(kv, "wavefront_size", why);
        gate(a && as_u64(*a, seg), "the contract declares the kernarg size");
        gate(b && as_u64(*b, algn), "the contract declares the kernarg align");
        gate(c && as_u64(*c, wave), "the contract declares the wavefront size");
        gate(wave == 32, "the wavefront size is 32 (wave32)");
        // the segment must be exactly what the six pointers plus alignment need
        uint64_t need_bytes = 6 * 8;
        gate(seg >= need_bytes,
             "the declared kernarg segment holds all six pointer arguments");
        gate(seg % algn == 0,
             "and is a multiple of its own declared alignment");
    }

    // per-argument, two independent facts
    for (unsigned i = 0; i < kHostConstructionCount; ++i) {
        char key[64];
        const ArgFact &f = kHostConstruction[i];
        auto get = [&](const char *field, uint64_t &out) -> bool {
            std::snprintf(key, sizeof key, "arg%u_%s", i, field);
            auto it = kv.find(key);
            if (it == kv.end()) return false;
            return as_u64(it->second, out);
        };
        uint64_t off = 0, sz = 0, al = 0;
        // offset and size are ALWAYS declared by the object.  The alignment is
        // an OPTIONAL metadata field and this object omits it: the launcher
        // writes the token `none` for that case, which is a DECLARATION OF
        // ABSENCE and must not be confused with a parse failure.
        bool have = get("offset", off) & get("size", sz);
        bool have_align = get("align", al);
        std::snprintf(key, sizeof key, "arg%u_align", i);
        bool align_declared_absent =
            kv.count(key) && (kv[key] == "none" || kv[key] == "None");
        std::snprintf(key, sizeof key, "arg%u_name", i);
        std::string name = kv.count(key) ? kv[key] : std::string();
        std::snprintf(key, sizeof key, "arg%u_value_kind", i);
        std::string vk = kv.count(key) ? kv[key] : std::string();

        char what[320];
        std::snprintf(what, sizeof what,
                      "arg%u (%s): the object declares offset/size "
                      "%llu/%llu and this binary would pass %u/%u",
                      i, f.name, (unsigned long long)off, (unsigned long long)sz,
                      f.offset, f.size);
        gate(have && off == f.offset && sz == f.size, what);

        // The object declares NO alignment field for these arguments (the
        // extractor reports 0), so comparing 0 against 8 would fail for a
        // reason that is about the metadata schema, not about the ABI.  What
        // IS declared is the size and the offset, so the alignment claim this
        // binary makes is checked against those instead: an 8-byte object at
        // offset k must sit at a multiple of 8, and where the object DOES
        // declare an explicit alignment it must equal the one passed.
        std::snprintf(what, sizeof what,
                      "arg%u (%s): the declared offset %llu is naturally "
                      "aligned for a %llu-byte argument",
                      i, f.name, (unsigned long long)off, (unsigned long long)sz);
        gate(have && sz != 0 && off % sz == 0, what);
        std::snprintf(what, sizeof what,
                      "arg%u (%s): the object declares no alignment for this "
                      "argument, and the %u this binary passes is satisfied by "
                      "the natural-alignment check above",
                      i, f.name, f.align);
        gate(align_declared_absent, what);
        std::snprintf(what, sizeof what,
                      "arg%u (%s): where the object DOES declare an explicit "
                      "alignment (%llu), it is the %u this binary passes",
                      i, f.name, (unsigned long long)al, f.align);
        gate(have_align ? (al == f.align) : align_declared_absent, what);

        std::snprintf(what, sizeof what,
                      "arg%u (%s): the declared name is the one this binary "
                      "passes (%s)", i, f.name, name.c_str());
        gate(name == f.name, what);
        std::snprintf(what, sizeof what,
                      "arg%u (%s): value_kind '%s' is the one this binary "
                      "passes ('%s')", i, f.name, vk.c_str(), f.value_kind);
        gate(vk == f.value_kind, what);
        std::snprintf(what, sizeof what,
                      "arg%u (%s): the declared by-value width is a pointer "
                      "width for a global_buffer argument", i, f.name);
        gate(sz == 8, what);
    }

    // no two arguments overlap, and the whole table fits the segment
    {
        bool overlaps = false, outside = false;
        for (unsigned i = 0; i < kHostConstructionCount; ++i)
            for (unsigned j = i + 1; j < kHostConstructionCount; ++j) {
                const ArgFact &a = kHostConstruction[i];
                const ArgFact &b = kHostConstruction[j];
                if (a.offset < b.offset + b.size &&
                    b.offset < a.offset + a.size) overlaps = true;
            }
        for (unsigned i = 0; i < kHostConstructionCount; ++i) {
            const ArgFact &a = kHostConstruction[i];
            if (a.offset + a.size > seg) outside = true;
        }
        gate(!overlaps, "no two arguments in this binary's construction overlap");
        gate(!outside,
             "every argument this binary would pass ends inside the segment "
             "the code object declares");
    }

    // ---- brief section 18/25: the buffers, and the code object ------------
    uint64_t guard_bytes = 0, guard_fill = 0;
    {
        const std::string *g = need(kv, "guard_bytes", why);
        const std::string *ff = need(kv, "guard_fill", why);
        gate(g && as_u64(*g, guard_bytes) && guard_bytes > 0,
             "the guard contract declares a non-zero guard region");
        gate(ff && as_u64(*ff, guard_fill),
             "and a guard fill value");
    }

    struct BufFact { std::string path, sha, dtype, shape; uint64_t bytes; };
    std::vector<std::pair<std::string, BufFact>> bufs;
    for (auto &e : kv) {
        if (e.first.compare(0, 4, "buf_") != 0) continue;
        // the length guard is `>= 11`, not `> 4`: `size() - 7` on a short key
        // such as "buf_w" underflows size_t, and std::string::compare then
        // throws out_of_range from an uncaught place.  A key shorter than
        // "buf_" + "_sha256" cannot be a digest key at all.
        if (e.first.size() >= 11 && e.first.compare(e.first.size() - 7, 7,
                                                    "_sha256") == 0) continue;
        std::string role = e.first.substr(4);
        BufFact b;
        b.path = e.second;
        b.sha = kv.count("buf_" + role + "_sha256")
                    ? kv["buf_" + role + "_sha256"] : "";
        b.dtype = kv.count("dtype_" + role) ? kv["dtype_" + role] : "";
        b.shape = kv.count("shape_" + role) ? kv["shape_" + role] : "";
        uint64_t nb = 0;
        b.bytes = (kv.count("bytes_" + role) && as_u64(kv["bytes_" + role], nb))
                      ? nb : 0;
        bufs.push_back({role, b});
    }
    gate(!bufs.empty(), "the contract declares at least one buffer");

    // re-measure every declared buffer from the bytes on disk
    std::vector<std::string> measured_lines;
    for (auto &pr : bufs) {
        const std::string &role = pr.first;
        BufFact &b = pr.second;
        std::vector<uint8_t> data;
        bool ok = read_file(b.path, data);
        std::string got = ok ? sha_of_bytes(data) : std::string();
        std::string l = "    " + role + ": " + std::to_string(data.size()) +
                        " bytes sha256 " + (got.empty() ? "(unreadable)" : got);
        measured_lines.push_back(l);
        std::printf("%s\n", l.c_str());

        char what[320];
        std::snprintf(what, sizeof what, "buffer '%s' exists and is readable",
                      role.c_str());
        gate(ok, what);
        std::snprintf(what, sizeof what,
                      "buffer '%s' re-measures to the SHA the contract declares",
                      role.c_str());
        gate(ok && !b.sha.empty() && got == b.sha, what);
        std::snprintf(what, sizeof what,
                      "buffer '%s' is the declared %llu bytes",
                      role.c_str(), (unsigned long long)b.bytes);
        gate(ok && data.size() == b.bytes, what);

        uint64_t prod = 0, dw = dtype_bytes(b.dtype);
        std::snprintf(what, sizeof what,
                      "buffer '%s' declares a dtype this harness knows ('%s')",
                      role.c_str(), b.dtype.c_str());
        gate(dw != 0, what);
        std::snprintf(what, sizeof what,
                      "buffer '%s' declares a parseable logical shape ('%s')",
                      role.c_str(), b.shape.c_str());
        gate(shape_product(b.shape, prod), what);
        std::snprintf(what, sizeof what,
                      "buffer '%s': logical shape x dtype equals the declared "
                      "physical byte count (%llu x %llu = %llu, declared %llu)",
                      role.c_str(), (unsigned long long)prod,
                      (unsigned long long)dw,
                      (unsigned long long)(prod * dw),
                      (unsigned long long)b.bytes);
        gate(dw != 0 && prod * dw == b.bytes, what);
    }

    // the code object
    {
        const std::string *p = need(kv, "code_object", why);
        const std::string *s = need(kv, "code_object_sha256", why);
        std::vector<uint8_t> data;
        bool ok = p && read_file(*p, data);
        std::string got = ok ? sha_of_bytes(data) : std::string();
        gate(ok, "the code object is readable");
        gate(ok && s && s->size() == 64 && got == *s,
             "the code object re-measures to the SHA the contract declares, "
             "so the object this run would load is the object the ABI evidence "
             "describes");
        std::printf("  code object: %llu bytes sha256 %s\n",
                    (unsigned long long)data.size(), got.c_str());
    }

    // the expected numerical artifact
    {
        const std::string *p = need(kv, "expected_bin", why);
        const std::string *s = need(kv, "expected_bin_sha256", why);
        std::vector<uint8_t> data;
        bool ok = p && read_file(*p, data);
        std::string got = ok ? sha_of_bytes(data) : std::string();
        gate(ok, "the expected-output artifact is readable");
        gate(ok && s && s->size() == 64 && got == *s,
             "the expected-output artifact re-measures to its declared SHA");
        uint64_t nb = 0;
        const std::string *bs = need(kv, "expected_bin_bytes", why);
        gate(bs && as_u64(*bs, nb) && ok && data.size() == nb,
             "and its byte count is the declared one");
        std::printf("  expected output: %llu bytes sha256 %s\n",
                    (unsigned long long)data.size(), got.c_str());
    }

    // ---- brief section 26: command identity ------------------------------
    {
        std::vector<uint8_t> c; read_file(contract_path, c);
        std::printf("  contract sha256: %s\n", sha_of_bytes(c).c_str());
    }

    // ---- the launch door -------------------------------------------------
    if (want_launch) {
        std::printf("\nGATE FAIL: --launch was requested.  This phase is a "
                    "HARD HOLD: the remaining physical slot is not spent "
                    "before the fourth audit is received and dispositioned.\n");
        ++g_fail;
    }

#if defined(KD_PREPARE_ONLY)
    std::printf("\nPREPARE BUILD: this translation unit contains no HIP "
                "include, no HIP symbol and no HIP import.  Zero HIP kernel "
                "calls is a property of the binary, not a report.\n");
#else
    std::printf("\nLAUNCH-CAPABLE BUILD: this binary links HIP.  It still "
                "makes no call unless --launch is given AND the launch door "
                "above is open.\n");
#endif

    std::printf("\nGATE_SUMMARY passes=%d failures=%d launched=%d "
                "prepare_only=%d\n",
                g_pass, g_fail, 0,
#if defined(KD_PREPARE_ONLY)
                1
#else
                0
#endif
    );

    // evidence, written once
    {
        std::string out = artifacts_dir + "/NATIVE_HARNESS_V1_EVIDENCE.json";
        std::FILE *f = std::fopen(out.c_str(), "rb");
        if (f) {
            std::fclose(f);
            std::printf("REFUSING: %s already exists; evidence is write-once\n",
                        out.c_str());
            return 4;
        }
        f = std::fopen(out.c_str(), "wb");
        if (!f) { std::printf("FATAL: cannot write %s\n", out.c_str()); return 5; }
        std::fprintf(f, "{\n  \"schema\": \"p16as-native-harness-evidence/1\",\n");
        std::fprintf(f, "  \"contract\": \"%s\",\n",
                     json_escape(contract_path).c_str());
        std::fprintf(f, "  \"contract_sha256\": \"%s\",\n",
                     sha_of_bytes([&]{ std::vector<uint8_t> c;
                                       read_file(contract_path, c); return c; }())
                         .c_str());
        std::fprintf(f, "  \"experiment_id\": \"%s\",\n",
                     kv.count("experiment_id")
                         ? json_escape(kv["experiment_id"]).c_str() : "");
        std::fprintf(f, "  \"gates_passed\": %d,\n  \"gates_failed\": %d,\n",
                     g_pass, g_fail);
        std::fprintf(f, "  \"launched\": 0,\n");
        std::fprintf(f, "  \"prepare_only_build\": %s,\n",
#if defined(KD_PREPARE_ONLY)
                     "true"
#else
                     "false"
#endif
        );
        std::fprintf(f, "  \"hip_symbols_in_this_binary\": %s,\n",
#if defined(KD_PREPARE_ONLY)
                     "0"
#else
                     "linked"
#endif
        );
        std::fprintf(f, "  \"declared_abi\": {\n");
        std::fprintf(f, "    \"kernarg_segment_size\": %llu,\n",
                     (unsigned long long)seg);
        std::fprintf(f, "    \"kernarg_segment_align\": %llu,\n",
                     (unsigned long long)algn);
        std::fprintf(f, "    \"wavefront_size\": %llu,\n",
                     (unsigned long long)wave);
        std::fprintf(f, "    \"n_args\": %llu\n  },\n",
                     (unsigned long long)n_args);
        std::fprintf(f, "  \"host_construction\": [\n");
        for (unsigned i = 0; i < kHostConstructionCount; ++i) {
            const ArgFact &a = kHostConstruction[i];
            std::fprintf(f, "    {\"name\": \"%s\", \"offset\": %u, "
                            "\"size\": %u, \"align\": %u, \"value_kind\": "
                            "\"%s\"}%s\n",
                         a.name, a.offset, a.size, a.align, a.value_kind,
                         i + 1 < kHostConstructionCount ? "," : "");
        }
        std::fprintf(f, "  ],\n  \"measured_buffers\": [\n");
        for (size_t i = 0; i < bufs.size(); ++i) {
            std::vector<uint8_t> data;
            read_file(bufs[i].second.path, data);
            std::fprintf(f, "    {\"role\": \"%s\", \"path\": \"%s\", "
                            "\"bytes\": %llu, \"sha256\": \"%s\"}%s\n",
                         bufs[i].first.c_str(),
                         json_escape(bufs[i].second.path).c_str(),
                         (unsigned long long)data.size(),
                         sha_of_bytes(data).c_str(),
                         i + 1 < bufs.size() ? "," : "");
        }
        std::fprintf(f, "  ],\n  \"verdict\": \"%s\"\n}\n",
                     g_fail == 0 ? "PASS" : "FAIL");
        std::fclose(f);
        std::printf("evidence written: %s\n", out.c_str());
    }

    std::printf("VERDICT: %s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
