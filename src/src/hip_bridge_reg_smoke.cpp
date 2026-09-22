// Phase 11G: host-only registration substitution tests (mock backend).
//
// Uses the REAL upstream fatbin blob bytes (extracted statically from the
// vendor copy; private test artifact, never redistributed) so the
// fail-closed identity gate is exercised against the genuine payload.
//
// Cases:
//  1. real blob, substitution env OFF -> forwarded unchanged (mock sees
//     the original wrapper data pointer)
//  2. real blob, substitution env ON  -> canonical gfx1030 bundle
//     substituted (mock sees a different pointer whose content starts
//     with the bundle magic and contains the gfx1030 identifier)
//  3. unknown payload (unrelated bytes) -> forwarded unchanged
//  4. malformed/truncated payload     -> forwarded unchanged, no crash
//  5. wrong-hash payload (real blob, one byte mutated) -> forwarded
//     unchanged (structural pass, hash gate refuses)
//  6. oversized entry count/id length -> fail closed, no crash
//
// No GPU, no real HIP runtime.
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>

static std::string read_all_text(const char* path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return "";
    }
    std::string out;
    char buf[4096];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) {
        out.append(buf, got);
    }
    CloseHandle(h);
    return out;
}

static int failures = 0;
#define CHECK(cond, what)                                                      \
    do {                                                                       \
        if (cond) {                                                            \
            printf("PASS: %s\n", what);                                        \
        } else {                                                               \
            printf("FAIL: %s\n", what);                                        \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

typedef void** (*RegFn)(const void*);
typedef void (*UnregFn)(void**);

struct Wrapper {
    unsigned magic;
    unsigned version;
    const void* data;
    unsigned unused;
};

static const unsigned kHipfMagic = 0x48495046;  // 'HIPF'

static void* g_lastMockData = nullptr;  // what the mock backend saw

int main(int argc, char** argv)
{
    if (argc != 2) {
        printf("usage: hip_bridge_reg_smoke <original_fatbin_extract.bin>\n");
        return 2;
    }
    FILE* f = nullptr;
    fopen_s(&f, argv[1], "rb");
    if (!f) {
        printf("cannot open %s\n", argv[1]);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    long blobLen = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* blob = new unsigned char[(size_t)blobLen];
    fread(blob, 1, (size_t)blobLen, f);
    fclose(f);

    DeleteFileA("amdhip64_7_bridge.log");
    DeleteFileA("mock_hip6.log");
    SetEnvironmentVariableA("DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH", "0");

    HMODULE bridge = LoadLibraryExA("test_build\\amdhip64_7.dll", nullptr,
                                    LOAD_WITH_ALTERED_SEARCH_PATH);
    CHECK(bridge != nullptr, "load test-build bridge");
    RegFn regFn = (RegFn)GetProcAddress(bridge, "__hipRegisterFatBinary");
    UnregFn unregFn = (UnregFn)GetProcAddress(bridge, "__hipUnregisterFatBinary");
    CHECK(regFn != nullptr && unregFn != nullptr, "registration exports resolved");

    // ---------------- case 1: real blob, substitution OFF ----------------
    Wrapper w1 = {kHipfMagic, 1, blob, 0};
    SetEnvironmentVariableA("DLSSNR_GFX1030_USE_GFX1030_FATBIN", "0");
    void** h1 = regFn(&w1);
    CHECK(h1 != nullptr, "case1 register returned handle");
    unregFn(h1);

    // ---------------- case 2: real blob, substitution ON ----------------
    Wrapper w2 = {kHipfMagic, 1, blob, 0};
    SetEnvironmentVariableA("DLSSNR_GFX1030_USE_GFX1030_FATBIN", "1");
    void** h2 = regFn(&w2);
    CHECK(h2 != nullptr, "case2 register returned handle");
    unregFn(h2);

    // ---------------- case 3: unknown payload ---------------------------
    unsigned char junk[64];
    memset(junk, 0x5A, sizeof(junk));
    Wrapper w3 = {kHipfMagic, 1, junk, 0};
    void** h3 = regFn(&w3);
    CHECK(h3 != nullptr, "case3 register returned handle");
    unregFn(h3);

    // ---------------- case 4: malformed/truncated ------------------------
    unsigned char trunc8[8] = {0x5A};
    Wrapper w4 = {kHipfMagic, 1, trunc8, 0};
    void** h4 = regFn(&w4);
    CHECK(h4 != nullptr, "case4 register returned handle (fail closed)");
    unregFn(h4);
    Wrapper w4b = {0xDEADBEEF, 1, blob, 0};  // wrong wrapper magic
    void** h4b = regFn(&w4b);
    CHECK(h4b != nullptr, "case4b wrong wrapper magic forwarded");
    unregFn(h4b);

    // ---------------- case 5: wrong hash (one byte mutated) --------------
    unsigned char* mutated = new unsigned char[(size_t)blobLen];
    memcpy(mutated, blob, (size_t)blobLen);
    mutated[blobLen - 1] ^= 0x01;
    Wrapper w5 = {kHipfMagic, 1, mutated, 0};
    void** h5 = regFn(&w5);
    CHECK(h5 != nullptr, "case5 register returned handle");
    unregFn(h5);

    // ---------------- case 6: oversized entry -----------------------------
    unsigned char evil[64];
    memset(evil, 0, sizeof(evil));
    memcpy(evil, "__CLANG_OFFLOAD_BUNDLE__\0", 24);
    // version 5 at +24
    evil[24] = 5;
    // first entry: off=0 size=0 idLen=0xFFFFFF (way out of bounds)
    evil[32 + 16] = 0xFF;
    Wrapper w6 = {kHipfMagic, 1, evil, 0};
    void** h6 = regFn(&w6);
    CHECK(h6 != nullptr, "case6 register returned handle (oversized entry, fail closed)");
    unregFn(h6);

    // ---------------- inspect what the mock backend saw ----------------
    // The mock logs "MOCK __hipRegisterFatBinary data=%p"; the pointer the
    // MOCK received is the pointer the BRIDGE forwarded. Determine the
    // forwarded pointer from the log, then classify per call order.
    FILE* logf = nullptr;
    fopen_s(&logf, "mock_hip6.log", "r");
    CHECK(logf != nullptr, "mock log present");
    void* forwarded[8] = {nullptr};
    int nFwd = 0;
    if (logf) {
        char line[512];
        while (fgets(line, sizeof(line), logf)) {
            const char* hit = strstr(line, "MOCK __hipRegisterFatBinary data=");
            const void* p = nullptr;
            if (hit && sscanf(hit, "MOCK __hipRegisterFatBinary data=%p", &p) == 1) {
                if (nFwd < 8) {
                    forwarded[nFwd++] = (void*)p;
                }
            }
        }
        fclose(logf);
    }
    CHECK(nFwd >= 6, "mock saw 6 registrations");

    // The bridge forwards WRAPPER pointers. Pass-through keeps the exact
    // caller wrapper address; substitution forwards the bridge's own
    // static wrapper whose ->data is the embedded gfx1030 bundle.
    auto dataOf = [](const void* w) -> const unsigned char* {
        const void* d = nullptr;
        memcpy(&d, (const char*)w + 8, sizeof(d));
        return (const unsigned char*)d;
    };
    auto isOurBundle = [&](const void* w) {
        const unsigned char* b = dataOf(w);
        if (b == nullptr || memcmp(b, "__CLANG_OFFLOAD_BUNDLE__", 24) != 0) {
            return false;
        }
        // bounded, NUL-safe search for the gfx1030 identifier
        const char needle[] = "gfx1030";
        for (int i = 24; i < 4096; ++i) {
            if (memcmp(b + i, needle, sizeof(needle) - 1) == 0) {
                return true;
            }
        }
        return false;
    };
    CHECK(nFwd > 0 && forwarded[0] == (void*)&w1,
          "case1: original wrapper forwarded unchanged (gate off)");
    CHECK(nFwd > 1 && forwarded[1] != (void*)&w2 && isOurBundle(forwarded[1]),
          "case2: canonical gfx1030 bundle substituted (gate on)");
    CHECK(nFwd > 2 && forwarded[2] == (void*)&w3,
          "case3: unknown payload forwarded unchanged");
    CHECK(nFwd > 3 && forwarded[3] == (void*)&w4,
          "case4: truncated payload forwarded unchanged, no crash");
    CHECK(nFwd > 4 && forwarded[4] == (void*)&w4b,
          "case4b: wrong wrapper magic forwarded unchanged");
    CHECK(nFwd > 5 && forwarded[5] == (void*)&w5,
          "case5: wrong-hash payload forwarded unchanged (hash gate refused)");
    CHECK(nFwd > 6 && forwarded[6] == (void*)&w6,
          "case6: oversized-entry payload forwarded unchanged (fail closed)");

    // bridge log must show the decisions
    std::string blog = read_all_text("amdhip64_7_bridge.log");
    bool sawSub = blog.find("FATBIN_SUBSTITUTED") != std::string::npos;
    bool sawMatchNoSub = blog.find("FATBIN_MATCH_NO_SUBSTITUTION") != std::string::npos;
    bool sawNotOurs = blog.find("FATBIN_NOT_OURS") != std::string::npos;
    CHECK(sawMatchNoSub, "log: match without substitution (gate off)");
    CHECK(sawSub, "log: substitution recorded");
    CHECK(sawNotOurs, "log: not-ours decisions recorded");

    FreeLibrary(bridge);
    printf(failures == 0 ? "\nREGISTRATION SMOKE: ALL PASS\n"
                         : "\nREGISTRATION SMOKE: FAILURES=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
