// Phase 16AT RAW_DUMP -- recorder self-test host.
//
// Drives raw_dump::self_test() against a directory the caller owns and prints
// the steps as JSON. This is the "prove it can fail AND prove it passes"
// instrument for the RECORDER'S OWN checks, which is a different question from
// the eight capture controls.
//
// Usage: recorder_selftest.exe --dir <dir>
#include <windows.h>

#include <cstdio>
#include <cstring>

#include "raw_dump_recorder.h"

// Every string this host prints is a Windows path or a recorder reason string,
// so both backslashes and double quotes occur in them. Printing them raw
// produced JSON that would not parse; the runner re-parses this output, so it
// is escaped here.
static void put_json_string(const char* s)
{
    std::putchar('"');
    for (const char* q = s; q != nullptr && *q != '\0'; ++q) {
        unsigned char c = (unsigned char)*q;
        if (c == '\\' || c == '"') {
            std::printf("\\%c", c);
        } else if (c == '\n') {
            std::printf("\\n");
        } else if (c == '\r') {
            std::printf("\\r");
        } else if (c == '\t') {
            std::printf("\\t");
        } else if (c < 0x20) {
            std::printf("\\u%04x", c);
        } else {
            std::putchar((char)c);
        }
    }
    std::putchar('"');
}

int main(int argc, char** argv)
{
    const char* dir = ".";
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--dir") == 0) { dir = argv[i + 1]; }
    }
    CreateDirectoryA(dir, nullptr);
    SetEnvironmentVariableA("RAW_DUMP_DIR", dir);
    SetEnvironmentVariableA("RAW_DUMP", "1");
    SetEnvironmentVariableA("RAW_DUMP_KERNELS", "all");

    static raw_dump::SelfTestStep steps[16];
    std::size_t n = raw_dump::self_test(dir, steps, 16);

    std::printf("{\n \"schema\": \"p16at/raw-dump-recorder-selftest/1\",\n");
    std::printf(" \"dir\": ");
    put_json_string(dir);
    std::printf(",\n \"n_steps\": %zu,\n \"steps\": [\n", n);
    std::size_t passed = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (steps[i].ok) { ++passed; }
        std::printf("  { \"name\": ");
        put_json_string(steps[i].name);
        std::printf(", \"ok\": %s, \"detail\": ", steps[i].ok ? "true" : "false");
        put_json_string(steps[i].detail);
        std::printf(" }%s\n", (i + 1 == n) ? "" : ",");
    }
    std::printf(" ],\n \"n_passed\": %zu,\n \"all_passed\": %s\n}\n", passed,
                (passed == n && n > 0) ? "true" : "false");
    std::fflush(stdout);
    return (passed == n && n > 0) ? 0 : 1;
}
