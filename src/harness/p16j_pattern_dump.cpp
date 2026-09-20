// Host-only dump of the input pattern, so the C++ generator used by the
// physical harness and the Python generator used by the host reference can
// be proved identical instead of assumed identical.  No HIP call.
//
// Offsets are read from stdin, one unsigned decimal per line, and the
// pattern byte is printed for each.  Taking the offsets as input (rather
// than sweeping a range) is deliberate: the interesting cases are the
// uint32-wrap boundaries, and a range that spans them is not enumerable.
//
// usage: p16j_pattern_dump.exe <generator A|B>   (offsets on stdin)
#include "p16j_pattern.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv)
{
    const char gen = (argc > 1) ? argv[1][0] : 'A';
    char line[128];
    while (fgets(line, sizeof line, stdin)) {
        char* end = nullptr;
        unsigned long long i = strtoull(line, &end, 10);
        if (end == line) { continue; }
        unsigned b = (gen == 'B') ? pattern_b(i) : pattern_at(i);
        printf("%llu %u\n", i, b);
    }
    return 0;
}
