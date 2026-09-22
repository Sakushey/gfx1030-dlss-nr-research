// Phase 16AX -- implementation of the single wired entry point.
#include "p16ax_capture_point.h"

#include "raw_dump_repair_16ax.h"

extern "C" void raw_dump_16ax_capture_from_env(const char* identity,
                                               const void* function_address,
                                               void** args,
                                               unsigned launch_ordinal,
                                               const void* stream)
{
    rd16aw::capture_from_env(identity, function_address, args, launch_ordinal,
                             stream);
}
