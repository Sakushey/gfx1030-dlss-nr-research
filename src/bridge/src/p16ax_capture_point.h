// Phase 16AX -- THE WIRED ENTRY POINT.
//
// This is the ONLY symbol the shipping bridge source has to know about.  It is
// a single C-linkage function so the injected statement cannot half-configure
// the capture: the whole configuration (which directory, which mutation, which
// enable state) is read inside, from the environment, once.
//
// HOST-ONLY.  This translation unit includes the C runtime and <windows.h> for
// file creation.  It imports NOTHING from any HIP runtime, and it never calls
// into the backend.
#pragma once

extern "C" void raw_dump_16ax_capture_from_env(const char* identity,
                                               const void* function_address,
                                               void** args,
                                               unsigned launch_ordinal,
                                               const void* stream);
