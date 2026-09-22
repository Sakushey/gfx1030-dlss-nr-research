// Phase 16AT RAW_DUMP -- the four defect-injection points.
//
// The eight required controls (brief IX section 50) include five that are
// defects IN the capture itself: a one-byte shift, a truncation, a wrong
// declared size, a wrong launch ordinal and a wrong kernel identity. Those are
// produced the way phase16y produced its mutation arms -- by generating a
// mutant of the shipping source and compiling it -- rather than by #ifdefs
// buried in the logic that ships.
//
// So the shipping source routes each of those four quantities through one of
// the macros below. In the shipping build every macro is the identity. The
// mutant generator (p16at_emit_mutants.py) rewrites exactly ONE macro body per
// mutant by exact-text substitution, and refuses to emit a mutant unless the
// parent body occurred exactly once and the mutant's bytes differ from the
// parent's. The whole injection surface is these four lines, so "the mutant
// differs from the parent in exactly one recorded place" is a checkable claim.
#ifndef RAWD_BLOB_POINTER
#define RAWD_BLOB_POINTER(p) (p)
#endif
#ifndef RAWD_BLOB_LENGTH
#define RAWD_BLOB_LENGTH(n) (n)
#endif
#ifndef RAWD_LAUNCH_ORDINAL
#define RAWD_LAUNCH_ORDINAL(n) (n)
#endif
#ifndef RAWD_KERNEL_IDENTITY
#define RAWD_KERNEL_IDENTITY(s) (s)
#endif
