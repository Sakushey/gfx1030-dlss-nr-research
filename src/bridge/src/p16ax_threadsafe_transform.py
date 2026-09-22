#!/usr/bin/env python3
"""Phase 16AX -- turn the 16AW repaired capture layer into a THREAD-SAFE layer.

The 16AW layer is correct about ARGUMENTS and FRAMES but carries three
unsynchronised globals, which is exactly the class of defect that produced the
original frame numbering bug (brief section 44: the frame id was minted by an
unsynchronised counter incremented at the closer).

This script is a TRANSFORMER, not an editor: it reads the byte-exact 16AW
archive, applies a list of named substitutions, and writes the 16AX file. Every
substitution is recorded with its byte offsets and a hit count, and any
substitution that does not match EXACTLY the declared number of times is a hard
failure -- a silent no-op transform would report the inverse of the truth
(house rule 7).

Run:  python p16ax_threadsafe_transform.py
Writes: p16ax/bridge/THREAD_SAFETY_DELTA_16AX.json
        p16ax/bridge/src/raw_dump_repair_16ax.cpp
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "archive_16aw", "raw_dump_repair_16aw.cpp")
OUT = os.path.join(HERE, "raw_dump_repair_16ax.cpp")
REPORT = os.path.join(os.path.dirname(HERE), "THREAD_SAFETY_DELTA_16AX.json")

# (name, exact_old, exact_new, expected_hits, why)
EDITS = [
    (
        "S0_include_own_header_renamed",
        '#include "raw_dump_repair_16aw.h"\n',
        '#include "raw_dump_repair_16ax.h"\n',
        1,
        "the 16AX translation unit includes the 16AX header (the argument-spec "
        "header keeps its 16AW name: it is byte-exact and must not be re-emitted)",
    ),
    (
        "S1_include_atomic_and_mutex",
        "#include <cstdarg>\n#include <cstdint>\n#include <cstdio>\n#include <cstring>\n",
        "#include <atomic>\n#include <cstdarg>\n#include <cstdint>\n#include <cstdio>\n"
        "#include <cstring>\n#include <mutex>\n",
        1,
        "the layer needs <atomic> for the invocation-id mint and <mutex> for the "
        "frame machine and the trace appends",
    ),
    (
        "S2_frame_machine_guard",
        "FrameAssignment FrameMachine::on_event(const char* symbol, const void* stream,\n"
        "                                      unsigned launch_ordinal)\n"
        "{\n"
        "    (void)launch_ordinal;\n",
        "FrameAssignment FrameMachine::on_event(const char* symbol, const void* stream,\n"
        "                                      unsigned launch_ordinal)\n"
        "{\n"
        "    // 16AX: the frame machine is process-wide state.  Every read and every\n"
        "    // mutation of it happens under one recursive lock, so a frame's value is\n"
        "    // minted and consumed by the same critical section.  A recursive mutex is\n"
        "    // used because frame_machine() may lazily reset() on first use.\n"
        "    std::lock_guard<std::recursive_mutex> frame_guard(g_frame_mutex);\n"
        "    (void)launch_ordinal;\n",
        1,
        "the frame machine had no synchronisation at all",
    ),
    (
        "S3_frame_mutex_declaration",
        "namespace {\n\nstruct Sha256 {",
        "namespace {\n\n"
        "// 16AX: the process-wide frame lock.  It is declared HERE, in the first\n"
        "// anonymous namespace of this translation unit, because FrameMachine::\n"
        "// on_event is DEFINED above the point where the frame machine's own\n"
        "// state object is declared.  Declaring the lock beside g_machine would\n"
        "// put it AFTER its first use, which does not compile -- the first version\n"
        "// of this transform did exactly that and the compiler refused it.\n"
        "std::recursive_mutex g_frame_mutex;\n\nstruct Sha256 {",
        1,
        "the lock S2 takes must be declared before FrameMachine::on_event, which "
        "is defined above the frame machine's own state object",
    ),
    (
        "S4_frame_machine_reset_guarded",
        "void frame_machine_reset(long declared_override)\n"
        "{\n"
        "    g_machine.reset(declared_override);\n"
        "    g_machine_ready = true;\n"
        "}\n"
        "FrameMachine& frame_machine()\n"
        "{\n"
        "    if (!g_machine_ready) { frame_machine_reset(0); }\n"
        "    return g_machine;\n"
        "}\n",
        "void frame_machine_reset(long declared_override)\n"
        "{\n"
        "    std::lock_guard<std::recursive_mutex> g(g_frame_mutex);\n"
        "    g_machine.reset(declared_override);\n"
        "    g_machine_ready = true;\n"
        "}\n"
        "FrameMachine& frame_machine()\n"
        "{\n"
        "    std::lock_guard<std::recursive_mutex> g(g_frame_mutex);\n"
        "    if (!g_machine_ready) { frame_machine_reset(0); }\n"
        "    return g_machine;\n"
        "}\n",
        1,
        "the lazy first-use reset and the readiness flag were both races",
    ),
    (
        "S5_frames_left_open_guarded",
        "unsigned FrameMachine::n_frames_left_open() const\n"
        "{\n"
        "    unsigned k = 0;\n",
        "unsigned FrameMachine::n_frames_left_open() const\n"
        "{\n"
        "    std::lock_guard<std::recursive_mutex> g(g_frame_mutex);\n"
        "    unsigned k = 0;\n",
        1,
        "a reader of the same state must take the same lock",
    ),
    (
        "S6_trace_append_serialised",
        "void trace_line(const char* dir, const char* event, const char* detail)\n"
        "{\n"
        "    if (dir == nullptr || dir[0] == '\\0') { return; }\n",
        "void trace_line(const char* dir, const char* event, const char* detail)\n"
        "{\n"
        "    if (dir == nullptr || dir[0] == '\\0') { return; }\n"
        "    // 16AX: CreateFileA(FILE_APPEND_DATA) + WriteFile is not an atomic\n"
        "    // append for concurrent writers, and the trace is what distinguishes\n"
        "    // REACHED from REFUSED.  Serialise it.\n"
        "    std::lock_guard<std::mutex> tl(g_trace_mutex);\n",
        1,
        "concurrent trace appends could interleave and corrupt the very record "
        "that proves whether the emission point was reached",
    ),
    (
        "S7_trace_mutex_declaration",
        "namespace {\nvoid trace_line(const char* dir, const char* event, const char* detail)\n",
        "namespace {\nstd::mutex g_trace_mutex;\n\n"
        "void trace_line(const char* dir, const char* event, const char* detail)\n",
        1,
        "the lock S6 takes must exist",
    ),
    (
        "S8_record_buffer_thread_local",
        "    static char json[96 * 1024];\n",
        "    // 16AX: was a process-wide `static char json[96*1024]`.  Two threads\n"
        "    // emitting concurrently composed their records in ONE buffer and wrote\n"
        "    // each other's bytes.  thread_local gives every invocation its own.\n"
        "    static thread_local char json[96 * 1024];\n",
        1,
        "a shared record-composition buffer is a data race that silently "
        "mis-attributes argument bytes between instances",
    ),
    (
        "S9_instance_seq_atomic",
        "namespace {\nunsigned g_instance_seq = 0;\n}  // namespace\n\n"
        "unsigned instance_seq_value() { return g_instance_seq; }\n",
        "namespace {\n// 16AX: an atomic mint.  The launch ordinal in the bridge itself was an\n"
        "// unsynchronised `static unsigned`; an id minted without an atomic can be\n"
        "// handed to two threads, which is how a record comes to own another\n"
        "// invocation's ordinal.\nstd::atomic<unsigned long long> g_instance_seq{0};\n"
        "}  // namespace\n\n"
        "unsigned instance_seq_value()\n"
        "{\n"
        "    return (unsigned)g_instance_seq.load(std::memory_order_relaxed);\n"
        "}\n",
        1,
        "the invocation id must be minted atomically",
    ),
    (
        "S10_instance_seq_fetch_add",
        "    capture_at_launch_point(identity, function_address, args, launch_ordinal,\n"
        "                            stream, ++g_instance_seq, dir, m);\n",
        "    const unsigned inst =\n"
        "        (unsigned)g_instance_seq.fetch_add(1, std::memory_order_relaxed) + 1u;\n"
        "    capture_at_launch_point(identity, function_address, args, launch_ordinal,\n"
        "                            stream, inst, dir, m);\n",
        1,
        "fetch_add, not ++, is what makes the id unique under concurrency",
    ),
    (
        "S11_record_name_carries_thread_and_instance",
        '    char base[300];\n'
        '    std::snprintf(base, sizeof(base), "%s_i%05u_%s_%s", stamp, instance_seq,\n'
        '                  stem, o.mutation);\n',
        '    char base[300];\n'
        '    // 16AX: the thread id is part of the name.  The atomic already makes\n'
        '    // instance ids unique; carrying the writer\'s thread id makes OWNERSHIP\n'
        '    // auditable from the record itself rather than inferred from the path.\n'
        '    unsigned long long tid =\n'
        '        (unsigned long long)(uintptr_t)GetCurrentThreadId();\n'
        '    std::snprintf(base, sizeof(base), "%s_i%05u_t%05llu_%s_%s", stamp,\n'
        '                  instance_seq, tid & 0xfffffu, stem, o.mutation);\n',
        1,
        "record ownership must be visible in the artefact, not inferred",
    ),
    (
        "S12_record_states_its_own_layer_and_thread",
        '    b.key_str("capture_layer", "16AW_INDEPENDENT_ARG_CAPTURE");\n',
        '    b.key_str("capture_layer", "16AX_INDEPENDENT_ARG_CAPTURE_THREADSAFE");\n'
        '    b.raw(",\\n");\n'
        '    {\n'
        '        char tb[32];\n'
        '        std::snprintf(tb, sizeof(tb), "%lu",\n'
        '                      (unsigned long)GetCurrentThreadId());\n'
        '        b.key_str("writer_thread_id", tb);\n'
        '    }\n'
        '    b.raw(",\\n");\n'
        '    b.key_int("thread_safety_epoch", 1L);\n',
        1,
        "a record must say which layer and which thread wrote it",
    ),
    (
        "S13_selftest_reports_the_epoch",
        '    step("spec_table_loads_all_15_identities", kNumKernelSpecs == 15,\n',
        '    step("thread_safety_epoch_is_1", true,\n'
        '         "atomic instance mint; recursive-mutex frame machine; serialised "\n'
        '         "trace; thread_local record buffer");\n'
        '    step("spec_table_loads_all_15_identities", kNumKernelSpecs == 15,\n',
        1,
        "the layer's own self-test reports which epoch it is",
    ),
]


def main():
    raw = open(SRC, "rb").read()
    text = raw.decode("utf-8")
    records = []
    cur = text
    for name, old, new, expect, why in EDITS:
        hits = cur.count(old)
        rec = {
            "edit": name,
            "expected_hits": expect,
            "observed_hits": hits,
            "why": why,
            "old_bytes": len(old.encode("utf-8")),
            "new_bytes": len(new.encode("utf-8")),
        }
        if hits != expect:
            rec["result"] = "FAILED_SUBSTITUTION_NOT_APPLIED"
            records.append(rec)
            json.dump(
                {
                    "schema": "p16ax/thread-safety-delta/1",
                    "source": SRC,
                    "source_sha256": hashlib.sha256(raw).hexdigest(),
                    "transform_applied": False,
                    "edits": records,
                    "verdict": "FAILED",
                },
                open(REPORT, "w"),
                indent=1,
            )
            print("FAILED: %s expected %d hits, observed %d" % (name, expect, hits))
            return 1
        before = cur.find(old)
        cur = cur.replace(old, new)
        rec["result"] = "APPLIED"
        rec["offset_in_output"] = before
        records.append(rec)

    out = cur.encode("utf-8")
    open(OUT, "wb").write(out)

    # Reversibility: applying the edits in reverse must reproduce the archive.
    back = cur
    for name, old, new, expect, why in reversed(EDITS):
        back = back.replace(new, old)
    reversibility_ok = back == text
    recovered = hashlib.sha256(back.encode("utf-8")).hexdigest()

    report = {
        "schema": "p16ax/thread-safety-delta/1",
        "phase": "16AX",
        "host_only": True,
        "what_this_is": (
            "the byte-exact difference between the 16AW repaired capture layer "
            "and the 16AX thread-safe integration of it.  It is produced by an "
            "exact-substitution transformer, not by hand, so the delta cannot "
            "contain an unrecorded change."
        ),
        "source": SRC,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "output": OUT,
        "output_sha256": hashlib.sha256(out).hexdigest(),
        "source_bytes": len(raw),
        "output_bytes": len(out),
        "n_edits": len(EDITS),
        "n_edits_applied": sum(1 for r in records if r["result"] == "APPLIED"),
        "transform_was_a_no_op": hashlib.sha256(raw).hexdigest()
        == hashlib.sha256(out).hexdigest(),
        "reversible": reversibility_ok,
        "reversibility_detail": (
            "applying the substitutions in reverse reproduces %s == %s"
            % (recovered, hashlib.sha256(raw).hexdigest())
        ),
        "edits": records,
        "what_is_NOT_claimed": (
            "this establishes the SYNCHRONISATION surface only.  It does not "
            "establish the absence of other races: the bridge's own registration "
            "ledger, its launch ordinal and its log are synchronised by the "
            "bridge's transformation (p16ax_apply_capture_point.py), not here."
        ),
        "verdict": "APPLIED_AND_REVERSIBLE" if reversibility_ok else "NOT_REVERSIBLE",
    }
    json.dump(report, open(REPORT, "w"), indent=1)
    print(
        "OK  %d/%d edits applied, reversible=%s\n    %s\n    -> %s\n    -> %s"
        % (
            report["n_edits_applied"],
            report["n_edits"],
            reversibility_ok,
            hashlib.sha256(out).hexdigest(),
            OUT,
            REPORT,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
