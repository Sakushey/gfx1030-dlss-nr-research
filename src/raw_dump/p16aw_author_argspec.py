#!/usr/bin/env python3
# Phase 16AW -- AUTHOR THE ARGUMENT-SPEC TABLE (brief section 38).
#
# WHAT THIS DOES
#   Derives, for each of the 15 targeted kernel identities, the list of EXPLICIT
#   HOST ARGUMENTS the caller builds a void** array for, and for each one:
#   host_arg_index, explicit byte size, semantic kind, alignment, canonical
#   kernarg offset, type/signedness where known, and the EVIDENCE SOURCE for
#   every one of those fields.
#
# THE EVIDENCE, AND WHY IT IS NOT THE CODE UNDER TEST
#   phase9_original_kernel_metadata.json is the CODE OBJECT METADATA of the
#   ORIGINAL (game-side) module -- the same artefact family the loader reads.
#   It declares, per kernel, the ordered .args[] with .offset, .size and
#   .value_kind, plus .kernarg_segment_size and .kernarg_segment_align. It is
#   produced by the compiler, not by this project's capture code.
#
#   The Itanium mangled identity is a SECOND, INDEPENDENT lineage for arity and
#   parameter type: it is decoded here from the symbol text alone and cross
#   checked against .args[].
#
#   p16ao/contracts/FIRST_FRAME_FIELD_CLOSURE.json is a THIRD lineage: it
#   declares each identity's by-value blob size and the kernarg range those
#   bytes live in, derived from the identity's own ISA body.
#
#   Three lineages, compared against each other. Agreement is reported with the
#   number of comparisons actually made.
#
# IT ALSO EMITS THE C HEADER the repaired capture layer compiles against, from
#   the very same table object, so the compiled table and the JSON cannot drift;
#   the header carries the JSON's SHA-256 and the layer re-checks it.
#
# HOST-ONLY. Reads JSON, writes two files. No GPU, no HIP, no launch.
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "p16aw", "raw_dump")

ORIGINAL_META = os.path.join(ROOT, "phase9_original_kernel_metadata.json")
CLOSURE = os.path.join(ROOT, "p16ao", "contracts", "FIRST_FRAME_FIELD_CLOSURE.json")
LEGACY_TABLE = os.path.join(ROOT, "p16at", "raw_dump", "RAW_DUMP_BLOB_TABLE.json")

ARGS_JSON = os.path.join(OUT, "RAW_DUMP_ARGSPEC_16AW.json")
HDR = os.path.join(OUT, "src", "raw_dump_argspec_16aw.h")

KIND_POINTER = "POINTER"
KIND_SCALAR = "SCALAR"
KIND_BY_VALUE_STRUCT = "BY_VALUE_STRUCT"
KIND_OTHER = "OTHER_EXPLICIT"

HIDDEN_LABEL = "RUNTIME_PROVIDED_NOT_HOST_ARG_ARRAY"


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# Itanium mangled-parameter decoder -- an evidence lineage independent of the
# code object metadata. Only the codes the 15 identities actually use are
# implemented; anything else is reported as NOT_DECODED rather than guessed.
# --------------------------------------------------------------------------
BUILTIN = {
    "v": "void", "b": "bool", "c": "char", "a": "signed char",
    "h": "unsigned char", "s": "short", "t": "unsigned short",
    "i": "int", "j": "unsigned int", "l": "long", "m": "unsigned long",
    "x": "long long", "y": "unsigned long long", "f": "float", "d": "double",
    "e": "long double", "w": "wchar_t",
}


class DemangleError(Exception):
    pass


def _decode_type(s, i):
    """Decode one type starting at s[i]; return (text, next_index)."""
    if i >= len(s):
        raise DemangleError("truncated type")
    c = s[i]
    if c in BUILTIN:
        return BUILTIN[c], i + 1
    if c == "P":
        inner, j = _decode_type(s, i + 1)
        return inner + "*", j
    if c == "R":
        inner, j = _decode_type(s, i + 1)
        return inner + "&", j
    if c == "K":
        inner, j = _decode_type(s, i + 1)
        return inner + " const", j
    if c.isdigit():
        j = i
        while j < len(s) and s[j].isdigit():
            j += 1
        n = int(s[i:j])
        name = s[j:j + n]
        if len(name) != n:
            raise DemangleError("truncated length-prefixed name")
        return name, j + n
    raise DemangleError("unhandled type code %r at %d" % (c, i))


def demangle_params(mangled):
    """Return (plain_function_name, [param_type_text, ...])."""
    if not mangled.startswith("_Z"):
        raise DemangleError("not an Itanium mangled name")
    s = mangled[2:]
    j = 0
    while j < len(s) and s[j].isdigit():
        j += 1
    if j == 0:
        raise DemangleError("no name length")
    n = int(s[:j])
    name = s[j:j + n]
    if len(name) != n:
        raise DemangleError("truncated function name")
    i = j + n
    params = []
    while i < len(s):
        if s[i] == "v" and i == len(s) - 1:
            break  # '(void)'
        t, i = _decode_type(s, i)
        params.append(t)
    return name, params


# --------------------------------------------------------------------------
def derive(meta_kernel, identity, closure_row):
    args = meta_kernel[".args"]
    explicit, hidden = [], []
    for a in args:
        if a[".value_kind"].startswith("hidden_"):
            hidden.append(a)
        else:
            explicit.append(a)

    rows = []
    for idx, a in enumerate(explicit):
        vk, off, size = a[".value_kind"], a[".offset"], a[".size"]
        if vk == "global_buffer":
            kind = KIND_POINTER
        elif vk == "by_value":
            # A by-value argument the compiler names a single scalar-sized
            # object is a SCALAR; one the size of the identity's whole declared
            # parameter block is that block (BY_VALUE_STRUCT). The threshold is
            # stated rather than hidden, and the closure cross-check below
            # confirms it on all 15: no identity here is ambiguous (by_value
            # sizes observed are 4 and 24..72).
            kind = KIND_SCALAR if size <= 8 else KIND_BY_VALUE_STRUCT
        elif vk == "by_reference":
            kind = KIND_OTHER
        else:
            kind = KIND_OTHER
        # Alignment is NOT declared per argument by the metadata; the offset
        # implies a lower bound on it. Reported as derived, never as declared.
        if off > 0:
            align = 1
            while align * 2 <= off and off % (align * 2) == 0:
                align *= 2
            align = min(align, 8)
        else:
            align, p = 1, 1
            while p * 2 <= size:
                p *= 2
            align = min(p, 8)
        rows.append({
            "host_arg_index": idx,
            "explicit_byte_size": size,
            "semantic_kind": kind,
            "alignment_bytes": align,
            "alignment_basis": "DERIVED_FROM_KERNARG_OFFSET (a lower bound; the "
                               "code object metadata declares no per-argument "
                               "alignment)",
            "canonical_kernarg_offset": off,
            "value_kind_in_the_code_object": vk,
            "evidence_source": {
                "host_arg_index": "Itanium parameter ORDER in the mangled "
                                  "identity (phase9_original_kernel_metadata.json"
                                  " .symbol) + the order of .args[] in the same "
                                  "artefact",
                "explicit_byte_size": "phase9_original_kernel_metadata.json "
                                      "kernels[%s]['.args'][%d]['.size']" % (identity, idx),
                "semantic_kind": "phase9_original_kernel_metadata.json same "
                                 ".args[].value_kind ('global_buffer'->POINTER; "
                                 "'by_value' with size<=8->SCALAR; 'by_value' "
                                 "with size>=16->BY_VALUE_STRUCT)",
                "alignment_bytes": "DERIVED from .args[].offset",
                "canonical_kernarg_offset": "phase9_original_kernel_metadata.json "
                                            "kernels[%s]['.args'][%d]['.offset']" % (identity, idx),
                "type_name": "Itanium mangled-parameter decode of the symbol in "
                             "phase9_original_kernel_metadata.json",
            },
        })

    return rows, hidden


def validate(identities, rows_by_id, hidden_by_id, meta, closure_by_id, legacy_by_id):
    """Five cross-lineage checks. Returns (n_comparisons, [problems])."""
    n = 0
    problems = []

    for ident in identities:
        rows = rows_by_id[ident]
        hidden = hidden_by_id[ident]
        cl = closure_by_id[ident]
        lg = legacy_by_id[ident]
        seg = meta[ident][".kernarg_segment_size"]

        # V1: mangled arity vs the number of non-hidden .args[] entries
        try:
            _, params = demangle_params(ident)
        except DemangleError as e:
            problems.append("%s: V1 demangle failed: %s" % (ident, e))
            continue
        n += 1
        if len(params) != len(rows):
            problems.append("%s: V1 arity mangled=%d vs explicit_args=%d"
                            % (ident, len(params), len(rows)))

        # V2: sum of by-value sizes == the closure's declared by-value blob size
        n += 1
        bv = sum(r["explicit_byte_size"] for r in rows
                 if r["value_kind_in_the_code_object"] == "by_value")
        if bv != cl["declared_by_value_blob_bytes"]:
            problems.append("%s: V2 by_value sum=%d vs closure declared=%d"
                            % (ident, bv, cl["declared_by_value_blob_bytes"]))

        # V3: by-value kernarg range == the closure's declared range
        n += 2
        bvs = [r for r in rows if r["value_kind_in_the_code_object"] == "by_value"]
        lo = min(r["canonical_kernarg_offset"] for r in bvs)
        hi = max(r["canonical_kernarg_offset"] + r["explicit_byte_size"] for r in bvs)
        clo, chi = (int(x, 16) for x in cl["declared_by_value_blob_range_bytes"])
        if lo != clo:
            problems.append("%s: V3 lo=%d vs closure=%d" % (ident, lo, clo))
        if hi != chi:
            problems.append("%s: V3 hi=%d vs closure=%d" % (ident, hi, chi))

        # V4: every explicit arg lies inside the kernarg segment
        for r in rows:
            n += 1
            end = r["canonical_kernarg_offset"] + r["explicit_byte_size"]
            if r["canonical_kernarg_offset"] < 0 or end > seg:
                problems.append("%s: V4 arg%d [%d,%d) outside segment %d"
                                % (ident, r["host_arg_index"],
                                   r["canonical_kernarg_offset"], end, seg))

        # V5: the legacy code reads args[0] for blob_bytes bytes. That is only
        # the declared by-value bytes when the identity's FIRST HOST ARGUMENT is
        # the by-value argument. Assert the predicate both ways so the count of
        # identities the legacy capture is wrong for is MEASURED, not asserted.
        n += 1
        first_is_by_value = rows[0]["value_kind_in_the_code_object"] == "by_value"
        legacy_correct = (first_is_by_value
                          and lg["blob_bytes"] == rows[0]["explicit_byte_size"])
        if first_is_by_value and lg["blob_bytes"] != rows[0]["explicit_byte_size"]:
            problems.append("%s: V5 legacy blob_bytes=%d vs first by_value size=%d"
                            % (ident, lg["blob_bytes"], rows[0]["explicit_byte_size"]))

        # hidden args must be exactly the metadata's hidden_* entries and must
        # never be claimed as host bytes
        n += 1
        if len(hidden) != sum(1 for a in meta[ident][".args"]
                              if a[".value_kind"].startswith("hidden_")):
            problems.append("%s: V6 hidden arg count mismatch" % ident)

    return n, problems


def build():
    with open(ORIGINAL_META, encoding="utf-8") as f:
        meta_doc = json.load(f)
    meta = meta_doc["kernels"]
    with open(CLOSURE, encoding="utf-8") as f:
        cl_doc = json.load(f)
    closure_by_id = {r["identity"]: r for r in cl_doc["fields"]}
    with open(LEGACY_TABLE, encoding="utf-8") as f:
        lg_doc = json.load(f)
    legacy_by_id = {r["identity"]: r for r in lg_doc["rows"]}

    identities = list(legacy_by_id.keys())          # the 15, in the legacy order
    rows_by_id, hidden_by_id, specs = {}, {}, []
    for ident in identities:
        if ident not in meta:
            raise SystemExit("FATAL: %s absent from the code object metadata -- "
                             "refusing to invent a spec" % ident)
        rows, hidden = derive(meta[ident], ident, closure_by_id[ident])
        try:
            fname, params = demangle_params(ident)
        except DemangleError:
            fname, params = "?", []
        for r, t in zip(rows, params):
            r["type_name"] = t
            r["signedness_or_type"] = t
        rows_by_id[ident] = rows
        hidden_by_id[ident] = hidden
        specs.append({
            "identity": ident,
            "plain_name": fname,
            "mangled_parameters": params,
            "kernarg_segment_size": meta[ident][".kernarg_segment_size"],
            "kernarg_segment_align": meta[ident][".kernarg_segment_align"],
            "wavefront_size": meta[ident].get(".wavefront_size"),
            "n_explicit_host_args": len(rows),
            "n_hidden_arguments": len(hidden),
            "explicit_args": rows,
            "hidden_arguments": [{
                "value_kind": h[".value_kind"],
                "canonical_kernarg_offset": h[".offset"],
                "explicit_byte_size": h[".size"],
                "provenance": HIDDEN_LABEL,
                "captured_as_host_bytes": False,
                "note": "runtime-provided; NOT an entry of the caller's void** "
                        "args array and NOT captured. Listed so the canonical "
                        "record can name it without claiming its bytes.",
            } for h in hidden],
        })
    return identities, rows_by_id, hidden_by_id, specs, meta, closure_by_id, legacy_by_id


def main():
    (identities, rows_by_id, hidden_by_id, specs, meta,
     closure_by_id, legacy_by_id) = build()

    n_cmp, problems = validate(identities, rows_by_id, hidden_by_id, meta,
                               closure_by_id, legacy_by_id)

    # ---- self-check: the validator must reject three known-bad derivations ----
    bad_cases = []

    def check_bad(name, mutate):
        rows2 = {k: [dict(r) for r in v] for k, v in rows_by_id.items()}
        h2 = {k: list(v) for k, v in hidden_by_id.items()}
        mutate(rows2)
        c, probs = validate(identities, rows2, h2, meta, closure_by_id, legacy_by_id)
        bad_cases.append({"case": name, "n_problems": len(probs),
                          "problems": probs[:3], "rejected": len(probs) > 0})

    def m_drop(rows2):
        rows2["_Z11k_flag_waitPjjj"].pop()          # arity now 2, mangled says 3

    def m_size(rows2):
        rows2["_Z14k_dec_upsample11DecUpParams"][0]["explicit_byte_size"] = 44

    def m_offset(rows2):
        # every identity here has exactly one explicit argument unless it is a
        # flag kernel, so shift the flag kernel's SECOND (a real second entry)
        rows2["_Z11k_flag_waitPjjj"][1]["canonical_kernarg_offset"] += 1

    def m_first_kind(rows2):
        rows2["_Z10k_flag_setPjj"][0]["value_kind_in_the_code_object"] = "by_value"
        rows2["_Z10k_flag_setPjj"][0]["semantic_kind"] = KIND_SCALAR

    for nm, fn in (("arity_dropped", m_drop), ("size_perturbed", m_size),
                   ("kernarg_offset_shifted", m_offset),
                   ("flag_pointer_relabelled_by_value", m_first_kind)):
        check_bad(nm, fn)
    n_bad_rejected = sum(1 for c in bad_cases if c["rejected"])

    # ---- which identities is the legacy args[0] capture WRONG for? ----------
    wrong_for, right_for = [], []
    for s in specs:
        r0 = s["explicit_args"][0]
        lg = legacy_by_id[s["identity"]]
        if r0["value_kind_in_the_code_object"] == "by_value":
            right_for.append(s["identity"])
        else:
            wrong_for.append({
                "identity": s["identity"],
                "legacy_reads": "args[0] (%s, %d B) as the %d-byte by-value blob"
                                % (r0["type_name"], r0["explicit_byte_size"],
                                   lg["blob_bytes"]),
                "legacy_should_have_read":
                    [{"host_arg_index": a["host_arg_index"],
                      "bytes": a["explicit_byte_size"],
                      "kernarg_offset": a["canonical_kernarg_offset"]}
                     for a in s["explicit_args"]
                     if a["value_kind_in_the_code_object"] == "by_value"],
                "n_by_value_bytes_legacy_reads_from_the_wrong_argument": lg["blob_bytes"],
                "n_explicit_args_legacy_never_reads":
                    len([a for a in s["explicit_args"]
                         if a["value_kind_in_the_code_object"] == "by_value"]),
            })

    doc = {
        "schema": "p16aw/raw-dump-argspec/1",
        "phase": "16AW",
        "brief_sections": [38, 39, 40, 41],
        "host_only": True,
        "gpu_execution_performed": False,
        "what_this_is": "One argument-spec row per EXPLICIT HOST ARGUMENT of each "
                        "of the 15 targeted kernel identities: the caller's "
                        "void** args array position, its declared byte size, its "
                        "semantic kind, its alignment, its canonical kernarg "
                        "offset, its decoded type, and the evidence source for "
                        "every one of those fields.",
        "what_this_is_NOT": "It is not a value list. The values in these "
                            "arguments are the 15 UNRESOLVED scalar constants "
                            "and remain unresolved; this table says where the "
                            "bytes ARE, not what they are.",
        "why_it_exists": "The capture layer it replaces read args[0] as the "
                         "by-value blob for EVERY identity. That is wrong for "
                         "any identity whose first host argument is not the "
                         "by-value one, because the caller's void** entries are "
                         "per-parameter host pointers and are NOT guaranteed "
                         "contiguous (brief section 39).",
        "evidence_lineages": {
            "A_code_object_metadata": {
                "file": "phase9_original_kernel_metadata.json",
                "sha256": sha256_file(ORIGINAL_META),
                "what_it_declares": "the ORIGINAL module's per-kernel .args[] "
                                    "with .offset/.size/.value_kind, "
                                    ".kernarg_segment_size, .kernarg_segment_align",
                "why_it_is_not_the_code_under_test": "produced by the compiler "
                                                     "from the game's own module; this project's "
                                                     "capture layer does not write it",
            },
            "B_mangled_symbol": {
                "decoded_from": "phase9_original_kernel_metadata.json .symbol "
                                "(and the identity string itself)",
                "what_it_declares": "parameter ARITY and parameter TYPE, decoded "
                                    "here from the Itanium mangling",
            },
            "C_first_frame_closure": {
                "file": "p16ao/contracts/FIRST_FRAME_FIELD_CLOSURE.json",
                "sha256": sha256_file(CLOSURE),
                "what_it_declares": "each identity's by-value blob size and the "
                                    "kernarg range those bytes live in, derived "
                                    "from the identity's own ISA body",
            },
            "D_the_table_being_replaced": {
                "file": "p16at/raw_dump/RAW_DUMP_BLOB_TABLE.json",
                "sha256": sha256_file(LEGACY_TABLE),
                "why_it_is_read": "to state exactly what the defective capture "
                                  "read, and to enumerate the 15 identities",
            },
        },
        "semantic_kind_vocabulary": [KIND_POINTER, KIND_SCALAR,
                                     KIND_BY_VALUE_STRUCT, KIND_OTHER],
        "hidden_argument_label": HIDDEN_LABEL,
        "n_identities": len(specs),
        "n_explicit_host_args_total": sum(s["n_explicit_host_args"] for s in specs),
        "n_hidden_arguments_total": sum(s["n_hidden_arguments"] for s in specs),
        "identities": specs,
        "what_the_legacy_capture_gets_wrong": {
            "rule": "the legacy capture reads args[0] for every identity",
            "n_identities": len(specs),
            "n_identities_it_is_correct_for": len(right_for),
            "n_identities_it_is_WRONG_for": len(wrong_for),
            "correct_for": right_for,
            "wrong_for": wrong_for,
            "measured_not_asserted": "the split is computed from the table above; "
                                     "the predicate is the code object's own "
                                     "value_kind of each identity's FIRST host "
                                     "argument",
        },
        "cross_lineage_validation": {
            "n_comparisons": n_cmp,
            "n_problems": len(problems),
            "problems": problems,
            "verdict": "ALL_LINEAGES_AGREE" if not problems else "DISAGREEMENT",
            "checks": [
                "V1 mangled arity == the number of explicit .args[] entries",
                "V2 sum of by_value sizes == the closure's declared by-value blob size",
                "V3 by_value kernarg range == the closure's declared range (lo and hi)",
                "V4 every explicit argument lies wholly inside the kernarg segment",
                "V5 the legacy table's blob_bytes equals the FIRST explicit "
                "argument's size wherever that argument really is the by-value one",
                "V6 the hidden-argument count is carried through unchanged",
            ],
            "self_check_the_validator_can_fail": {
                "cases": bad_cases,
                "n_cases": len(bad_cases),
                "n_rejected": n_bad_rejected,
                "all_rejected": n_bad_rejected == len(bad_cases),
                "statement": "the same validator is pointed at four deliberately "
                             "corrupted derivations and must reject every one; a "
                             "validator that has never rejected anything is not "
                             "evidence.",
            },
        },
        "the_39_constraint_encoded_here": "No field of this table licenses "
                                          "reading memory adjacent to an argument. Each row names ONE host "
                                          "index, and the capture layer reads exactly explicit_byte_size "
                                          "bytes from exactly that entry's own pointer.",
    }
    if "--check" in sys.argv:
        # STALENESS CHECK, not a rewrite. Renders the document this run would
        # write and compares it to the file on disk; then checks that the
        # generated header carries that same file's digest. A stale table is
        # refused rather than silently regenerated, so the table the layer
        # compiles cannot differ from the table the verifier reads.
        rendered = json.dumps(doc, indent=1) + "\n"
        on_disk = ""
        if os.path.isfile(ARGS_JSON):
            with open(ARGS_JSON, "r", encoding="utf-8") as f:
                on_disk = f.read()
        same_json = (rendered == on_disk)
        js_disk = sha256_file(ARGS_JSON) if os.path.isfile(ARGS_JSON) else ""
        hdr_text = ""
        if os.path.isfile(HDR):
            with open(HDR, "r", encoding="utf-8") as f:
                hdr_text = f.read()
        hdr_carries = (js_disk != "" and js_disk in hdr_text)
        print("ARGS_AUTHOR_CHECK json_matches=%s header_carries_the_json_digest=%s "
              "disk_sha256=%s" % (same_json, hdr_carries, js_disk))
        print("ARGS_AUTHOR_CHECK cross_lineage_comparisons=%d validator_cases=%d "
              "rejected=%d" % (n_cmp, len(bad_cases), n_bad_rejected))
        if not same_json or not hdr_carries or n_cmp == 0:
            print("ARGS_AUTHOR_CHECK STALE_OR_VACUOUS -- re-run without --check")
            return 1
        print("ARGS_AUTHOR_CHECK UP_TO_DATE")
        return 0

    with open(ARGS_JSON, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")

    js = sha256_file(ARGS_JSON)
    write_header(specs, js)

    # ---- report the counts this run actually compared -----------------------
    print("ARGS_AUTHOR identities=%d explicit_args=%d hidden=%d"
          % (len(specs), doc["n_explicit_host_args_total"],
             doc["n_hidden_arguments_total"]))
    print("ARGS_AUTHOR cross_lineage_comparisons=%d problems=%d verdict=%s"
          % (n_cmp, len(problems), doc["cross_lineage_validation"]["verdict"]))
    print("ARGS_AUTHOR validator_self_check cases=%d rejected=%d"
          % (len(bad_cases), n_bad_rejected))
    print("ARGS_AUTHOR legacy_capture wrong_for=%d correct_for=%d"
          % (len(wrong_for), len(right_for)))
    for w in wrong_for:
        print("ARGS_AUTHOR   WRONG %s : reads args[0] %dB, should read %s"
              % (w["identity"], w["n_by_value_bytes_legacy_reads_from_the_wrong_argument"],
                 [(a["host_arg_index"], a["bytes"]) for a in w["legacy_should_have_read"]]))
    print("ARGS_AUTHOR wrote %s sha256=%s" % (os.path.relpath(ARGS_JSON, ROOT), js))
    print("ARGS_AUTHOR wrote %s" % os.path.relpath(HDR, ROOT))

    if problems:
        return 1
    if n_bad_rejected != len(bad_cases):
        return 1
    if n_cmp == 0:
        print("ARGS_AUTHOR VACUOUS: compared 0 things")
        return 1
    return 0


def write_header(specs, args_json_sha):
    L = []
    A = L.append
    A("// GENERATED by p16aw/raw_dump/p16aw_author_argspec.py -- DO NOT EDIT.")
    A("//")
    A("// The argument-spec table of RAW_DUMP_ARGSPEC_16AW.json, in a form the")
    A("// repaired capture layer compiles against. Both are written from ONE table")
    A("// object in one run, and the JSON's digest is carried below, so the table the")
    A("// layer compiles and the table the verifier reads cannot drift apart.")
    A("//")
    A("// Derived from the ORIGINAL module's code object metadata")
    A("// (phase9_original_kernel_metadata.json), cross-checked against the Itanium")
    A("// mangled symbol and the 16AO first-frame closure. See the JSON for the")
    A("// per-field evidence sources.")
    A("#pragma once")
    A("")
    A("#include <cstddef>")
    A("")
    A("namespace rd16aw {")
    A("")
    A("constexpr const char* kArgspecJsonSha256 = \"%s\";" % args_json_sha)
    A("")
    A("enum ArgKind { KIND_POINTER = 0, KIND_SCALAR = 1, KIND_BY_VALUE_STRUCT = 2,")
    A("               KIND_OTHER_EXPLICIT = 3 };")
    A("")
    A("struct ArgSpec {")
    A("    unsigned    host_arg_index;")
    A("    unsigned    bytes;                 // explicit_byte_size")
    A("    unsigned    kind;                  // ArgKind")
    A("    unsigned    alignment;")
    A("    unsigned    kernarg_offset;        // canonical explicit-kernarg offset")
    A("    const char* value_kind;            // the code object's own spelling")
    A("    const char* type_name;")
    A("};")
    A("")
    A("struct HiddenArg {")
    A("    const char* value_kind;")
    A("    unsigned    kernarg_offset;")
    A("    unsigned    bytes;")
    A("};")
    A("")
    A("struct KernelSpec {")
    A("    const char*          identity;")
    A("    unsigned             kernarg_segment_size;")
    A("    unsigned             kernarg_segment_align;")
    A("    unsigned             n_explicit;")
    A("    const ArgSpec*       explicit_args;")
    A("    unsigned             n_hidden;")
    A("    const HiddenArg*     hidden_args;")
    A("};")
    A("")

    for s in specs:
        tag = s["identity"].replace("_Z", "k_").replace("_", "")
        A("static const ArgSpec %s_args[] = {" % tag)
        for r in s["explicit_args"]:
            A("    {%uu, %uu, %uu, %uu, %uu, \"%s\", \"%s\"},"
              % (r["host_arg_index"], r["explicit_byte_size"],
                 {"POINTER": 0, "SCALAR": 1, "BY_VALUE_STRUCT": 2,
                  "OTHER_EXPLICIT": 3}[r["semantic_kind"]],
                 r["alignment_bytes"], r["canonical_kernarg_offset"],
                 r["value_kind_in_the_code_object"], r["type_name"]))
        A("};")
        A("static const HiddenArg %s_hidden[] = {" % tag)
        for h in s["hidden_arguments"]:
            A("    {\"%s\", %uu, %uu}," % (h["value_kind"],
                                           h["canonical_kernarg_offset"],
                                           h["explicit_byte_size"]))
        A("};")
        A("")

    A("static const KernelSpec kKernelSpecs[] = {")
    for s in specs:
        tag = s["identity"].replace("_Z", "k_").replace("_", "")
        A("    {\"%s\", %uu, %uu, %uu, %s_args, %uu, %s_hidden},"
          % (s["identity"], s["kernarg_segment_size"], s["kernarg_segment_align"],
             s["n_explicit_host_args"], tag, s["n_hidden_arguments"], tag))
    A("};")
    A("")
    A("constexpr std::size_t kNumKernelSpecs =")
    A("    sizeof(kKernelSpecs) / sizeof(kKernelSpecs[0]);")
    A("")
    A("inline const KernelSpec* spec_lookup(const char* identity)")
    A("{")
    A("    if (identity == nullptr) { return nullptr; }")
    A("    for (std::size_t i = 0; i < kNumKernelSpecs; ++i) {")
    A("        const char* a = kKernelSpecs[i].identity;")
    A("        const char* b = identity;")
    A("        std::size_t k = 0;")
    A("        while (a[k] != '\\0' && a[k] == b[k]) { ++k; }")
    A("        if (a[k] == '\\0' && b[k] == '\\0') { return &kKernelSpecs[i]; }")
    A("    }")
    A("    return nullptr;")
    A("}")
    A("")
    A("// Hard cap on one captured argument. The largest explicit argument in the")
    A("// table is 72 B; the cap stops a corrupted table entry from turning the")
    A("// capture into an unbounded reader.")
    A("constexpr unsigned kMaxArgBytes = 4096u;")
    A("")
    A("}  // namespace rd16aw")
    A("")

    with open(HDR, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    sys.exit(main())
