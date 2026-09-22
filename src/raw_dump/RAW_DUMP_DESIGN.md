# RAW_DUMP — design

Phase 16AT. Host-only. **No GPU work, no HIP calls, no HIP runtime imported,
nothing outside `p16at/` modified.**

RAW_DUMP is a **capture-only recorder** for the complete host **by-value
parameter blob** of a kernel launch — the raw bytes — so that the 15
scalar constants still baked into those blobs can be *read out of a real launch*
instead of inferred. It is an instrument, not a resolver: it records bytes and
interprets none.

Artefacts: `RAW_DUMP_SCHEMA.json` (record schema, derived from a real record),
`RAW_DUMP_REACH_CONTROLS.json` (the eight controls of brief §50–§51),
`RAW_DUMP_NOGPU_REHEARSAL.json` (§52), `RAW_DUMP_STATUS.json`,
`RAW_DUMP_BLOB_TABLE.json` (the 15 identities and their read offsets).

---

## 1. The capture point

| | |
|---|---|
| file | `phase16_bridge_telemetry/src/amdhip64_7.cpp` (sha256 `36f47bea73857161…`, 24460 B, 607 lines) |
| function | `hipLaunchKernel` (line 559) |
| anchor statement | `    decode_launch_args(name, args);` — **line 584** |
| inserted call | `raw_dump_at_launch_capture_point(name, function_address, args, launch_ordinal);` — line **586** of the transformed copy |

The surrounding original, unchanged:

```c
577    log_line("LAUNCH_ATTEMPT ordinal=%u kernel=\"%s\" function=%p " ...,
580             ++launch_ordinal, name, ...);
584    decode_launch_args(name, args);          // <-- capture goes immediately after this
585    if (!gate) {
586        log_line("BLOCKED_KERNEL_LAUNCH kernel=\"%s\" function=%p " ...);
589        return kHipErrorLaunchFailure;       // no kernel was launched
590    }
591    hipError_t rc = fn(function_address, numBlocks, dimBlocks, args,
592                       sharedMemBytes, stream);   // <-- backend submission
```

`launch_ordinal` is pre-incremented at line 580, so the value handed to the
capture is exactly the one the `LAUNCH_ATTEMPT` line printed for this launch.

### Why here, and not earlier or later

* **After the complete blob exists.** The caller has already materialised every
  by-value parameter into host memory and built the `void** args` array before it
  entered the bridge. At line 584 the complete image exists — for the 15
  identities of interest, `args[0]` points at one by-value struct.
* **After `decode_launch_args`, which only reads.** It `memcpy`s out; it cannot
  have altered the image. Placing the capture after it therefore still sees the
  application's own bytes, *and* it cannot perturb the bridge's own decode.
* **Before anything that can change the representation.** Only two statements
  in the bridge could: the gate's early return (line 589) and the backend
  submission `fn(...)` (line 591). A backend is free to pack the parameters into
  its own kernarg buffer, and the caller is free to reuse the stack storage the
  moment `hipLaunchKernel` returns. Both are downstream of line 586.
* **Before the gate, deliberately.** With the gate OFF — the only mode this
  project is authorised to run — the launch never reaches the backend at all, so
  nothing downstream of line 586 can have touched the image. This is not a
  theoretical claim: it is measured. The `probe_gate_off` arm runs the whole
  path with `DLSSNR_GFX1030_ALLOW_KERNEL_LAUNCH=0` and the recorder ON, and the
  trace shows `CAPTURE_SITE_REACHED → RECORDER_ENTERED → EMISSION_POINT_REACHED
  → RECORD_WRITTEN` while `bridge.log` carries two `BLOCKED_KERNEL_LAUNCH` lines
  and the mock backend sees **zero** launches
  (`RAW_DUMP_STATUS.json → capture_point.gate_off_probe`).

### How it is wired in without touching the original

`src/p16at_apply_capture_point.py` writes a **transformed copy** to
`_work/amdhip64_7_capture.cpp` and a patch to
`src/amdhip64_7_capture_point.patch`. It inserts **9 lines** (1 `#include` at
line 37, and 8 statements after line 584) and removes none. Four properties are
proved in `_work/capture_point_application.json`:

| proof | result |
|---|---|
| P1 the two anchors occur exactly once each | true |
| P2 deleting the inserted lines reproduces the original byte-for-byte, sha256 `36f47bea…` recovered | true |
| P3 added = 9, removed = 0 | true |
| P4 the patch round-trips to the transformed file | true |

The shipping source is never opened for writing. Its hash is unchanged.

---

## 2. Record schema

`RAW_DUMP_SCHEMA.json` is **derived from a record the recorder actually
emitted**, not written from memory: its generator fails if the record and the
declared field table disagree in either direction, and it evaluates ten
cross-field invariants against the record's own values. It also points the same
checks at four known-bad variants of that record and requires all four to be
rejected (`prove_it_can_fail_and_prove_it_passes`).

Schema id: `p16at/raw-dump-record/1`. 24 fields; the **nine fields brief §49
makes mandatory** are marked `mandatory_by_section_49: true`:

| §49 field | meaning |
|---|---|
| `frame_id` | the first-frame ordinal; **null** until a frame marker has been seen, with `frame_id_source` recording where the number came from |
| `launch_ordinal` | the bridge's per-process counter for this launch |
| `kernel_identity` | the registered device (mangled) name |
| `raw_blob_length` | bytes read from `args[0]` |
| `raw_bytes` | the captured image, lowercase hex |
| `sha256` | SHA-256 of the captured bytes |
| `timestamp_utc` | ISO-8601 UTC with milliseconds |
| `source_callsite` | the exact statement in the bridge |
| `requested_field_offsets` | the offsets in the blob the 15 unresolved values live at, **BLOB-relative**, as decimal JSON integers |

`requested_field_offsets` is reported in both coordinate systems — blob-relative
(`requested_field_offsets`) and kernarg-relative
(`requested_field_offsets_kernarg_relative`) — with quoted hex views alongside,
so a reader can compare directly against 16AO's hex spelling. The offsets come
from the **shipping table row** for the identity, never from the caller: a
caller cannot ask the recorder to read outside the declared image.

The offsets are **decimal JSON integers** (`[0, 32]`), not hex literals. An
earlier generation emitted `[0x0,0x20]`, which is not JSON; the hex spelling is
now carried separately as a quoted string in `requested_field_offsets_hex`.

### Every emitted record is RFC-8259 JSON, structurally

A record is the recorder's *product*, and a consumer that cannot parse it has
nothing. Six records were once unreadable to a standard reader while the phase's
own artefact check reported "all JSON ok", because that check only ever looked
at the seven top-level artefacts. Escaping is therefore structural, not
per-site:

* `Buf::add_json()` is a complete RFC-8259 string escaper — `"`, `\`, `\b \f
  \n \r \t`, and every other control character as `\u00XX`.
* It is **private**, and `Buf::key_str()` / `key_str_last()` are the only route
  by which a string field reaches a record. One implementation, so the rule
  cannot be half-applied at one call site while another stays raw — which is
  exactly how the first, per-site fix left `raw_bytes_sidecar` unreadable.
* `rehearsal_driver.cpp` escapes every string field it writes, including the
  argv-supplied `--arm`.
* `build_raw_dump.ps1` writes the build manifest with
  `File::WriteAllText` + a BOM-less `UTF8Encoding`, and throws if a BOM is
  present (PowerShell 5.1's `Set-Content -Encoding UTF8` emits one).

Two checks keep it that way. The recorder's own self-test step 6,
`emitted_record_has_no_bare_backslash`, rejects a record whose strings contain a
backslash that does not begin a legal escape — scope is exactly that property,
not full JSON parsing. The full check is
`src/p16at_verify_all_records.py`, which decodes every emitted `.json` as strict
UTF-8 (a BOM is a failure) and parses it with Python's standard `json` module,
fails the run on any one failure, fails a scan that finds zero files, and is
pointed at the six pre-fix records on every run — which it must reject — so the
proof that it can fail cannot rot.

### Write-once

The record `.json` and its `.bin` side-car are each created with
`CreateFileA(..., CREATE_NEW)`. An existing file is **never** overwritten; a
collision retries on a `.dup1`, `.dup2`, … path. Path shape:

```
<UTCstamp>_<pid>_<ordinal>_<identity stem>_<first 12 hex of sha256>.json / .bin
```

The control trace log `_raw_dump_trace.log` is **append-only** — losing a line to
`already exists` would hide reach, which is the one thing the trace exists to
make visible.

---

## 3. Ordering guarantees

The recorder emits four trace events, in this order, and each is a separate
fact rather than one fact inferred from another:

| trace event | written by | means |
|---|---|---|
| `CAPTURE_SITE_REACHED` | the adapter (line 586) | the wired line executed |
| `RECORDER_ENTERED` | `emit()`, **before** the `RAW_DUMP` enable gate | the recorder ran at all |
| `EMISSION_POINT_REACHED` | `emit()`, **after** the enable gate, **before** any validation | there is an observer, and it is about to emit |
| `RECORD_WRITTEN` | `emit()`, after the bytes are on disk | a complete record exists, with its path |

`EMISSION_POINT_REACHED` is placed after the enable gate on purpose. With the
recorder disabled there is **no observer to reject anything**, so an arm whose
record is merely missing must be recorded as an **INVALID CONTROL**, never as a
successful rejection. Splitting the two events is what makes "the recorder was
off" and "the recorder refused" distinguishable in the evidence rather than in
prose.

Content ordering inside `emit()`: reach → gate → identity/blob checks →
kernel filter → the four injection points → declared-length bound (0, 4096] →
two independent reads of the image, refused if they disagree →
SHA-256 → table lookup → `frame_id` → side-car `CREATE_NEW` → record
`CREATE_NEW` → `RECORD_WRITTEN`.

A refusal always names itself in `Outcome.reason`, and any partially created
file is deleted rather than left behind: a half-written capture is worse than
none.

---

## 4. The mutation surface

Every capture defect the controls need to inject is a single macro, in
`src/raw_dump_injection_points.h`; the shipping build leaves all four
identity:

```c
RAWD_BLOB_POINTER(p)    (p)
RAWD_BLOB_LENGTH(n)     (n)
RAWD_LAUNCH_ORDINAL(n)  (n)
RAWD_KERNEL_IDENTITY(s) (s)
```

`src/p16at_emit_mutants.py` emits one mutated copy of the recorder per arm into
`_work/mutants/<arm>/`, each adding **exactly one** `#define RAWD_*` line, and
proves it (an exact-count diff on the `#define RAWD_*` lines, not a set
difference). Mutants are compiled from a **copy of the source**, never via
`-I<scratch>`: a quoted include resolves against the including file's own
directory first, so an include-path trick silently compiles the unmutated
header and the mutant tests nothing.

---

## 5. What RAW_DUMP does not do

* It does not run on a GPU, does not import a HIP runtime, and does not launch
  anything. Every binary built here is checked, after the build, to import only
  `KERNEL32.dll`.
* It does not resolve the 15 scalar constants. They stay **UNRESOLVED**: no real
  launch was captured, so no value was read. The first-frame contract figure
  therefore does not move (`520/535`).
* It does not modify the shipping bridge, or any file outside `p16at/`.
* It does not interpret the bytes it records.

## 6. Where the evidence is

| question | artefact |
|---|---|
| is the wiring exactly these 9 lines? | `_work/capture_point_application.json`, `src/amdhip64_7_capture_point.patch` |
| what does a record look like, and does the schema match one? | `RAW_DUMP_SCHEMA.json` |
| which 15 identities, how many bytes, which offsets? | `RAW_DUMP_BLOB_TABLE.json`, from `p16ao/contracts/FIRST_FRAME_FIELD_CLOSURE.json` |
| does a defect get caught, and was the observer even there? | `RAW_DUMP_REACH_CONTROLS.json` |
| do ON and OFF differ only by evidence? | `RAW_DUMP_NOGPU_REHEARSAL.json` |
| does every emitted record parse with a standard reader, and can that check fail? | `_work/all_records_parse.json`; corpus in `_work/known_bad_records/` |
| what was built, what was not, and can the checks fail? | `RAW_DUMP_STATUS.json` |
| the raw arms | `out/<arm>/` — `bridge.log`, `mock_hip6.log`, `_raw_dump_trace.log`, the records, `verification.json`, `driver_result.json` |
