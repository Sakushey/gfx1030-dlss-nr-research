# Bridge payload build DAG

How `bridge_gfx1030_fatbin.h` is produced, and which parts of that chain you
can actually run from this repository.

The machine-readable form of this document is
[`src/bridge/bridge_payload_dag.json`](../src/bridge/bridge_payload_dag.json),
and it is checked by
[`src/bridge/tools/bridge_payload_dag.py`](../src/bridge/tools/bridge_payload_dag.py):

```
python src/bridge/tools/bridge_payload_dag.py
```

The validator is not decoration. It fails closed on an undeclared
unpublished input, and it is the mechanism that stops this page from drifting
back into the claim it replaces.

## Why this document exists

`src/bridge/README.md` used to say the header should be generated "using the
tooling in `../isa/` and `../emulator/`". Neither directory contains a tool
that emits a fatbin or a header. `src/isa/` holds ISA models and interpreters;
`src/emulator/` holds an emulator and a disassembler. The tools that do
produce a bundle and a header were phase-9 and phase-11 scripts that this
repository does not publish, and nothing recorded which historical
directories the build depended on.

A reader following that instruction would conclude the payload was
reproducible from the tree. It was not. This page says which steps are
reproducible and which are not, and names every missing piece.

## The chain

```
   [1] installer_bundle          USER-SUPPLIED, untracked
        |                         your own copy of the distributed runtime
        v
   [2] extract_bundle            locate + slice the clang offload bundle
        |
        +-----------------------+
        v                       v
   [3] profile_identity      [4] source_elf
        |  parse, count,         |  the source-architecture code object
        |  target identity       |
        |                        v
        |                   [5] symbol_metadata
        |                        |  symbol map + resource table
        |                        v
        |                   [6] translate_isa
        |                        |  source ISA -> target ISA
        |                        v
        |                   [7] assemble_link
        |                        |  llvm-mc + ld.lld
        |                        v
        +------------------>[8] structural_validation
                                 |  the translated object is what it claims
                                 v
                            [9] replacement_bundle
                                 |  the clang bundle, rebuilt
                                 v
                           [10] bridge_gfx1030_fatbin.h
```

The ten stage names in that diagram are the `stages` array in the JSON, in
order, and the validator rejects a DAG whose stages are not all used or whose
edges run backwards through them.

## What you can run from this repository

| Stage | Tool | Status |
| --- | --- | --- |
| 3 profile identity | `src/bridge/offload_bundle.py` | **published** |
| 8 structural validation | `src/bridge/tools/p11_bundle_build.py` | **published** |
| 9 replacement bundle | `src/bridge/tools/p11_bundle_build.py` | **published** |
| 10 header | `src/bridge/tools/p11_embed_header.py` | **published** |
| 2 extraction | phase-11 locator | not published |
| 4 source ELF | phase-11 locator | not published |
| 5 symbol metadata | phase-9 metadata scripts | not published |
| 6 translation | phase-7/8 tooling | not published |
| 7 assemble + link | phase-9 drivers | not published |

The validator reports the same split:

```
user-supplied (untracked): ['installer_bundle']
reproducible-from-this-tree: ['embed_header', 'profile_identity', 'replacement_bundle', 'structural_validation']
blocking gaps (5): ['extract_bundle', 'source_elf', 'symbol_metadata', 'translate_isa', 'assemble_link']
```

**The terminal is `NOT_REPRODUCIBLE_FROM_PUBLIC_TREE`, and it says so.** That
is the honest status, not a temporary one: publishing the translator and the
phase-9 drivers is a separate decision that has not been made. What has
changed is that the gaps are now enumerated, machine-checked, and impossible
to add to silently.

## The proprietary input

Stage 1 is the only input that is neither published nor produced by another
stage. It is your own copy of the distribution under study, and it stays
yours:

- it is marked `untracked: true` in the DAG;
- the validator fails if a path declared `USER_SUPPLIED` exists in this tree;
- the validator fails if it appears in `audit/PUBLICATION_MANIFEST.json`.

So if anyone ever publishes that file here, the DAG check fails rather than
quietly continuing to describe it as user-supplied.

## Reproducing the header from your own payload

If you have the proprietary input and the translated object, the last four
stages run from this repository:

```powershell
# 3: parse the bundle you extracted and confirm the target identity
python -c "import sys; sys.path.insert(0,'src/bridge'); import offload_bundle as ob; b=ob.parse_file(r'your.extracted.bundle'); print(b.declared_count, b.ids); print(ob.select_gfx1030(b))"

# 8 + 9: validate the translated object and write the replacement bundle
python src/bridge/tools/p11_bundle_build.py --object your_translated.co --out gfx1030_dlssnr.fatbin

# 10: emit the header
python src/bridge/tools/p11_embed_header.py --bundle gfx1030_dlssnr.fatbin --out src/bridge/bridge_gfx1030_fatbin.h
```

`p11_bundle_build.py` writes the bundle only after re-parsing its own output
with the published reader and hashing the extracted payload back against the
input object. A bundle that exists has already passed a structural read.

`p11_embed_header.py` writes nothing if the bundle does not parse or does not
carry the requested target. An identity gate compiled against a header built
from the wrong bundle would compare the wrong bytes and verify nothing, which
is worse than a missing file — so the tool refuses rather than guesses.

### One byte difference you should expect

The historical rebuilt bundle in the private tree writes `5` in the count
field while carrying two descriptors, and pads the table with a zero
descriptor as a terminator. `src/bridge/offload_bundle.py` parses exactly
`count` descriptors, so it rejects that file:

```
$ python src/bridge/tools/p11_bundle_build.py --check <historical>/gfx1030_dlssnr.fatbin
STATUS FAILED BundleFormatError: entry 2: identifier length is 0; every
descriptor names a target, and an empty identifier names nothing
```

The same tool over the bundle clang actually wrote, which genuinely has five
entries, parses cleanly and reports all five payloads ELF-aligned:

```
$ python src/bridge/tools/p11_bundle_build.py --check <historical>/original_fatbin_extract.bin
bundle: 5 entries, table ends at 0x136, span 3982944 bytes
  [0] host-x86_64-unknown-linux-gnu-  offset=0x1000 size=0x0
  [1] hipv4-amdgcn-amd-amdhsa--gfx1100  offset=0x1000 size=0x11f980 payload0=7f454c46
  [2] hipv4-amdgcn-amd-amdhsa--gfx1101  offset=0x121000 size=0x11f880 payload0=7f454c46
  [3] hipv4-amdgcn-amd-amdhsa--gfx1102  offset=0x241000 size=0x121ab8 payload0=7f454c46
  [4] hipv4-amdgcn-amd-amdhsa--gfx1201  offset=0x363000 size=0x69660 payload0=7f454c46
```

A header generated today therefore differs from the historical one in those
eight bytes, and consequently in the payload hash and in every identity
constant derived from it. **Do not restore the literal `5` to make the hashes
match.** That value is a count. Writing 5 over two descriptors is the defect,
not the compatibility.

## Identifier terminators

Clang writes `idLength` as a character count and appends no NUL. The reader
in `src/bridge/offload_bundle.py` reads exactly `idLength` bytes, which is
the authoritative reading — measured on a real bundle, where the byte after
the host identifier belongs to the next descriptor's offset field, so
assuming a terminator misplaces descriptor 1 entirely.

`p11_bundle_build.py` writes no terminator by default, matching clang. The
`--nul-terminated-ids` switch reproduces the older layout byte for byte, for
anyone who needs to rebuild a payload that must hash identically to an
existing one. It is not a cosmetic switch: it changes the bundle bytes.

## See also

- [`src/bridge/README.md`](../src/bridge/README.md) — the bridge itself
- [`src/bridge/offload_bundle.py`](../src/bridge/offload_bundle.py) — the container reader
- [`docs/proof-model.md`](proof-model.md) — what the stages of evidence mean
