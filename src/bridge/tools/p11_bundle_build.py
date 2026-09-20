"""Build a clang offload bundle around a translated code object.

This is the packaging step of the bridge payload build DAG
(`src/bridge/bridge_payload_dag.json`, node `replacement_bundle`). It is
published because it is payload-agnostic: it checks shape, arithmetic and
identity, and it never interprets an instruction. The bytes it embeds come
from the caller's file, so publishing the packager does not publish the
payload.

The field after the magic is the entry count, not a version
----------------------------------------------------------
The 8 bytes at offset 24 are the number of descriptors that follow. This
tool writes that count. It is worth stating plainly because an earlier
builder in this project wrote a literal 5 there while emitting two
descriptors, and documented the field as "version u64 = 5"; a reader that
believed the documentation then rejected every bundle clang actually
produces. The count is derived here, never chosen, and `--check` re-reads it.

Identifiers are written without a NUL terminator by default
-----------------------------------------------------------
Clang writes `idLength` as the character count with no terminator, and the
published reader `src/bridge/offload_bundle.py` reads exactly that many
bytes. An earlier builder here appended a NUL and counted it. Both readings
round-trip through that reader, so `--nul-terminated-ids` is offered for
byte-compatibility with an existing payload -- but note that it changes the
bundle bytes and therefore the payload hash the identity gate compares. It
is not a cosmetic switch: changing it invalidates a header generated from a
bundle built the other way.

Self-checking
-------------
The bundle is written only after it has been re-parsed with the published
reader and the target payload has been extracted and hashed back against the
input object. A build whose own output does not re-parse is not written at
all, so a bundle that exists has already passed a structural read.

Host-only. Reads one file, writes one file. It does not invoke a compiler,
an assembler, a linker, or a device.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import offload_bundle as ob  # noqa: E402  (path set above)

ELF_MAGIC = b"\x7fELF"
DEFAULT_TARGET_ID = ob.GFX1030_TARGET_ID
DEFAULT_HOST_ID = "host-x86_64-unknown-linux-gnu"
DEFAULT_ALIGNMENT = 0x1000


class BuildError(Exception):
    """The input cannot be packaged, with the reason named."""


def check_elf(data: bytes, path: str, expect_class: str = "ELF64LE") -> None:
    """Reject anything that is not an ELF of the declared class.

    The translated object is linked for a 64-bit little-endian target. A
    packaging step that accepted a wrong-class object would produce a bundle
    that parses perfectly and carries something the loader cannot use, which
    is the failure mode this check exists to prevent.
    """
    if len(data) < 20:
        raise BuildError(f"{path}: {len(data)} bytes is too short to be an ELF")
    if data[:4] != ELF_MAGIC:
        raise BuildError(
            f"{path}: not an ELF file (first 4 bytes {data[:4]!r}, expected "
            f"{ELF_MAGIC!r})")
    ei_class, ei_data = data[4], data[5]
    if expect_class == "ELF64LE":
        if ei_class != 2:
            raise BuildError(
                f"{path}: EI_CLASS is {ei_class} (expected 2 = 64-bit); pass "
                "--elf-class to declare a different target class")
        if ei_data != 1:
            raise BuildError(
                f"{path}: EI_DATA is {ei_data} (expected 1 = little-endian)")
    elif expect_class == "ANY":
        pass
    else:
        raise BuildError(f"unknown --elf-class {expect_class!r}")


def build(object_bytes: bytes, target_id: str, host_id: str,
          alignment: int = DEFAULT_ALIGNMENT,
          nul_terminated_ids: bool = False) -> bytes:
    """Return the bundle bytes for `object_bytes`.

    Two passes, because a descriptor's payload offset depends on the size of
    the whole table, and the table's size depends on the identifiers.
    """
    if alignment <= 0 or alignment & (alignment - 1):
        raise BuildError(f"alignment {alignment} is not a positive power of two")
    if not target_id:
        raise BuildError("target id must be non-empty")
    if not host_id:
        raise BuildError("host id must be non-empty")
    if host_id == target_id:
        raise BuildError(
            f"host id and target id are both {target_id!r}; the reader rejects "
            "duplicate identifiers, so this bundle could never be parsed")

    term = b"\0" if nul_terminated_ids else b""
    entries = [(host_id.encode("utf-8") + term, b""),
               (target_id.encode("utf-8") + term, object_bytes)]

    # Pass 1: table size, which does not depend on the offsets.
    table = bytearray(ob.MAGIC)
    table += struct.pack("<Q", len(entries))
    for ident, _payload in entries:
        table += struct.pack("<QQQ", 0, 0, len(ident))
        table += ident
    content_off = max(alignment, -(-len(table) // alignment) * alignment)

    # Pass 2: the real offsets.
    table = bytearray(ob.MAGIC)
    table += struct.pack("<Q", len(entries))
    cursor = content_off
    for ident, payload in entries:
        table += struct.pack("<QQQ", cursor, len(payload), len(ident))
        table += ident
        cursor += len(payload)

    if len(table) > content_off:
        raise BuildError(
            f"the {len(table)}-byte descriptor table does not fit below the "
            f"{content_off:#x} payload base")
    return bytes(table) + b"\0" * (content_off - len(table)) + object_bytes


def verify(bundle: bytes, object_bytes: bytes, target_id: str) -> list:
    """Re-parse the bundle with the published reader and hash the payload back.

    Returns report lines. Raises on any disagreement, so a caller that writes
    the file only after this returns has written a bundle that already parsed.
    """
    parsed = ob.parse(bundle, expect_full_span=True)
    if parsed.declared_count != 2:
        raise BuildError(
            f"re-parse reports {parsed.declared_count} entries, expected 2")
    # The count field is the count. Re-read it as a count and require that it
    # matches the descriptors actually parsed, which is the check that would
    # have caught the literal-5 defect at build time.
    (field,) = struct.unpack_from("<Q", bundle, ob.COUNT_FIELD_OFFSET)
    if field != len(parsed.entries):
        raise BuildError(
            f"the field at offset {ob.COUNT_FIELD_OFFSET} is {field} but "
            f"{len(parsed.entries)} descriptors were parsed")
    if field == 5:
        raise BuildError(
            "the count field is 5; that is a version-field value, not a count, "
            "and it is the defect this builder exists to not repeat")

    ob.check_payload_alignment(parsed, 0x1000)
    entry = ob.select_target(parsed, (target_id,))
    payload = entry.payload(memoryview(bundle))
    if payload != object_bytes:
        raise BuildError("the extracted payload is not the input object")
    if entry.end != len(bundle):
        raise BuildError(
            f"payload ends at {entry.end:#x} but the bundle is {len(bundle):#x} "
            "bytes; the bundle carries trailing bytes nothing accounts for")

    return [
        f"  re-parse: {parsed.declared_count} entries, table ends "
        f"{parsed.table_end:#x}, span {parsed.span_length} bytes",
        f"  ids: {list(parsed.ids)}",
        f"  target entry {entry.index}: offset {entry.offset:#x} "
        f"size {entry.size:#x} ({entry.offset:#x}-aligned)",
        f"  target payload sha256: {hashlib.sha256(payload).hexdigest()}",
    ]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # Not `required=True`: `--check` inspects an existing bundle and needs
    # neither. The pair is enforced below instead, so that `--check` alone is
    # a usable invocation rather than an argparse misuse.
    ap.add_argument("--object",
                    help="the translated code object (ELF) to embed")
    ap.add_argument("--out", help="bundle to write")
    ap.add_argument("--target-id", default=DEFAULT_TARGET_ID)
    ap.add_argument("--host-id", default=DEFAULT_HOST_ID)
    ap.add_argument("--alignment", type=lambda s: int(s, 0),
                    default=DEFAULT_ALIGNMENT)
    ap.add_argument("--elf-class", default="ELF64LE",
                    choices=("ELF64LE", "ANY"))
    ap.add_argument("--nul-terminated-ids", action="store_true",
                    help="reproduce an existing payload byte-for-byte; "
                         "changes the payload hash, so do not mix")
    ap.add_argument("--check", metavar="BUNDLE",
                    help="parse an existing bundle and report, write nothing")
    args = ap.parse_args(argv)

    try:
        if args.check:
            bundle = open(args.check, "rb").read()
            parsed = ob.parse(bundle, expect_full_span=True)
            for line in ob.describe(parsed, memoryview(bundle)):
                print(line)
            print(f"sha256: {hashlib.sha256(bundle).hexdigest()}")
            return 0

        if not args.object or not args.out:
            ap.error("--object and --out are both required unless --check is used")
        object_bytes = open(args.object, "rb").read()
        check_elf(object_bytes, args.object, args.elf_class)
        print(f"object: {args.object} ({len(object_bytes)} bytes)")
        print(f"object sha256: {hashlib.sha256(object_bytes).hexdigest()}")

        bundle = build(object_bytes, args.target_id, args.host_id,
                       args.alignment, args.nul_terminated_ids)
        print(f"bundle: {len(bundle)} bytes, {len(bundle) - len(object_bytes)} "
              "bytes of header")
        for line in verify(bundle, object_bytes, args.target_id):
            print(line)

        # Written only now: everything above can raise, and a partially
        # verified bundle on disk is worse than no bundle.
        with open(args.out, "wb") as f:
            f.write(bundle)
        print(f"wrote {args.out}")
        print(f"bundle sha256: {hashlib.sha256(bundle).hexdigest()}")
        print("STATUS OK")
        return 0
    except (BuildError, ob.BundleError, OSError) as exc:
        print(f"STATUS FAILED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
