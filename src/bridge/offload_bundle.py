"""Strict reader for the clang offload-bundle container.

The container
-------------
Clang writes a fat binary as a flat bundle::

    offset 0   24 bytes   "__CLANG_OFFLOAD_BUNDLE__"
    offset 24   8 bytes   u64 ENTRY COUNT
    offset 32   per entry, `count` times:
                  u64 payload offset
                  u64 payload size
                  u64 identifier length
                  identifier bytes

There is no terminator and no version field. The u64 at offset 24 is the
number of descriptors that follow; a reader that treats it as a version and
then scans for a zero descriptor is wrong in two independent ways, and both
of them fail *open*:

  * it rejects every bundle clang actually produces, because clang writes the
    entry count there -- 2 for a host-plus-one-target bundle -- and never 5;
  * it stops at the first all-zero descriptor rather than after `count`
    entries, so any non-zero bytes between the table and the first payload are
    read as a descriptor and become a phantom entry, while a bundle whose
    declared count is larger than the entries that fit is silently truncated
    to whatever it managed to read.

This module parses exactly `count` descriptors and validates the arithmetic
around them, so a malformed bundle is an error rather than a short list.

The identifier length counts bytes, and there is no NUL
-------------------------------------------------------
This contradicts a note repeated in this repository (`p11_fatbin.py`,
`registry_ident.{h,cpp}`), which describes the identifier as "id bytes (incl
NUL)". It is measurable, and the measurement says otherwise. On the real
bundle named in `tests/host/test_offload_bundle.py`, the host entry declares
`idLength = 27` and the 27 bytes at that offset are exactly
`host-x86_64-unknown-linux--` -- the last byte is `-`, not `\0`, and the next
byte belongs to the following descriptor's offset field. The target entry
declares `idLength = 32` over exactly `hipv4-amdgcn-amd-amdhsa--gfx1030`,
again ending on a character. Assuming a terminator instead changes both
entries' descriptor sizes and immediately misplaces the second descriptor, so
the two readings are not interchangeable.

The length is therefore authoritative and the identifier is read as exactly
that many bytes. A trailing NUL, if present, is trimmed when the identifier is
turned into text, so a bundle written by this project's own builder -- which
does append one -- still yields the right identifier. Nothing structural
depends on it.

What is NOT here
----------------
Which targets are acceptable is a *policy* question and does not belong in a
structural reader. `select_target()` is a separate function with a separate
exception type; a structurally perfect bundle for an unsupported architecture
parses cleanly and is then rejected by policy, and the two failures stay
distinguishable in a report. The same separation applies to the 0x1000 payload
alignment clang happens to use: `check_payload_alignment()` is a named policy
step, not a parse-time assumption.

Host-only, stdlib only, no I/O beyond the optional `parse_file` convenience.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple

MAGIC = b"__CLANG_OFFLOAD_BUNDLE__"
MAGIC_LEN = 24
COUNT_FIELD_OFFSET = MAGIC_LEN
DESCRIPTOR_SIZE = 24
HEADER_LEN = MAGIC_LEN + 8

#: Upper bound on the entry count. A bundle carries one descriptor per
#: offload target; real ones carry a handful. The cap exists so a corrupt or
#: hostile count cannot make the reader allocate or scan proportionally to a
#: field that can hold 2**64 - 1.
MAX_ENTRIES = 4096

U64_MAX = (1 << 64) - 1

#: The architecture this project's payload is translated for.
GFX1030_TARGET_ID = "hipv4-amdgcn-amd-amdhsa--gfx1030"


class BundleError(Exception):
    """Base class for every bundle failure."""


class BundleFormatError(BundleError):
    """The bytes are not a well-formed bundle. Structural, never policy."""


class BundleProfileError(BundleError):
    """The bundle is well-formed but does not carry a wanted target.

    Deliberately NOT a subclass of BundleFormatError: a report must be able to
    say "this file is fine, it is the wrong file" without implying corruption.
    """


@dataclass(frozen=True)
class Entry:
    """One bundle descriptor plus the payload span it names."""

    index: int
    offset: int
    size: int
    id_bytes: bytes

    @property
    def target_id(self) -> str:
        """Identifier as text, without a trailing NUL if one was written.

        clang writes no terminator; this project's own builder appends one.
        Trimming makes both read the same, and nothing structural depends on
        it -- the byte length is what the descriptor declares.
        """
        return self.id_bytes.rstrip(b"\0").decode("utf-8", "replace")

    @property
    def end(self) -> int:
        """One past the last payload byte."""
        return self.offset + self.size

    def payload(self, span: memoryview) -> bytes:
        """The payload bytes, re-checked against the span it came from."""
        if self.end > len(span):
            raise BundleFormatError(
                f"entry {self.index} ({self.target_id!r}): payload "
                f"[{self.offset:#x}, {self.end:#x}) is outside the "
                f"{len(span)}-byte span")
        return bytes(span[self.offset:self.end])


@dataclass(frozen=True)
class Bundle:
    """A parsed bundle: its declared count and its entries."""

    declared_count: int
    entries: Tuple[Entry, ...]
    table_end: int
    span_length: int

    def by_id(self, target_id: str) -> Optional[Entry]:
        for e in self.entries:
            if e.target_id == target_id:
                return e
        return None

    @property
    def ids(self) -> Tuple[str, ...]:
        return tuple(e.target_id for e in self.entries)


# ---------------------------------------------------------------------------
# span handling
# ---------------------------------------------------------------------------
def _as_span(data) -> memoryview:
    """Return `data` as a flat, readable, non-empty 1-byte-item memoryview.

    The requirement that the parser be handed a real readable span is
    enforced here rather than assumed. A `str`, a list, or anything else
    without the buffer protocol is rejected outright; a non-contiguous or
    multi-byte-item memoryview is rejected because the offsets in the format
    are byte offsets; and a zero-length span is rejected because a reader that
    accepts it reports an empty bundle instead of a missing one.

    `memoryview` also gives a concrete failure for a *stale* span: a view over
    a released buffer raises `ValueError` on access, which this converts into
    a parse error rather than letting it escape as a confusing `ValueError`
    from somewhere deeper.
    """
    if isinstance(data, str):
        raise BundleFormatError(
            "span is text; a bundle span must be bytes "
            "(open the file with 'rb')")
    try:
        view = memoryview(data)
    except (TypeError, ValueError, BufferError) as exc:
        # A released memoryview raises ValueError here, not TypeError; both
        # are "this is not a span you can read", and neither should escape as
        # a bare builtin exception from the middle of a parse.
        raise BundleFormatError(
            f"span is not a readable byte buffer ({type(data).__name__}): {exc}"
        ) from exc

    try:
        if view.ndim != 1 or view.itemsize != 1:
            view = view.cast("B")
        if not view.contiguous:
            raise BundleFormatError("span is not contiguous")
        n = view.nbytes
    except (TypeError, ValueError, BufferError) as exc:
        raise BundleFormatError(f"span is not a readable byte span: {exc}") from exc

    if n < HEADER_LEN:
        raise BundleFormatError(
            f"span is {n} bytes, too short to hold the {HEADER_LEN}-byte "
            "bundle header")
    return view


def _u64(span: memoryview, offset: int, what: str) -> int:
    """Read a u64 field, guarding the descriptor arithmetic around it.

    The fields are u64 and downstream consumers -- including the C++ that
    embeds the translated object -- compute `offset + size` in 64-bit
    arithmetic. A descriptor whose sum wraps is therefore rejected here, where
    the wrap can be named, instead of surfacing as a wild pointer there.
    """
    if offset + 8 > len(span):
        raise BundleFormatError(
            f"{what}: field at {offset:#x} runs past the {len(span)}-byte span")
    (value,) = struct.unpack_from("<Q", span, offset)
    return value


# ---------------------------------------------------------------------------
# structural parse
# ---------------------------------------------------------------------------
def parse(data, *, expect_full_span: bool = False) -> Bundle:
    """Parse a bundle structurally.

    `data` may be bytes, bytearray, or a memoryview. It is the caller's whole
    span: the parser does not read beyond it and does not treat a shortage as
    a short bundle. If you have only part of a file, that is a parse error and
    the caller will be told so, which is the entire point -- the previous
    reader walked `while pos + 24 <= len(data)` and so reported a *shorter*
    entry list for a truncated buffer instead of failing.

    `expect_full_span=True` additionally requires that the payloads account
    for every byte of the span, which is what a caller who read a whole file
    wants: it catches a span that is longer than the bundle it contains.
    """
    span = _as_span(data)

    if bytes(span[:MAGIC_LEN]) != MAGIC:
        got = bytes(span[:MAGIC_LEN])
        raise BundleFormatError(
            f"bad bundle magic: expected {MAGIC!r}, found {got!r}")

    count = _u64(span, COUNT_FIELD_OFFSET, "entry count")

    if count == 0:
        raise BundleFormatError(
            "entry count is 0: a bundle with no descriptors is not usable, "
            "and a zero here is indistinguishable from an uninitialised field")
    if count > MAX_ENTRIES:
        raise BundleFormatError(
            f"entry count {count} exceeds the cap of {MAX_ENTRIES}")

    # Descriptor bounds. Every descriptor is a fixed 24 bytes plus a variable
    # identifier, so the minimum table for `count` entries is known before any
    # of it is read; requiring it up front is what turns a truncated span into
    # an error instead of a partial entry list.
    minimum_table_end = HEADER_LEN + count * DESCRIPTOR_SIZE
    if minimum_table_end > len(span):
        raise BundleFormatError(
            f"declared count {count} needs at least {minimum_table_end} bytes "
            f"of descriptor table ({HEADER_LEN} + {count} * {DESCRIPTOR_SIZE}) "
            f"but the span is {len(span)} bytes")

    entries = []
    pos = HEADER_LEN
    seen_ids = {}
    for i in range(count):
        off = _u64(span, pos, f"entry {i} payload offset")
        size = _u64(span, pos + 8, f"entry {i} payload size")
        idlen = _u64(span, pos + 16, f"entry {i} identifier length")

        if idlen == 0:
            raise BundleFormatError(
                f"entry {i}: identifier length is 0; every descriptor names a "
                "target, and an empty identifier names nothing")
        if idlen > U64_MAX - pos - DESCRIPTOR_SIZE:
            # Only reachable with a hostile idlen; checked before it is added
            # to anything so the bound below is a comparison, not an overflow.
            raise BundleFormatError(
                f"entry {i}: identifier length {idlen} overflows the "
                "descriptor arithmetic")
        id_end = pos + DESCRIPTOR_SIZE + idlen
        if id_end > len(span):
            raise BundleFormatError(
                f"entry {i}: identifier of {idlen} bytes at {pos + DESCRIPTOR_SIZE:#x} "
                f"runs past the {len(span)}-byte span")

        # Exactly `idlen` bytes. No terminator is required or expected: the
        # declared length is authoritative (see the module docstring for the
        # measurement that establishes this).
        raw_id = bytes(span[pos + DESCRIPTOR_SIZE:id_end])

        # Payload fields, before the entry is accepted.
        if off > len(span):
            raise BundleFormatError(
                f"entry {i}: payload offset {off:#x} is past the "
                f"{len(span)}-byte span")
        if size > U64_MAX - off:
            raise BundleFormatError(
                f"entry {i}: payload offset {off:#x} + size {size:#x} wraps "
                "the 64-bit descriptor arithmetic")
        if off + size > len(span):
            raise BundleFormatError(
                f"entry {i}: payload [{off:#x}, {off + size:#x}) runs past "
                f"the {len(span)}-byte span")
        if size > 0 and off < minimum_table_end:
            raise BundleFormatError(
                f"entry {i}: payload starts at {off:#x}, inside the "
                f"descriptor table which ends at {minimum_table_end:#x}")

        text = raw_id.rstrip(b"\0").decode("utf-8", "replace")
        entry = Entry(index=i, offset=off, size=size, id_bytes=raw_id)
        if text in seen_ids:
            raise BundleFormatError(
                f"entry {i}: duplicate identifier {text!r}, already used by "
                f"entry {seen_ids[text]}")
        seen_ids[text] = i
        entries.append(entry)
        pos = id_end

    # Overlapping payloads. Two entries may share a span (an empty host entry
    # pointing at the same start as a real one is the normal clang shape), but
    # two *non-empty* payloads may not overlap: the byte at that offset would
    # belong to two different objects.
    spans = sorted((e for e in entries if e.size > 0),
                   key=lambda e: e.offset)
    for a, b in zip(spans, spans[1:]):
        if b.offset < a.end:
            raise BundleFormatError(
                f"entries {a.index} ({a.target_id!r}) and {b.index} "
                f"({b.target_id!r}) overlap: [{a.offset:#x}, {a.end:#x}) and "
                f"[{b.offset:#x}, {b.end:#x})")

    table_end = pos
    if expect_full_span:
        covered = max([table_end] + [e.end for e in entries])
        if covered != len(span):
            raise BundleFormatError(
                f"span is {len(span)} bytes but the bundle accounts for "
                f"{covered}: the span is longer than the bundle it holds")

    return Bundle(declared_count=count, entries=tuple(entries),
                  table_end=table_end, span_length=len(span))


def parse_file(path, *, expect_full_span: bool = True) -> Bundle:
    """Read `path` and parse it as a bundle.

    Reads the real file, so the span handed to `parse` is exactly the bytes on
    disk. `expect_full_span` defaults to True because a whole file should be
    fully accounted for.
    """
    with open(path, "rb") as f:
        data = f.read()
    return parse(data, expect_full_span=expect_full_span)


# ---------------------------------------------------------------------------
# policy -- deliberately separate from the structural reader
# ---------------------------------------------------------------------------
def check_payload_alignment(bundle: Bundle, alignment: int = 0x1000) -> None:
    """Reject payloads not aligned to `alignment`.

    Policy, not structure: the format does not require it, clang happens to do
    it. A caller who needs it asks for it.
    """
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("alignment must be a positive power of two")
    for e in bundle.entries:
        if e.size == 0:
            continue
        if e.offset % alignment:
            raise BundleProfileError(
                f"entry {e.index} ({e.target_id!r}): payload offset "
                f"{e.offset:#x} is not {alignment:#x}-aligned")


def select_target(bundle: Bundle, wanted: Iterable[str]) -> Entry:
    """Return the entry for the first wanted target id, or raise.

    Policy, not structure: `bundle` is already known well-formed. A miss is a
    BundleProfileError, which a caller can report as "wrong file" rather than
    as corruption.
    """
    wanted = tuple(wanted)
    if not wanted:
        raise ValueError("no wanted target ids given")
    for target in wanted:
        entry = bundle.by_id(target)
        if entry is not None:
            return entry
    raise BundleProfileError(
        f"none of the wanted targets {list(wanted)} is in the bundle; it "
        f"carries {list(bundle.ids)}")


def select_gfx1030(bundle: Bundle) -> Entry:
    """The project's target: the gfx1030 offload image."""
    return select_target(bundle, (GFX1030_TARGET_ID,))


def describe(bundle: Bundle, span: Optional[memoryview] = None) -> Sequence[str]:
    """One line per entry, for a report."""
    lines = [f"bundle: {bundle.declared_count} entries, "
             f"table ends at {bundle.table_end:#x}, "
             f"span {bundle.span_length} bytes"]
    for e in bundle.entries:
        head = ""
        if span is not None and e.size >= 4:
            head = " payload0=" + bytes(span[e.offset:e.offset + 4]).hex()
        lines.append(f"  [{e.index}] {e.target_id}  "
                     f"offset={e.offset:#x} size={e.size:#x}{head}")
    return lines
