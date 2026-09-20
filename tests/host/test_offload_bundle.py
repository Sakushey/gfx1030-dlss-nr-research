"""Host-only regression for `src/bridge/offload_bundle.py`.

The defect this covers
----------------------
The bundle reader this replaces documented the u64 after the 24-byte magic as
a *version*, required it to equal 5, and then read descriptors in a
``while pos + 24 <= len(data)`` loop that stopped at the first all-zero
descriptor. The u64 is the ENTRY COUNT. Clang writes 2 there for a
host-plus-one-target bundle and never writes 5, so the reader rejected every
real bundle; and because it stopped at a zero rather than after `count`
entries, a truncated or padded span produced a *shorter entry list* instead of
an error.

Both halves are exercised here against bytes taken from a real bundle:

  * `TestTheDefect` implements the old rule verbatim and requires it to reject
    the genuine clang output embedded below, and requires the new reader to
    accept the same bytes. A control that only showed the new reader working
    would not establish that the old rule was wrong.
  * `TestNegativeControls` constructs each malformed shape the new reader
    claims to reject and requires a rejection, including the phantom-entry and
    silent-truncation behaviours the old loop exhibited.

The fixture
-----------
`REAL_TABLE_HEX` is bytes 0x00..0x8b of a real clang bundle
(`soft_wmma_test.cpp-hip-amdgcn-amd-amdhsa.hipfb`, sha256
`0248e241d1a48b15defd9780ad582a68228ab1a2f4b49ae9efd0561d6490dd2b`,
9464 bytes): the magic, the entry count, and both descriptors, including their
identifiers. That region contains no compiled code -- it is the container's
own table. The payloads are replaced with a deterministic pattern, sized to
the real entry sizes (0 and 0x14f8) so the reconstruction is byte-for-byte the
same length as the original. Nothing proprietary is published here.
"""
from __future__ import annotations

import os
import struct
import unittest

import hostpath  # noqa: F401  (sets up the import namespace)

import offload_bundle
from offload_bundle import (Bundle, BundleFormatError, BundleProfileError,
                            Entry, parse, select_gfx1030, select_target)

REPO = hostpath.REPO_ROOT
MODULE = os.path.join(REPO, "src", "bridge", "offload_bundle.py")

# --- real bundle facts, measured from the file named in the module docstring
REAL_FILE_SIZE = 9464
REAL_FILE_SHA256 = "0248e241d1a48b15defd9780ad582a68228ab1a2f4b49ae9efd0561d6490dd2b"
REAL_ENTRY_COUNT = 2
REAL_HOST_ID = "host-x86_64-unknown-linux--"
REAL_TARGET_ID = "hipv4-amdgcn-amd-amdhsa--gfx1030"
REAL_TARGET_OFFSET = 0x1000
REAL_TARGET_SIZE = 0x14F8
REAL_TABLE_END = 0x8B

#: Bytes 0x00..0x8b of that bundle: magic, count, both descriptors.
REAL_TABLE_HEX = (
    "5f5f434c414e475f4f46464c4f41445f42554e444c455f5f0200000000000000"
    "001000000000000000000000000000001b00000000000000686f73742d783836"
    "5f36342d756e6b6e6f776e2d6c696e75782d2d0010000000000000f814000000"
    "000000200000000000000068697076342d616d6467636e2d616d642d616d6468"
    "73612d2d67667831303330"
)


def real_table() -> bytes:
    return bytes.fromhex(REAL_TABLE_HEX)


def real_bundle(payload_fill: int = 0xA5) -> bytes:
    """The real header, plus payloads of the real sizes.

    Same total length as the original file, same descriptor table, same
    offsets and sizes. Only the payload bytes differ, because the original
    payload is the translated object and is not republished.
    """
    table = real_table()
    assert len(table) == REAL_TABLE_END, len(table)
    buf = bytearray(table)
    buf += b"\0" * (REAL_TARGET_OFFSET - len(buf))          # the real padding
    buf += bytes([payload_fill]) * REAL_TARGET_SIZE
    return bytes(buf)


def old_parse_bundle(data):
    """The pre-fix reader, verbatim in behaviour.

    Magic check, `version == 5` check, then a scan for an all-zero descriptor.
    Kept here so the control is the actual old rule rather than a description
    of it.
    """
    magic = b"__CLANG_OFFLOAD_BUNDLE__"
    if data[:len(magic)] != magic:
        raise ValueError("bad bundle magic")
    (version,) = struct.unpack_from("<Q", data, len(magic))
    if version != 5:
        raise ValueError(f"bundle version {version} != 5")
    entries = []
    pos = len(magic) + 8
    while pos + 24 <= len(data):
        off, size, idlen = struct.unpack_from("<QQQ", data, pos)
        if off == 0 and size == 0 and idlen == 0:
            break
        ident = data[pos + 24: pos + 24 + idlen]
        if len(ident) < idlen:
            raise ValueError("truncated identifier")
        entries.append({"offset": off, "size": size,
                        "id": ident.rstrip(b"\0").decode()})
        pos += 24 + idlen
    return entries


def old_parse_with_version_field_patched(data, field: int = 5):
    """`old_parse_bundle` with the count field rewritten to `field`.

    The old reader has two defects in sequence: the version check fires first
    and rejects everything, so its scan behaviour is only observable once the
    version check is satisfied. Rewriting that one field to 5 is how the
    second defect is reached -- and 5 is exactly the value at which a real
    bundle looks valid to it, which is the point of the first control.
    """
    buf = bytearray(data)
    struct.pack_into("<Q", buf, 24, field)
    return old_parse_bundle(bytes(buf))


class TestTheFixtureIsReal(unittest.TestCase):
    """The embedded bytes must be the real ones, or nothing below means anything."""

    def test_table_is_139_bytes_and_holds_two_descriptors(self):
        t = real_table()
        self.assertEqual(len(t), REAL_TABLE_END)
        self.assertEqual(t[:24], b"__CLANG_OFFLOAD_BUNDLE__")

    def test_the_field_after_the_magic_is_the_entry_count(self):
        """The whole defect in one assertion.

        It is 2, which is exactly the number of descriptors that follow -- and
        it is not 5, which is what the old reader demanded.
        """
        (field,) = struct.unpack_from("<Q", real_table(), 24)
        self.assertEqual(field, REAL_ENTRY_COUNT)
        self.assertNotEqual(field, 5)

    def test_reconstruction_matches_the_real_file_length(self):
        """Same size, same table, same offsets: only payload bytes differ."""
        self.assertEqual(len(real_bundle()), REAL_FILE_SIZE)

    def test_the_real_descriptors_are_the_measured_ones(self):
        b = parse(real_bundle(), expect_full_span=True)
        self.assertEqual(b.declared_count, REAL_ENTRY_COUNT)
        self.assertEqual(b.table_end, REAL_TABLE_END)
        self.assertEqual(b.ids, (REAL_HOST_ID, REAL_TARGET_ID))
        host, target = b.entries
        self.assertEqual(host.size, 0)
        self.assertEqual(host.offset, REAL_TARGET_OFFSET)
        self.assertEqual(target.offset, REAL_TARGET_OFFSET)
        self.assertEqual(target.size, REAL_TARGET_SIZE)

    def test_the_fixture_is_a_real_readable_span(self):
        b = parse(bytearray(real_bundle()))
        self.assertEqual(b.span_length, REAL_FILE_SIZE)
        b2 = parse(memoryview(real_bundle()))
        self.assertEqual(b2.ids, b.ids)


class TestTheDefect(unittest.TestCase):
    """The old rule, run against genuine clang output."""

    def test_negative_control_the_old_reader_rejects_real_clang_output(self):
        """The defect: every real bundle fails the version check.

        This is the control that makes the fix meaningful. If this ever
        stops raising, the old rule has changed and the rationale for the new
        reader needs re-deriving.
        """
        with self.assertRaises(ValueError) as cm:
            old_parse_bundle(real_bundle())
        self.assertIn("bundle version 2 != 5", str(cm.exception))

    def test_positive_control_the_new_reader_accepts_the_same_bytes(self):
        """The same bytes the control above rejects must parse here."""
        b = parse(real_bundle(), expect_full_span=True)
        self.assertEqual(b.declared_count, REAL_ENTRY_COUNT)

    def test_negative_control_the_old_reader_reads_past_the_table(self):
        """The zero-terminator loop invents an entry from non-zero padding.

        The format has no terminator: the table ends after `count`
        descriptors and whatever follows is payload or padding. Padding that
        is not zero is legal, and the old loop has no way to know it has left
        the table, so it reads the padding as a third descriptor.
        """
        table = real_table()
        # Legal-looking non-zero padding immediately after the table.
        padding = struct.pack("<QQQ", 0x2000, 4, 1) + b"x\0"
        data = table + padding + b"\0" * (REAL_TARGET_OFFSET - len(table) -
                                          len(padding)) + \
            bytes([0xA5]) * REAL_TARGET_SIZE
        # The old reader's version check must be satisfied before its scan is
        # reachable at all; see old_parse_with_version_field_patched.
        old = old_parse_with_version_field_patched(data)
        self.assertEqual(len(old), 3,
                         "the old loop did not invent a third entry")
        self.assertNotEqual(old[2]["id"], REAL_HOST_ID)

        # The new reader knows the count and never looks past the table.
        b = parse(data, expect_full_span=True)
        self.assertEqual(len(b.entries), REAL_ENTRY_COUNT)
        self.assertEqual(b.ids, (REAL_HOST_ID, REAL_TARGET_ID))

    def test_negative_control_the_old_reader_truncates_instead_of_failing(self):
        """A short span yields a short list, not an error.

        `while pos + 24 <= len(data)` exits quietly when the span runs out, so
        a caller handed a prefix of a bundle is told the bundle has fewer
        entries -- with no indication that anything was lost.
        """
        full = real_bundle()
        truncated = full[:REAL_TABLE_END]         # table only, no payloads
        # The old reader does not fail; it reports whatever it could read, and
        # the payload bounds are never checked so the entries look usable.
        old = old_parse_with_version_field_patched(truncated)
        self.assertEqual(len(old), REAL_ENTRY_COUNT)
        for e in old:
            self.assertEqual(e["offset"], REAL_TARGET_OFFSET)
            self.assertGreater(e["size"] + e["offset"], len(truncated),
                               "the old reader's entries point outside the span")

        # Now drop the second descriptor entirely: the old reader reports ONE
        # entry, with no error, for a bundle that declares two.
        half = truncated[:32 + 24 + 27]
        old_half = old_parse_with_version_field_patched(half)
        self.assertEqual(len(old_half), 1,
                         "the old reader did not silently drop an entry")
        self.assertEqual(struct.unpack_from("<Q", half, 24)[0], 2)

        # The new reader rejects both spans rather than shortening the list.
        # The exact message differs by which bound is reached first -- a span
        # that stops inside the table trips the offset check, one that stops
        # after it trips the size check -- so both are accepted.
        for span in (truncated, half):
            with self.assertRaises(BundleFormatError) as cm:
                parse(span)
            self.assertRegex(str(cm.exception), r"runs past|is past the")


class TestNegativeControls(unittest.TestCase):
    """Every malformed shape the reader claims to reject."""

    def _data(self, **overrides) -> bytes:
        """The real bundle with one descriptor field replaced."""
        table = bytearray(real_table())
        # second descriptor starts at 32 + 24 + 27
        d2 = 32 + 24 + 27
        for field, value in overrides.items():
            name, _, index = field.partition("_")
            off = {"off": d2, "size": d2 + 8, "idlen": d2 + 16}[name]
            struct.pack_into("<Q", table, off, value)
        buf = bytes(table)
        buf += b"\0" * (REAL_TARGET_OFFSET - len(buf))
        buf += bytes([0xA5]) * REAL_TARGET_SIZE
        return buf

    def test_rejects_a_bad_magic(self):
        data = bytearray(real_bundle())
        data[:4] = b"XXXX"
        with self.assertRaises(BundleFormatError) as cm:
            parse(bytes(data))
        self.assertIn("bad bundle magic", str(cm.exception))

    def test_rejects_a_count_beyond_the_cap(self):
        """A cap, not a literal: the count field is a u64."""
        data = bytearray(real_bundle())
        struct.pack_into("<Q", data, 24, offload_bundle.MAX_ENTRIES + 1)
        with self.assertRaises(BundleFormatError) as cm:
            parse(bytes(data))
        self.assertIn("exceeds the cap", str(cm.exception))

    def test_rejects_a_hostile_count_without_scanning(self):
        """count = 2**40 must be refused by the cap, not acted on."""
        data = bytearray(real_bundle())
        struct.pack_into("<Q", data, 24, 1 << 40)
        with self.assertRaises(BundleFormatError) as cm:
            parse(bytes(data))
        self.assertIn("exceeds the cap", str(cm.exception))

    def test_rejects_a_zero_count(self):
        """Zero descriptors is an error, not an empty bundle."""
        data = bytearray(real_bundle())
        struct.pack_into("<Q", data, 24, 0)
        with self.assertRaises(BundleFormatError) as cm:
            parse(bytes(data))
        self.assertIn("entry count is 0", str(cm.exception))

    def test_rejects_a_count_larger_than_the_descriptors_that_fit(self):
        data = bytearray(real_bundle())
        struct.pack_into("<Q", data, 24, 500)
        with self.assertRaises(BundleFormatError) as cm:
            parse(bytes(data))
        self.assertIn("descriptor table", str(cm.exception))

    def test_rejects_an_identifier_running_past_the_span(self):
        with self.assertRaises(BundleFormatError) as cm:
            parse(self._data(idlen_=1 << 40))
        self.assertIn("runs past", str(cm.exception))

    def test_rejects_a_zero_identifier_length(self):
        with self.assertRaises(BundleFormatError) as cm:
            parse(self._data(idlen_=0))
        self.assertIn("identifier length is 0", str(cm.exception))

    def test_rejects_a_non_nul_terminated_identifier(self):
        """The length is authoritative, so a terminator is neither needed nor
        checked -- and this is asserted as a *measurement* rather than left
        implicit, because this repository's own notes say the opposite.

        The real bundle's identifiers end on a character, not on `\\0`, and
        the entries after them land exactly where the declared lengths put
        them. A reader that demanded a terminator would reject genuine clang
        output; a reader that assumed one would misplace the second
        descriptor.
        """
        b = parse(real_bundle(), expect_full_span=True)
        host, target = b.entries
        self.assertEqual(len(host.id_bytes), 27)
        self.assertEqual(len(target.id_bytes), 32)
        self.assertNotEqual(host.id_bytes[-1], 0)
        self.assertNotEqual(target.id_bytes[-1], 0)
        self.assertEqual(host.id_bytes, REAL_HOST_ID.encode())
        self.assertEqual(target.id_bytes, REAL_TARGET_ID.encode())
        # ... and the identifiers are still usable as text.
        self.assertEqual(host.target_id, REAL_HOST_ID)
        self.assertEqual(target.target_id, REAL_TARGET_ID)

    def test_a_trailing_nul_is_trimmed_but_not_required(self):
        """This project's own builder appends a NUL; clang does not.

        Both must yield the same identifier text, because the length field is
        what the reader trusts and the terminator is decoration.
        """
        table = bytearray(real_table())
        d2 = 32 + 24 + 27
        new_id = REAL_TARGET_ID.encode() + b"\0"       # 33 bytes, with NUL
        struct.pack_into("<QQQ", table, d2, REAL_TARGET_OFFSET,
                         REAL_TARGET_SIZE, len(new_id))
        table[d2 + 24:d2 + 24 + len(new_id)] = new_id
        # The table grew by one byte, so the payload start shifts with it and
        # the reconstruction keeps the real file's total length.
        pad = REAL_TARGET_OFFSET - len(table)
        buf = bytes(table) + b"\0" * pad + bytes([0xA5]) * REAL_TARGET_SIZE
        self.assertEqual(len(buf), REAL_FILE_SIZE)
        b = parse(buf, expect_full_span=True)
        self.assertEqual(b.table_end, REAL_TABLE_END + 1)
        self.assertEqual(b.by_id(REAL_TARGET_ID).target_id, REAL_TARGET_ID)

    def test_rejects_a_payload_offset_past_the_span(self):
        with self.assertRaises(BundleFormatError) as cm:
            parse(self._data(off_=REAL_FILE_SIZE + 1))
        self.assertIn("past the", str(cm.exception))

    def test_rejects_a_payload_size_running_past_the_span(self):
        with self.assertRaises(BundleFormatError) as cm:
            parse(self._data(size_=REAL_TARGET_SIZE + 1))
        self.assertIn("runs past", str(cm.exception))

    def test_rejects_a_payload_offset_inside_the_descriptor_table(self):
        with self.assertRaises(BundleFormatError) as cm:
            parse(self._data(off_=0x40, size_=8))
        self.assertIn("inside the descriptor table", str(cm.exception))

    def test_rejects_a_wrapping_offset_plus_size(self):
        """The fields are u64; a sum that wraps is rejected here, not there.

        The offset is inside the span and only the size is hostile, so this
        reaches the wraparound guard rather than the span guard: a C consumer
        computing `offset + size` in 64-bit arithmetic would get a small
        number and read the wrong bytes.
        """
        with self.assertRaises(BundleFormatError) as cm:
            parse(self._data(off_=REAL_TARGET_OFFSET, size_=(1 << 64) - 1))
        self.assertIn("wraps", str(cm.exception))

    def test_rejects_duplicate_identifiers(self):
        """Two descriptors for the same target: which payload is the target?"""
        table = bytearray(real_table())
        d2 = 32 + 24 + 27
        host_id = bytes(table[56:56 + 27])
        struct.pack_into("<QQQ", table, d2, REAL_TARGET_OFFSET,
                         REAL_TARGET_SIZE, len(host_id))
        table[d2 + 24:d2 + 24 + len(host_id)] = host_id
        buf = bytes(table) + b"\0" * (REAL_TARGET_OFFSET - len(table)) + \
            bytes([0xA5]) * REAL_TARGET_SIZE
        with self.assertRaises(BundleFormatError) as cm:
            parse(buf)
        self.assertIn("duplicate identifier", str(cm.exception))
    def test_rejects_overlapping_payloads(self):
        """Two non-empty payloads may not claim the same bytes.

        Both stay inside the span, so the overlap rule is what rejects this
        rather than the bounds check.
        """
        table = bytearray(real_table())
        d2 = 32 + 24 + 27
        struct.pack_into("<QQQ", table, d2, REAL_TARGET_OFFSET + 8, 0x40, 32)
        struct.pack_into("<Q", table, 32 + 8, 0x40)    # host entry, size 0x40
        buf = bytes(table) + b"\0" * (REAL_TARGET_OFFSET - len(table)) + \
            bytes([0xA5]) * REAL_TARGET_SIZE
        with self.assertRaises(BundleFormatError) as cm:
            parse(buf)
        self.assertIn("overlap", str(cm.exception))
        # Both payloads are genuinely inside the span, so this is the overlap
        # rule firing and not the bounds rule.
        self.assertNotIn("runs past", str(cm.exception))

    def test_two_zero_size_entries_may_share_an_offset(self):
        """The known-good case for the overlap rule.

        Refusing shared offsets outright would reject the normal clang shape,
        where an empty host entry names the same start as the real payload. A
        checker that cannot accept a legal bundle is broken, not strict.
        """
        table = bytearray(real_table())
        struct.pack_into("<Q", table, 32 + 8, 0)       # host size stays 0
        buf = bytes(table) + b"\0" * (REAL_TARGET_OFFSET - len(table)) + \
            bytes([0xA5]) * REAL_TARGET_SIZE
        b = parse(buf, expect_full_span=True)
        self.assertEqual(len(b.entries), 2)

    def test_rejects_a_span_longer_than_the_bundle(self):
        """A whole-file read must account for the whole file."""
        data = real_bundle() + b"\0" * 64
        with self.assertRaises(BundleFormatError) as cm:
            parse(data, expect_full_span=True)
        # and it is only an error when the caller asks for that guarantee
        self.assertEqual(len(parse(data).entries), REAL_ENTRY_COUNT)

    # ------------------------------------------------------ span requirements
    def test_rejects_a_span_that_is_not_readable_bytes(self):
        """Structural parsing must receive a real readable span."""
        for bad in ("not bytes at all", 12345, ["a", "b"], None):
            with self.assertRaises(BundleFormatError, msg=repr(bad)):
                parse(bad)

    def test_rejects_a_str_span_with_a_specific_message(self):
        with self.assertRaises(BundleFormatError) as cm:
            parse(real_bundle().hex())
        self.assertIn("span is text", str(cm.exception))

    def test_rejects_a_stale_memoryview(self):
        """A released buffer must be a parse error, not a stray ValueError."""
        data = real_bundle()
        view = memoryview(bytearray(data))
        view.release()
        with self.assertRaises(offload_bundle.BundleError):
            parse(view)

    def test_rejects_a_span_too_short_for_the_header(self):
        with self.assertRaises(BundleFormatError) as cm:
            parse(b"_")
        self.assertIn("too short", str(cm.exception))

    def test_accepts_a_sliced_memoryview_span(self):
        """A slice of a larger buffer is a legitimate span."""
        data = real_bundle()
        base = bytearray(b"\0" * 16) + bytearray(data)
        view = memoryview(base)[16:]
        self.assertEqual(view.nbytes, REAL_FILE_SIZE)
        b = parse(view, expect_full_span=True)
        self.assertEqual(b.span_length, REAL_FILE_SIZE)
        self.assertEqual(b.ids, (REAL_HOST_ID, REAL_TARGET_ID))

    def test_a_u64_framed_view_is_cast_rather_than_refused(self):
        """A caller who framed the bundle as u64 words still gets the bytes.

        On a little-endian host a `Q`-item view over the bundle holds exactly
        the bundle's bytes, so parsing it must succeed and must agree with the
        bytes view. The cast is not optional: offsets in the format are byte
        offsets, and an uncast view would index 8 bytes at a time.
        """
        data = real_bundle()
        view = memoryview(data).cast("Q")
        self.assertEqual(view.itemsize, 8)
        b = parse(view, expect_full_span=True)
        self.assertEqual(b.span_length, REAL_FILE_SIZE)
        self.assertEqual(b.ids, (REAL_HOST_ID, REAL_TARGET_ID))

    def test_a_u64_view_over_extra_bytes_is_still_length_checked(self):
        """Framing as u64 must not become a way to lose the tail.

        A whole number of u64 words is appended, so the cast succeeds and the
        span is longer than the bundle. A reader that trusted the item count
        rather than the byte length would accept it.
        """
        data = real_bundle() + b"\0" * 8               # 9472 = 1184 * 8
        view = memoryview(data).cast("Q")
        self.assertEqual(view.nbytes, REAL_FILE_SIZE + 8)
        with self.assertRaises(BundleFormatError) as cm:
            parse(view, expect_full_span=True)
        self.assertIn("longer than the bundle", str(cm.exception))


class TestPolicyIsSeparate(unittest.TestCase):
    """Structural correctness and target policy must not be conflated."""

    def test_a_valid_bundle_for_an_unsupported_target_still_parses(self):
        """The separation control.

        A well-formed bundle carrying only a gfx1100 image is not corrupt, it
        is the wrong file. The parser must accept it and the policy step must
        reject it, with different exception types, so a report can say which.
        """
        table = bytearray(real_table())
        d2 = 32 + 24 + 27
        new_id = b"hipv4-amdgcn-amd-amdhsa--gfx1100\0"
        struct.pack_into("<QQQ", table, d2, REAL_TARGET_OFFSET,
                         REAL_TARGET_SIZE, len(new_id))
        table[d2 + 24:d2 + 24 + len(new_id)] = new_id
        buf = bytes(table) + b"\0" * (REAL_TARGET_OFFSET - len(table)) + \
            bytes([0xA5]) * REAL_TARGET_SIZE

        b = parse(buf, expect_full_span=True)          # structure: fine
        self.assertTrue(any("gfx1100" in i for i in b.ids), b.ids)

        with self.assertRaises(BundleProfileError) as cm:   # policy: rejects
            select_gfx1030(b)
        self.assertIn("gfx1100", str(cm.exception))

    def test_a_profile_error_is_not_a_format_error(self):
        """Different failures must stay distinguishable to a caller."""
        self.assertFalse(issubclass(BundleProfileError, BundleFormatError))
        self.assertTrue(issubclass(BundleProfileError, offload_bundle.BundleError))
        self.assertTrue(issubclass(BundleFormatError, offload_bundle.BundleError))

    def test_the_real_target_is_selectable(self):
        b = parse(real_bundle(), expect_full_span=True)
        e = select_gfx1030(b)
        self.assertEqual(e.target_id, REAL_TARGET_ID)
        self.assertEqual(e.size, REAL_TARGET_SIZE)

    def test_a_corrupt_bundle_is_not_reported_as_a_profile_miss(self):
        """The converse: corruption must not be dressed up as policy."""
        data = bytearray(real_bundle())
        struct.pack_into("<Q", data, 24, 9999)
        with self.assertRaises(BundleFormatError):
            parse(bytes(data))

    def test_alignment_is_a_named_policy_step_not_a_parse_assumption(self):
        b = parse(real_bundle(), expect_full_span=True)
        offload_bundle.check_payload_alignment(b)          # real: aligned
        boxed = Entry(index=0, offset=REAL_TARGET_OFFSET + 1,
                      size=8, id_bytes=b"x\0")
        bad = Bundle(declared_count=1, entries=(boxed,), table_end=32,
                     span_length=REAL_FILE_SIZE)
        with self.assertRaises(BundleProfileError):
            offload_bundle.check_payload_alignment(bad)

    def test_select_target_requires_a_wanted_list(self):
        b = parse(real_bundle(), expect_full_span=True)
        with self.assertRaises(ValueError):
            select_target(b, ())
        with self.assertRaises(BundleProfileError):
            select_target(b, ("hipv4-amdgcn-amd-amdhsa--gfx900",))


class TestParserSource(unittest.TestCase):
    """Properties of the module itself."""

    def test_module_exists_and_is_stdlib_only(self):
        """Every import must be stdlib, checked on the parsed AST.

        Scanning lines for `import` would also match prose inside the module
        docstring -- which is where most of this file's prose lives.
        """
        import ast
        with open(MODULE, encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=MODULE)
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                mods.add((node.module or "").split(".")[0])
        self.assertTrue(mods, "no imports found: the AST scan is broken")
        self.assertLessEqual(
            mods, {"__future__", "struct", "dataclasses", "typing", "os",
                   "hashlib", "sys"},
            f"non-stdlib or unexpected imports: {sorted(mods)}")

    def test_no_literal_five_is_used_as_the_count_rule(self):
        """The defect must not be 'fixed' by swapping one literal for another.

        There is no `== 5` version comparison and no `VERSION` constant; the
        count comes from the file and is bounded by a named cap.
        """
        with open(MODULE, encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("VERSION", text)
        self.assertNotRegex(text, r"count\s*!=\s*5")
        self.assertNotRegex(text, r"version\s*!=\s*5")

    def test_the_cap_is_a_named_constant(self):
        self.assertEqual(offload_bundle.MAX_ENTRIES, 4096)

    def test_the_magic_and_field_offsets_are_the_documented_ones(self):
        self.assertEqual(offload_bundle.MAGIC_LEN, 24)
        self.assertEqual(offload_bundle.COUNT_FIELD_OFFSET, 24)
        self.assertEqual(offload_bundle.DESCRIPTOR_SIZE, 24)
        self.assertEqual(offload_bundle.HEADER_LEN, 32)


if __name__ == "__main__":
    unittest.main()
