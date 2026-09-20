"""Host-only regression for the bridge payload build DAG.

The defect
----------
`src/bridge/README.md` told the reader to generate `bridge_gfx1030_fatbin.h`
"using the tooling in `../isa/` and `../emulator/`". Neither directory
contains a tool that emits a fatbin or a header. Nothing anywhere recorded
which historical phase directories the build actually depended on, so a
mandatory input was not merely unpublished -- it was unlisted, and the
documentation asserted the opposite.

What is checked here
--------------------
That the DAG records the real chain, that every mandatory input is declared,
and that the declarations are true against this tree. The load-bearing checks
are the negative controls: each one constructs a DAG with the defect restored
and requires the validator to reject it. A validator that accepts every input
would pass the positive checks too.

Controls, each building a real broken DAG and asserting on the failure:

  * `test_negative_control_undeclared_unpublished_input` -- the defect
    verbatim: a node with an unpublished tool stripped of its `documented`,
    `gap` and `acquisition`, i.e. an *undocumented* mandatory input.
  * `test_negative_control_unpublished_but_declared_published` -- a
    dependency that is missing from the tree while being labelled as
    published, which is how the README's claim behaved.
  * `test_negative_control_proprietary_input_marked_tracked` -- the
    user-supplied distribution declared trackable.
  * `test_negative_control_cycle`, `..._unreachable_node`,
    `..._backwards_edge` -- structural controls.
  * `test_negative_control_terminal_hides_a_gap` -- an unpublished dependency
    added to the graph while the terminal keeps claiming fewer gaps. This is
    the one that stops the gap list drifting.
  * `test_negative_control_present_path_called_unpublished` -- the reverse
    lie, so the check is not a one-way "must be absent".

The two published tools the DAG names are executed for real, in a temporary
directory, on a synthetic ELF. Nothing here touches a device, a compiler, or
the network.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

import hostpath  # noqa: F401  (sets up the import namespace)

REPO = hostpath.REPO_ROOT
BRIDGE = os.path.join(REPO, "src", "bridge")
TOOLS = os.path.join(BRIDGE, "tools")
DAG = os.path.join(BRIDGE, "bridge_payload_dag.json")
VALIDATOR = os.path.join(TOOLS, "bridge_payload_dag.py")
BUILD_TOOL = os.path.join(TOOLS, "p11_bundle_build.py")
HEADER_TOOL = os.path.join(TOOLS, "p11_embed_header.py")
DOC = os.path.join(REPO, "docs", "bridge-payload-build-dag.md")
README = os.path.join(BRIDGE, "README.md")

sys.path.insert(0, BRIDGE)
sys.path.insert(0, TOOLS)

import bridge_payload_dag as dagmod  # noqa: E402
import offload_bundle as ob  # noqa: E402


def real_dag() -> dict:
    with open(DAG, encoding="utf-8") as f:
        return json.load(f)


def node(dag: dict, nid: str) -> dict:
    for n in dag["nodes"]:
        if n["id"] == nid:
            return n
    raise KeyError(nid)


def run_tool(args, timeout=180):
    p = subprocess.run([sys.executable] + args, cwd=REPO, capture_output=True,
                       text=True, encoding="utf-8", errors="replace",
                       timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def synthetic_elf(size: int = 0x4000) -> bytes:
    """A minimal, deterministic ELF64LE image.

    The packaging tool only reads the identity bytes and the length, so a
    full object is not needed -- but the bytes must be deterministic for the
    hash round-trip to mean anything.
    """
    head = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    body = bytes((i * 7 + 3) & 0xFF for i in range(size - len(head)))
    return head + body


class TestTheDagIsValid(unittest.TestCase):
    """The positive direction: the DAG as published must pass."""

    @classmethod
    def setUpClass(cls):
        cls.dag = real_dag()
        cls.summary = dagmod.validate(cls.dag, REPO)

    def test_dag_and_validator_exist(self):
        for path in (DAG, VALIDATOR, DOC):
            self.assertTrue(os.path.exists(path), path)

    def test_validator_run_as_a_script_reports_ok(self):
        """The documented command must work, not just the imported module."""
        rc, out = run_tool(["src/bridge/tools/bridge_payload_dag.py"])
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn("STATUS OK", out)

    def test_all_ten_required_stages_are_covered(self):
        """The chain in the brief, in order, each with a node."""
        required = ["installer_bundle", "extraction", "profile_identity",
                    "source_elf", "symbol_metadata", "translation",
                    "assembly_link", "structural_validation",
                    "replacement_bundle", "bridge_gfx1030_fatbin_h"]
        self.assertEqual(self.dag["stages"], required)

    def test_graph_is_acyclic_and_fully_reachable(self):
        self.assertEqual(len(self.summary["reachable"]),
                         len(self.summary["nodes"]))

    def test_terminal_is_the_header(self):
        self.assertEqual(self.dag["terminal"]["artifact"],
                         "bridge_gfx1030_fatbin.h")

    def test_the_header_is_not_published_and_says_why(self):
        term = self.dag["terminal"]
        self.assertFalse(term["published"])
        self.assertTrue(term["publish_reason"].strip())
        self.assertTrue(term["consumer"].strip())

    def test_the_status_is_honestly_not_reproducible(self):
        """The whole point of F5: say the real status, do not imply more.

        If publishing the phase-9/phase-7/8/phase-11 tooling ever closes
        these gaps, this test fails and the DAG must be updated to say so --
        which is the intended direction of failure.
        """
        self.assertFalse(dagmod.reproducible(self.summary))
        self.assertEqual(self.dag["terminal"]["reproducibility"],
                         dagmod.NOT_REPRODUCIBLE)
        self.assertEqual(len(self.dag["terminal"]["blocking_gaps"]), 5)


class TestProvenanceIsTrueAgainstTheTree(unittest.TestCase):
    """Each declaration, checked against the disk rather than believed."""

    @classmethod
    def setUpClass(cls):
        cls.dag = real_dag()
        cls.prov = dagmod.validate(cls.dag, REPO)["provenance"]

    def test_the_proprietary_input_is_the_only_user_supplied_node(self):
        user = sorted(n for n, p in self.prov.items()
                      if p["kind"] == "USER_SUPPLIED")
        self.assertEqual(user, ["installer_bundle"])

    def test_the_proprietary_input_is_untracked_absent_and_unmanifested(self):
        n = node(self.dag, "installer_bundle")
        self.assertTrue(n["untracked"])
        self.assertTrue(n["acquisition"].strip())
        self.assertTrue(n["proprietary"])
        self.assertFalse(os.path.exists(os.path.join(REPO, n["historical_path"])))

    def test_published_tools_exist_on_disk(self):
        for nid, p in self.prov.items():
            for tool in p.get("tools", []):
                pass  # existence already enforced by validate()
        for tool in ("src/bridge/offload_bundle.py",
                     "src/bridge/tools/p11_bundle_build.py",
                     "src/bridge/tools/p11_embed_header.py"):
            self.assertTrue(os.path.exists(os.path.join(REPO, tool)), tool)

    def test_no_unpublished_historical_path_exists_in_this_tree(self):
        """A path declared unpublished must really be absent.

        If one of these appears, the node is mislabelled and the DAG is
        describing a dependency it claims not to have.
        """
        for n in self.dag["nodes"]:
            tools = ([n["tool"]] if isinstance(n.get("tool"), dict) else []) + \
                    (n.get("tools") or [])
            for tool in tools:
                if tool.get("kind") == "UNPUBLISHED_TOOL":
                    hist = tool["historical_path"]
                    self.assertFalse(
                        os.path.exists(os.path.join(REPO, hist)),
                        f"{n['id']}: {hist} is present but declared unpublished")

    def test_every_unpublished_tool_carries_a_gap_and_an_acquisition(self):
        """The F5 rule, stated as a property of the published file."""
        seen = 0
        for n in self.dag["nodes"]:
            tools = ([n["tool"]] if isinstance(n.get("tool"), dict) else []) + \
                    (n.get("tools") or [])
            for tool in tools:
                if tool.get("kind") == "UNPUBLISHED_TOOL":
                    seen += 1
                    self.assertTrue(tool.get("documented") is True, n["id"])
                    self.assertTrue(tool["gap"].strip(), n["id"])
                    self.assertTrue(tool["acquisition"].strip(), n["id"])
        self.assertGreaterEqual(seen, 5, "the gaps vanished; update the DAG status")

    def test_external_tools_are_declared_external(self):
        """llvm-mc and ld.lld are vendor tools, not project artefacts."""
        tools = node(self.dag, "assemble_link")["tools"]
        ext = [t for t in tools if t["kind"] == "EXTERNAL_TOOL"]
        self.assertEqual(sorted(t["path"] for t in ext),
                         ["ld.lld.exe", "llvm-mc.exe"])
        for t in ext:
            self.assertTrue(t["why_external"].strip())


class TestNegativeControls(unittest.TestCase):
    """Each control restores the defect and requires rejection.

    Every one of these mutates a copy of the real DAG. If a mutation is
    accepted, the corresponding rule in the validator is not doing anything,
    and the positive tests above prove nothing.
    """

    @classmethod
    def setUpClass(cls):
        cls.dag = real_dag()

    def assertRejected(self, dag, needle=None, exc=dagmod.DagError):
        with self.assertRaises(exc) as ctx:
            dagmod.validate(dag, REPO)
        if needle:
            self.assertIn(needle, str(ctx.exception))

    def test_negative_control_undeclared_unpublished_input(self):
        """The defect verbatim: an unpublished mandatory input with no
        documentation. This is precisely what the README did -- a required
        step whose tooling was never named."""
        dag = copy.deepcopy(self.dag)
        tool = node(dag, "translate_isa")["tool"]
        for field in ("documented", "gap", "acquisition"):
            tool.pop(field, None)
        self.assertRejected(dag, "undocumented mandatory input",
                            dagmod.DagProvenanceError)

    def test_negative_control_unpublished_but_declared_published(self):
        """A dependency that is not in the tree, labelled as if it were.

        This is the shape of the original claim: the reader was told the
        tooling was in `../isa/`, so the dependency looked satisfied.
        """
        dag = copy.deepcopy(self.dag)
        tool = node(dag, "source_elf")["tool"]
        tool["kind"] = "PUBLISHED_TOOL"
        tool["path"] = "phase5_exact_fragment/gfx1100_code_object.o"
        self.assertRejected(dag, "declared published but is not in this tree",
                            dagmod.DagProvenanceError)

    def test_negative_control_present_path_called_unpublished(self):
        """The reverse lie must fail too, so the check is not one-way."""
        dag = copy.deepcopy(self.dag)
        tool = node(dag, "translate_isa")["tool"]
        tool["historical_path"] = "src/bridge"
        self.assertRejected(dag, "the node is mislabelled",
                            dagmod.DagProvenanceError)

    def test_negative_control_proprietary_input_marked_tracked(self):
        dag = copy.deepcopy(self.dag)
        node(dag, "installer_bundle")["untracked"] = False
        self.assertRejected(dag, "must be declared `untracked: true`",
                            dagmod.DagProvenanceError)

    def test_negative_control_proprietary_input_present_in_the_tree(self):
        """If the distribution is ever published here, the DAG must fail."""
        dag = copy.deepcopy(self.dag)
        node(dag, "installer_bundle")["historical_path"] = "src/bridge/README.md"
        self.assertRejected(dag, "present in the published tree",
                            dagmod.DagProvenanceError)

    def test_negative_control_terminal_hides_a_gap(self):
        """An unpublished dependency arrives; the terminal must notice.

        Without this, a new historical dependency could be added to the
        chain while the summary line went on reporting five gaps.
        """
        dag = copy.deepcopy(self.dag)
        tools = node(dag, "structural_validation")["tool"]
        tools["kind"] = "UNPUBLISHED_TOOL"
        tools["historical_path"] = "phase9_static/tools/"
        tools["documented"] = True
        tools["gap"] = "x"
        tools["acquisition"] = "y"
        self.assertRejected(dag, "does not declare these unpublished mandatory "
                                 "inputs")

    def test_negative_control_terminal_invents_a_gap(self):
        dag = copy.deepcopy(self.dag)
        dag["terminal"]["blocking_gaps"].append("structural_validation")
        self.assertRejected(dag, "declares gaps that are not in the graph")

    def test_negative_control_cycle_is_rejected(self):
        dag = copy.deepcopy(self.dag)
        # stage order would also catch this, so disable that by making the
        # edge legal in stage terms and check the cycle detector itself.
        node(dag, "installer_bundle").setdefault("inputs", []).append(
            "extract_bundle")
        node(dag, "installer_bundle")["stage"] = "extraction"
        dag["stages"] = [s for s in dag["stages"] if s != "installer_bundle"]
        if "extraction" not in dag["stages"]:
            dag["stages"].insert(0, "extraction")
        with self.assertRaises(dagmod.DagError) as ctx:
            dagmod.validate(dag, REPO)
        self.assertIn("cycle", str(ctx.exception))

    def test_negative_control_unreachable_node_is_rejected(self):
        dag = copy.deepcopy(self.dag)
        lonely = copy.deepcopy(node(dag, "symbol_metadata"))
        lonely["id"] = "orphan_step"
        dag["nodes"].append(lonely)
        self.assertRejected(dag, "not reachable from the terminal")

    def test_negative_control_backwards_edge_is_rejected(self):
        dag = copy.deepcopy(self.dag)
        node(dag, "installer_bundle")["inputs"] = ["embed_header"]
        with self.assertRaises(dagmod.DagError) as ctx:
            dagmod.validate(dag, REPO)
        self.assertIn("runs backwards", str(ctx.exception))

    def test_negative_control_undeclared_input_id(self):
        dag = copy.deepcopy(self.dag)
        node(dag, "embed_header")["inputs"] = ["not_a_node"]
        self.assertRejected(dag, "is not a declared node")

    def test_negative_control_a_stage_with_no_node(self):
        dag = copy.deepcopy(self.dag)
        dag["stages"].append("a_stage_nobody_implements")
        self.assertRejected(dag, "has no node")

    def test_negative_control_wrong_reproducibility_claim(self):
        """Claiming reproducibility while gaps exist is the README's error."""
        dag = copy.deepcopy(self.dag)
        dag["terminal"]["reproducibility"] = dagmod.REPRODUCIBLE
        self.assertRejected(dag, "the graph says")

    def test_negative_control_a_derived_node_with_no_tool(self):
        dag = copy.deepcopy(self.dag)
        node(dag, "translate_isa").pop("tool")
        self.assertRejected(dag, "must declare `tool` or `tools`")


class TestThePublishedToolsActuallyWork(unittest.TestCase):
    """The two tools the DAG names are run, not merely asserted to exist."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="f5tools-")
        self.obj = os.path.join(self.work, "translated.co")
        with open(self.obj, "wb") as f:
            f.write(synthetic_elf())
        self.bundle = os.path.join(self.work, "gfx1030_dlssnr.fatbin")
        self.header = os.path.join(self.work, "bridge_gfx1030_fatbin.h")

    def build(self, *extra):
        return run_tool(["src/bridge/tools/p11_bundle_build.py",
                         "--object", self.obj, "--out", self.bundle] + list(extra))

    def test_build_then_check_then_embed_round_trips(self):
        rc, out = self.build()
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn("STATUS OK", out)
        self.assertTrue(os.path.exists(self.bundle))

        rc, out = run_tool(["src/bridge/tools/p11_bundle_build.py",
                            "--check", self.bundle])
        self.assertEqual(rc, 0, out[-3000:])
        self.assertIn("2 entries", out)
        self.assertIn(ob.GFX1030_TARGET_ID, out)

        rc, out = run_tool(["src/bridge/tools/p11_embed_header.py",
                            "--bundle", self.bundle, "--out", self.header])
        self.assertEqual(rc, 0, out[-3000:])

    def test_the_written_bundle_is_the_input_object_under_a_real_parse(self):
        """Read the artifact back and check a property that is predictable."""
        rc, out = self.build()
        self.assertEqual(rc, 0, out[-3000:])
        with open(self.bundle, "rb") as f:
            bundle = f.read()
        parsed = ob.parse(bundle, expect_full_span=True)
        self.assertEqual(parsed.declared_count, 2)
        payload = ob.select_gfx1030(parsed).payload(memoryview(bundle))
        self.assertEqual(payload, synthetic_elf())
        # The synthetic object is an ELF; the header's first payload bytes
        # must therefore be the ELF magic, which is a fact about the input
        # rather than about the builder.
        self.assertEqual(payload[:4], b"\x7fELF")

    def test_the_count_field_is_a_count_not_a_version(self):
        """The defect this tool exists to not repeat.

        A previous builder wrote a literal 5 into the count field while
        emitting two descriptors, and documented the field as a version.
        """
        rc, out = self.build()
        self.assertEqual(rc, 0, out[-3000:])
        with open(self.bundle, "rb") as f:
            bundle = f.read()
        import struct
        (field,) = struct.unpack_from("<Q", bundle, ob.COUNT_FIELD_OFFSET)
        self.assertEqual(field, 2, "the count field is not the entry count")
        self.assertNotEqual(field, 5)

    def test_negative_control_a_non_elf_object_is_refused(self):
        with open(self.obj, "wb") as f:
            f.write(b"not an elf at all, just text" * 40)
        rc, out = self.build()
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertIn("not an ELF file", out)
        self.assertFalse(os.path.exists(self.bundle),
                         "a refused build still wrote a bundle")

    def test_negative_control_a_32_bit_object_is_refused(self):
        data = bytearray(synthetic_elf())
        data[4] = 1  # EI_CLASS = 32-bit
        with open(self.obj, "wb") as f:
            f.write(bytes(data))
        rc, out = self.build()
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertIn("EI_CLASS", out)

    def test_negative_control_duplicate_ids_are_refused(self):
        rc, out = self.build("--host-id", ob.GFX1030_TARGET_ID)
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertIn("duplicate", out.lower())

    def test_negative_control_a_wrong_target_id_is_refused(self):
        rc, out = self.build("--target-id", "hipv4-amdgcn-amd-amdhsa--gfx1100")
        # The build is fine; the *embedding* step is what refuses.
        self.assertEqual(rc, 0, out[-2000:])
        rc, out = run_tool(["src/bridge/tools/p11_embed_header.py",
                            "--bundle", self.bundle, "--out", self.header])
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertIn("wrong file", out.lower())
        self.assertFalse(os.path.exists(self.header),
                         "an identity gate header was written from a bundle "
                         "that does not carry the target")

    def test_negative_control_embedding_a_non_bundle_is_refused(self):
        with open(self.bundle, "wb") as f:
            f.write(b"\x00" * 4096)
        rc, out = run_tool(["src/bridge/tools/p11_embed_header.py",
                            "--bundle", self.bundle, "--out", self.header])
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertIn("does not parse", out)
        self.assertFalse(os.path.exists(self.header))

    def test_negative_control_check_refuses_the_historical_malformed_bundle(self):
        """Measured, not narrated: the strict reader rejects it.

        The historical rebuilt bundle carries two descriptors but writes 5
        in the count field and pads with a zero descriptor. A reader that
        parses exactly `count` descriptors therefore walks into the padding
        and rejects it. If that file is ever fixed, this control goes stale
        and must be replaced -- so it is written against a reconstruction of
        the malformed shape rather than against the private file, which this
        repository does not publish and must not depend on.
        """
        import struct
        term = b"\0"
        ids = [(b"host-x86_64-unknown-linux-gnu" + term, b""),
               (ob.GFX1030_TARGET_ID.encode() + term, synthetic_elf())]
        table = bytearray(ob.MAGIC) + struct.pack("<Q", 5)  # the defect
        cursor = 0x1000
        for ident, payload in ids:
            table += struct.pack("<QQQ", cursor, len(payload), len(ident))
            table += ident
            cursor += len(payload)
        table += b"\0" * 24  # the terminator the old reader scanned for
        malformed = bytes(table) + b"\0" * (0x1000 - len(table)) + synthetic_elf()
        with open(self.bundle, "wb") as f:
            f.write(malformed)

        rc, out = run_tool(["src/bridge/tools/p11_bundle_build.py",
                            "--check", self.bundle])
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertIn("identifier length is 0", out)

        # And the control is discriminating: the same bytes with the correct
        # count parse cleanly, so the rejection is caused by the field and
        # not by anything else in the reconstruction.
        good = bytearray(malformed)
        struct.pack_into("<Q", good, ob.COUNT_FIELD_OFFSET, 2)
        parsed = ob.parse(bytes(good), expect_full_span=True)
        self.assertEqual(parsed.declared_count, 2)


class TestTheReadmeNoLongerMisdirects(unittest.TestCase):
    """The published instruction that was wrong must not come back."""

    def setUp(self):
        with open(README, encoding="utf-8") as f:
            self.text = f.read()

    def test_readme_no_longer_claims_isa_and_emulator_generate_the_header(self):
        self.assertNotIn("using the tooling in", self.text)
        self.assertNotIn("`../isa/` and `../emulator/`", self.text)

    def test_readme_points_at_the_dag(self):
        self.assertIn("bridge-payload-build-dag", self.text)

    def test_readme_still_says_the_header_is_not_published(self):
        self.assertIn("deliberately not published", self.text)

    def test_doc_names_the_gaps_rather_than_claiming_reproducibility(self):
        with open(DOC, encoding="utf-8") as f:
            doc = f.read()
        self.assertIn("NOT_REPRODUCIBLE_FROM_PUBLIC_TREE", doc)
        self.assertIn("not published", doc)
        for stage in ("translation", "symbol metadata", "assemble"):
            self.assertIn(stage, doc)


if __name__ == "__main__":
    unittest.main()
