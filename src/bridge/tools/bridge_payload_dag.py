"""Validate `src/bridge/bridge_payload_dag.json`.

Why a validator and not just a document
---------------------------------------
A build DAG written as prose goes stale silently. The specific failure this
project had was worse than staleness: the published README named a directory
(`../isa/`) as the place to generate the bridge payload header from, and that
directory contains no tool which does any such thing. A reader following the
documentation would conclude the payload was reproducible from the tree when
it was not.

So the DAG is data, and the rules that make it honest are checked:

  * **structure** -- the graph is acyclic, every edge names a declared node,
    every node is reachable from the terminal, and no edge runs backwards
    through the declared stage order. A DAG that is really two disconnected
    fragments with a decorative arrow between them is rejected.

  * **provenance** -- every node's declared kind is checked against the disk.
    A node claiming `PUBLISHED_TOOL` must name a file that exists in this
    tree; a node claiming `UNPUBLISHED_TOOL` must name a historical path that
    does *not*, because a path that is present and still declared unpublished
    is a mislabelled dependency.

  * **documentation** -- this is the rule the original defect violated. An
    unpublished mandatory input is allowed only when it is *declared*: the
    node must carry a non-empty `gap` and a non-empty `acquisition`, and the
    terminal must list the node in its `blocking_gaps`. The terminal's list
    is compared against the set computed from the graph, in both directions,
    so an added unpublished dependency cannot slip in undeclared and a
    declared gap cannot describe something that is not there.

  * **the proprietary input stays untracked** -- the `USER_SUPPLIED` node must
    be flagged `untracked`, must not exist in this tree, and must not appear
    in `audit/PUBLICATION_MANIFEST.json`. If someone ever publishes the
    distribution under study, this check fails rather than letting the DAG go
    on claiming the input is user-supplied.

Structural validation and policy are kept apart here too, in the same spirit
as `offload_bundle.py`: `validate()` answers "is this DAG honest", and
`reproducible()` answers "can a reader with only this tree produce the
terminal", which is a *policy* question about what counts as reproducible.

Host-only, stdlib only, read-only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Sequence, Set, Tuple

SCHEMA = "bridge-payload-build-dag/1"

#: Relative to the repository root.
DAG_PATH = os.path.join("src", "bridge", "bridge_payload_dag.json")
MANIFEST_PATH = os.path.join("audit", "PUBLICATION_MANIFEST.json")

REPRODUCIBLE = "REPRODUCIBLE_FROM_PUBLIC_TREE"
NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE_FROM_PUBLIC_TREE"

TOOL_KINDS = ("PUBLISHED_TOOL", "UNPUBLISHED_TOOL", "EXTERNAL_TOOL")
NODE_KINDS = ("USER_SUPPLIED", "DERIVED")


class DagError(Exception):
    """Base class for every DAG validation failure."""


class DagDeclarationError(DagError):
    """The file itself is malformed or omits a required declaration."""


class DagProvenanceError(DagError):
    """A declared provenance is false against the tree it describes.

    Separate from `DagDeclarationError` so a report can distinguish "you
    forgot to say where this comes from" from "what you said is not true".
    """


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------
def load(path: str = DAG_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        dag = json.load(f)
    if not isinstance(dag, dict):
        raise DagDeclarationError("the DAG must be a JSON object")
    if dag.get("schema") != SCHEMA:
        raise DagDeclarationError(
            f"schema is {dag.get('schema')!r}, expected {SCHEMA!r}")
    return dag


def _nodes_by_id(dag: dict) -> Dict[str, dict]:
    nodes = dag.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise DagDeclarationError("`nodes` must be a non-empty list")
    out: Dict[str, dict] = {}
    for i, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise DagDeclarationError(f"node {i} is not an object")
        nid = node.get("id")
        if not nid or not isinstance(nid, str):
            raise DagDeclarationError(f"node {i} has no string `id`")
        if nid in out:
            raise DagDeclarationError(f"duplicate node id {nid!r}")
        out[nid] = node
    return out


def _tools_of(node: dict) -> List[dict]:
    """A node's tool declarations, accepting either spelling in the file."""
    tools = []
    if isinstance(node.get("tool"), dict):
        tools.append(node["tool"])
    if isinstance(node.get("tools"), list):
        tools.extend(node["tools"])
    return tools


def _nonempty(node: dict, field: str) -> str:
    value = node.get(field)
    if not isinstance(value, str) or not value.strip():
        raise DagDeclarationError(
            f"node {node.get('id')!r}: `{field}` must be a non-empty string")
    return value


# ---------------------------------------------------------------------------
# structure
# ---------------------------------------------------------------------------
def check_stages(dag: dict, nodes: Dict[str, dict]) -> List[str]:
    """The declared stage list must be exactly the stages the nodes use."""
    stages = dag.get("stages")
    if not isinstance(stages, list) or not stages:
        raise DagDeclarationError("`stages` must be a non-empty list")
    if len(set(stages)) != len(stages):
        raise DagDeclarationError(f"`stages` repeats a name: {stages}")
    index = {name: i for i, name in enumerate(stages)}

    for node in nodes.values():
        stage = node.get("stage")
        if stage not in index:
            raise DagDeclarationError(
                f"node {node['id']!r}: stage {stage!r} is not in `stages`")

    for name in stages:
        if not any(n.get("stage") == name for n in nodes.values()):
            raise DagDeclarationError(
                f"declared stage {name!r} has no node: the chain is not covered")
    return stages


def check_edges(dag: dict, nodes: Dict[str, dict]) -> List[Tuple[str, str]]:
    """Every input is a declared node, and no edge runs backwards in stage."""
    stages = dag["stages"]
    index = {name: i for i, name in enumerate(stages)}
    edges: List[Tuple[str, str]] = []
    for nid, node in nodes.items():
        inputs = node.get("inputs", [])
        if not isinstance(inputs, list):
            raise DagDeclarationError(f"node {nid!r}: `inputs` must be a list")
        for src in inputs:
            if src not in nodes:
                raise DagDeclarationError(
                    f"node {nid!r}: input {src!r} is not a declared node")
            if index[nodes[src]["stage"]] > index[node["stage"]]:
                raise DagDeclarationError(
                    f"edge {src!r} -> {nid!r} runs backwards: "
                    f"{nodes[src]['stage']!r} comes after {node['stage']!r}")
            edges.append((src, nid))
    return edges


def check_acyclic(nodes: Dict[str, dict]) -> None:
    WHITE, GREY, BLACK = 0, 1, 2
    colour = {nid: WHITE for nid in nodes}

    def visit(nid: str, path: List[str]) -> None:
        colour[nid] = GREY
        for src in nodes[nid].get("inputs", []):
            if colour[src] == GREY:
                cycle = path[path.index(src):] + [src] if src in path else [src, nid]
                raise DagDeclarationError(
                    f"cycle in the DAG: {' -> '.join(cycle)}")
            if colour[src] == WHITE:
                visit(src, path + [src])
        colour[nid] = BLACK

    for nid in nodes:
        if colour[nid] == WHITE:
            visit(nid, [nid])


def check_reachable(dag: dict, nodes: Dict[str, dict]) -> Set[str]:
    """Everything must be reachable from the terminal by walking backwards."""
    terminal = (dag.get("terminal") or {}).get("node")
    if terminal not in nodes:
        raise DagDeclarationError(
            f"terminal node {terminal!r} is not a declared node")
    seen: Set[str] = set()
    stack = [terminal]
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)
        stack.extend(nodes[nid].get("inputs", []))
    unreachable = sorted(set(nodes) - seen)
    if unreachable:
        raise DagDeclarationError(
            f"nodes not reachable from the terminal {terminal!r}: {unreachable}. "
            "A node nothing consumes is decoration, not a step.")
    return seen


# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------
def _manifest_source_paths(repo_root: str) -> Optional[Set[str]]:
    """Every `source_path` recorded in the publication manifest, or None."""
    path = os.path.join(repo_root, MANIFEST_PATH)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        manifest = json.load(f)
    out: Set[str] = set()
    for entry in manifest.get("files", []):
        if isinstance(entry, dict) and entry.get("source_path"):
            out.add(entry["source_path"].replace("\\", "/"))
    for entry in manifest.get("newly_authored", []):
        if isinstance(entry, str):
            out.add(entry.replace("\\", "/"))
        elif isinstance(entry, dict):
            for key in ("source_path", "public_path", "path"):
                if entry.get(key):
                    out.add(entry[key].replace("\\", "/"))
    return out


def check_provenance(dag: dict, nodes: Dict[str, dict], repo_root: str) -> dict:
    """Check every declared kind against the disk. Returns a provenance map."""
    repo_root = os.path.abspath(repo_root)
    manifest = _manifest_source_paths(repo_root)
    provenance: Dict[str, dict] = {}

    for nid, node in nodes.items():
        kind = node.get("kind")
        if kind not in NODE_KINDS:
            raise DagDeclarationError(
                f"node {nid!r}: kind {kind!r} is not one of {NODE_KINDS}")

        if kind == "USER_SUPPLIED":
            if node.get("untracked") is not True:
                raise DagProvenanceError(
                    f"node {nid!r}: a USER_SUPPLIED input must be declared "
                    "`untracked: true`. This project studies the distribution; "
                    "it does not redistribute it.")
            acquisition = _nonempty(node, "acquisition")
            hist = _nonempty(node, "historical_path").replace("\\", "/")
            if os.path.exists(os.path.join(repo_root, hist)):
                raise DagProvenanceError(
                    f"node {nid!r}: declared USER_SUPPLIED but {hist!r} is "
                    "present in the published tree")
            if manifest is not None and hist in manifest:
                raise DagProvenanceError(
                    f"node {nid!r}: the user-supplied input {hist!r} appears "
                    "in the publication manifest. The proprietary input must "
                    "stay untracked.")
            provenance[nid] = {"kind": kind, "untracked": True,
                               "acquisition": acquisition}
            continue

        # DERIVED: the interesting case, because a derived node's honesty is
        # entirely about the tool it names.
        tools = _tools_of(node)
        if not tools:
            raise DagDeclarationError(
                f"node {nid!r}: a DERIVED node must declare `tool` or `tools`")
        unpublished = False
        for tool in tools:
            tkind = tool.get("kind")
            if tkind not in TOOL_KINDS:
                raise DagDeclarationError(
                    f"node {nid!r}: tool kind {tkind!r} is not one of "
                    f"{TOOL_KINDS}")
            _nonempty(tool, "path")
            if tkind == "PUBLISHED_TOOL":
                rel = tool["path"].replace("\\", "/")
                if not os.path.exists(os.path.join(repo_root, rel)):
                    raise DagProvenanceError(
                        f"node {nid!r}: tool {rel!r} is declared published but "
                        "is not in this tree")
            elif tkind == "UNPUBLISHED_TOOL":
                unpublished = True
                hist = _nonempty(tool, "historical_path").replace("\\", "/")
                if os.path.exists(os.path.join(repo_root, hist)):
                    raise DagProvenanceError(
                        f"node {nid!r}: tool {hist!r} is declared unpublished "
                        "but is present in this tree; the node is mislabelled")
                # The rule the original documentation broke: an unpublished
                # mandatory input must be *documented*, at the node and at
                # the terminal.
                if tool.get("documented") is not True:
                    raise DagProvenanceError(
                        f"node {nid!r}: unpublished tool {hist!r} is an "
                        "undocumented mandatory input. Set `documented: true` "
                        "and give it a `gap` and an `acquisition`.")
                _nonempty(tool, "gap")
                _nonempty(tool, "acquisition")
            else:  # EXTERNAL_TOOL
                _nonempty(tool, "historical_path")
                _nonempty(tool, "why_external")
        provenance[nid] = {"kind": kind, "unpublished_tool": unpublished,
                           "tools": [t["path"] for t in tools]}
    return provenance


# ---------------------------------------------------------------------------
# the terminal's own declarations
# ---------------------------------------------------------------------------
def check_terminal(dag: dict, nodes: Dict[str, dict],
                   provenance: Dict[str, dict]) -> dict:
    """The terminal must declare exactly the gaps the graph actually has."""
    term = dag.get("terminal")
    if not isinstance(term, dict):
        raise DagDeclarationError("`terminal` must be an object")
    nid = term.get("node")
    if nid not in nodes:
        raise DagDeclarationError(f"terminal node {nid!r} is not declared")
    _nonempty(term, "artifact")

    declared = term.get("blocking_gaps")
    if not isinstance(declared, list):
        raise DagDeclarationError(
            "`terminal.blocking_gaps` must be a list (possibly empty)")
    if len(set(declared)) != len(declared):
        raise DagDeclarationError(
            f"`terminal.blocking_gaps` repeats an id: {declared}")

    actual = sorted(n for n in nodes
                    if provenance.get(n, {}).get("unpublished_tool"))
    if sorted(declared) != actual:
        undeclared = sorted(set(actual) - set(declared))
        phantom = sorted(set(declared) - set(actual))
        parts = []
        if undeclared:
            parts.append(
                f"the terminal does not declare these unpublished mandatory "
                f"inputs: {undeclared}")
        if phantom:
            parts.append(
                f"the terminal declares gaps that are not in the graph: "
                f"{phantom}")
        raise DagDeclarationError(
            "terminal.blocking_gaps does not match the graph; " + "; ".join(parts))

    want = NOT_REPRODUCIBLE if actual else REPRODUCIBLE
    if term.get("reproducibility") != want:
        raise DagDeclarationError(
            f"terminal.reproducibility is {term.get('reproducibility')!r} but "
            f"the graph says {want!r}")

    if term.get("published") is not True:
        _nonempty(term, "publish_reason")
        _nonempty(term, "consumer")
    return term


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------
def validate(dag: dict, repo_root: str) -> dict:
    """Check the DAG. Raises on the first failure; returns a summary."""
    nodes = _nodes_by_id(dag)
    stages = check_stages(dag, nodes)
    edges = check_edges(dag, nodes)
    check_acyclic(nodes)
    reachable = check_reachable(dag, nodes)
    provenance = check_provenance(dag, nodes, repo_root)
    term = check_terminal(dag, nodes, provenance)
    return {"nodes": nodes, "stages": stages, "edges": edges,
            "reachable": reachable, "provenance": provenance, "terminal": term}


def reproducible(summary: dict) -> bool:
    """Policy: can a reader with only this tree produce the terminal?

    Separated from `validate` on purpose. The DAG below is *valid* and is not
    reproducible, and a report has to be able to say both.
    """
    return not summary["terminal"]["blocking_gaps"]


def report(dag: dict, summary: dict) -> Sequence[str]:
    nodes, prov = summary["nodes"], summary["provenance"]
    lines = [f"DAG {dag['title']}",
             f"stages: {len(summary['stages'])} "
             f"({', '.join(summary['stages'])})",
             f"nodes: {len(nodes)}  edges: {len(summary['edges'])}"]

    user = sorted(n for n, p in prov.items() if p["kind"] == "USER_SUPPLIED")
    lines.append(f"user-supplied (untracked): {user}")
    pub = sorted(n for n, p in prov.items()
                 if p["kind"] == "DERIVED"
                 and not p.get("unpublished_tool"))
    lines.append(f"reproducible-from-this-tree: {pub}")
    gaps = summary["terminal"]["blocking_gaps"]
    lines.append(f"blocking gaps ({len(gaps)}): {gaps}")
    for nid in gaps:
        for tool in _tools_of(nodes[nid]):
            if tool.get("kind") == "UNPUBLISHED_TOOL":
                lines.append(f"  - {nid}: needs {tool['path']} "
                             f"(unpublished: {tool['historical_path']})")
    term = summary["terminal"]
    lines.append(f"terminal: {term['artifact']} "
                 f"(published={term.get('published')!r})")
    lines.append(f"reproducibility: {term['reproducibility']}")
    lines.append("STATUS OK")
    return lines


def _repo_root_default() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    # src/bridge/tools/ -> src/bridge -> src -> repo
    return os.path.dirname(os.path.dirname(os.path.dirname(here)))


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dag", default=DAG_PATH)
    ap.add_argument("--repo-root", default=_repo_root_default())
    ap.add_argument("--quiet", action="store_true",
                    help="print only STATUS and the gap count")
    args = ap.parse_args(argv)

    dag = load(args.dag)
    summary = validate(dag, args.repo_root)
    if args.quiet:
        print(f"STATUS OK GAPS {len(summary['terminal']['blocking_gaps'])}")
    else:
        for line in report(dag, summary):
            print(line)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DagError as exc:
        print(f"STATUS FAILED {type(exc).__name__}: {exc}")
        sys.exit(1)
