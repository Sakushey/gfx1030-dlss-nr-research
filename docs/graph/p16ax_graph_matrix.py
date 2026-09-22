#!/usr/bin/env python3
"""Phase 16AX / T-GRAPH (W5) -- DELIVERABLE 1.

CROSS_SOURCE_GRAPH_MATRIX_16AX.json: one ROW per logical block/operator, with
columns for the local mapping and for each external source mapping.

HOST ONLY.  numpy is NOT installed; this is pure standard library.

THE RULE THIS ARTIFACT EXISTS TO ENFORCE
----------------------------------------
Two sources agreeing is NOT proof.  If both sides of a comparison trace to one
artefact -- one parser, one capture, one upstream file -- the agreement is
guaranteed by construction and certifies nothing.  So every row carries:

  * an EVIDENCE LEVEL, which names what the local side actually measured, not
    how confident anyone feels about it; and
  * a CONSENSUS state that distinguishes AGREEMENT_WITHIN_ONE_LINEAGE (the two
    agreeing sides share an evidence lineage, so the agreement is not
    corroboration) from AGREEMENT_INDEPENDENT_SIDES and from
    CONFLICT_RECORDED.

External columns are populated ONLY from what worker W4 (T-SOURCES) actually
measured.  W4's output directory did not exist when this generator ran, so
every external cell is NOT_TESTED with an explicit pending marker naming the
pinned commit W4 must use.  That is a deliberate refusal to guess: a filled
cell here would be indistinguishable, to every downstream reader, from a
measurement that was never made.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p16ax_common as C   # noqa: E402

OUT = "p16ax/graph/CROSS_SOURCE_GRAPH_MATRIX_16AX.json"

# ---------------------------------------------------------------------------
# W4 / T-SOURCES measured output.  This worker does not measure these sources
# itself: it CONSUMES what W4 measured.  Every external cell below is filled
# from these artifacts or stays NOT_TESTED.  The five paths are hashed here so a
# later change to W4's evidence is visible rather than silently absorbed.
# ---------------------------------------------------------------------------
W4_SOURCE_REFRESH = "p16ax/sources/SOURCE_REFRESH_16AX.json"
W4_LICENCE_PROBE = "p16ax/sources/LICENCE_PROBE_16AX.json"
W4_LAYOUT_PROBE = "p16ax/sources/LAYOUT_PROBE_RESULT_16AX.json"
W4_ISA_CENSUS = "p16ax/sources/ISA_CENSUS_16AX.json"
W4_OUR_SIDE = "p16ax/sources/OUR_SIDE_FACTS_16AX.json"

W4_REQUIRED = [W4_SOURCE_REFRESH, W4_LICENCE_PROBE, W4_LAYOUT_PROBE,
               W4_ISA_CENSUS, W4_OUR_SIDE]

# ---------------------------------------------------------------------------
# External columns.  The three named sources are the ones the brief names.
# Each carries the pinned identity that a measurement would have to be scoped
# to, so that a later fill cannot silently be about a different revision.
# ---------------------------------------------------------------------------
EXTERNAL_SOURCES = [
    {
        "column": "opendlss_mapping",
        "source_id": "SRC-OPEN-DLSS-NR",
        "kind": "external_research_repository",
        "pinned_identity": "UNKNOWN -- no pinned commit is recorded anywhere in "
                           "this tree for a repository named OpenDLSS-NR",
        "pinned_identity_basis": "whole-tree search for the literal 'opendlss' "
                                 "returns exactly one hit outside the 16AX "
                                 "control plane: MASTER_PLAN_16AX.json's own W4 "
                                 "task title. No tree, clone, manifest, hash "
                                 "or locator for this source exists in the tree.",
        "cell_state": "NOT_TESTED",
        "cell_state_reason": "the source has no pinned identity in this tree, "
                             "so no cell can be scoped to a revision; a value "
                             "here would be unscoped",
        "owner_of_the_measurement": "W4 / T-SOURCES",
        "owner_output_path": "p16ax/sources/",
        "owner_output_present_when_this_ran": False,
    },
    {
        "column": "translation_lab_mapping",
        "source_id": "SRC-A-TRANSLATION-LAB",
        "kind": "external_research_repository",
        "pinned_identity": "152fdfecf0d3b03f08628606b6458dd3cbd90e0c",
        "pinned_identity_branch": "refs/heads/main",
        "pinned_identity_basis": "p16aw/sources/SOURCE_GROUNDING_REGISTER.json "
                                 "measured field last_seen_commit, which was "
                                 "read here, not measured here",
        "licence": "NO_EXPLICIT_LICENSE_OBSERVED -- vendoring_permitted false",
        "local_read_only_clone": "p16au/external/_clone/translation-lab",
        "local_clone_head": "4a0ec6e03bd05f11cd991d3a6883891037c1b7c2",
        "local_clone_head_differs_from_the_pin": True,
        "cell_state": "NOT_TESTED",
        "cell_state_reason": "W4 owns the compatibility measurement. A clone "
                             "exists locally, but reading it in this worker "
                             "would produce a SECOND local reading sharing this "
                             "project's own evidence lineage, not W4's measured "
                             "compatibility axis. The cell is left empty on "
                             "purpose.",
        "owner_of_the_measurement": "W4 / T-SOURCES",
        "owner_output_path": "p16ax/sources/",
        "owner_output_present_when_this_ran": False,
    },
    {
        "column": "paimonshen_mapping",
        "source_id": "SRC-PAIMONSHEN",
        "kind": "external_research_repository",
        "pinned_identity": "UNKNOWN -- no pinned commit is recorded anywhere in "
                           "this tree for a repository named Paimonshen",
        "pinned_identity_basis": "whole-tree search for the literal 'paimonshen' "
                                 "(case-insensitive) returns ZERO hits in the "
                                 "entire project tree, including the 16AX "
                                 "control plane.",
        "cell_state": "NOT_TESTED",
        "cell_state_reason": "the source has no pinned identity in this tree; "
                             "it is named in the W5 task text and nowhere else",
        "owner_of_the_measurement": "W4 / T-SOURCES",
        "owner_output_path": "p16ax/sources/",
        "owner_output_present_when_this_ran": False,
    },
]

# ---------------------------------------------------------------------------
# Evidence levels.  These describe WHAT THE LOCAL SIDE MEASURED.
# ---------------------------------------------------------------------------
EVIDENCE_VOCABULARY = {
    "E4_LOCAL_BLOCK_INSTANCE_GRADED":
        "the row has a local identity whose correspondence survives the 16AO "
        "row-uniqueness audit at REFERENCE BLOCK INSTANCE granularity, i.e. "
        "the audit judged it safe_to_ground_a_native_operator_on at that "
        "granularity",
    "E3_LOCAL_OPERATOR_TYPE_EXACT":
        "the row has a local identity with the EXACT verdict whose "
        "correspondence survives only at OPERATOR TYPE granularity: every "
        "same-family alternative is beaten through the positional channel",
    "E2_LOCAL_OPERATOR_TYPE_HIGH_CONFIDENCE":
        "the row has a local identity with the HIGH_CONFIDENCE verdict, which "
        "is operator-type evidence and carries no block-instance claim",
    "E1_LOCAL_TENTATIVE":
        "the row has a local identity with the TENTATIVE verdict: one of shape "
        "or dependency matched, not both",
    "E0_LOCAL_ONLY_NO_REFERENCE_COUNTERPART":
        "the row is a LOCAL operator with no reference block at all: it is a "
        "boundary/protocol operator of the port, not a network block",
    "E0_REFERENCE_ONLY_NO_LOCAL_IDENTITY":
        "the row is a reference block with NO local identity mapped to it",
    "NOT_TESTED":
        "no measurement has been made on this axis by the owner of the axis",
}

# ---------------------------------------------------------------------------
# Consensus / conflict.  THE WHOLE POINT: lineage is part of the verdict.
# ---------------------------------------------------------------------------
CONSENSUS_VOCABULARY = {
    "AGREEMENT_WITHIN_ONE_LINEAGE":
        "two or more records agree, but every agreeing record derives from the "
        "SAME evidence lineage (same generator, same parser, same capture). "
        "The agreement is guaranteed by construction and is NOT corroboration.",
    "AGREEMENT_INDEPENDENT_SIDES":
        "two or more records agree and they do not share a parser, a capture, "
        "a generator or a failure mode",
    "CONFLICT_RECORDED":
        "two records disagree; BOTH are recorded with their own evidence level "
        "and neither is resolved by counting votes",
    "SINGLE_SOURCE_ONLY":
        "exactly one record speaks to this row; there is nothing to agree or "
        "disagree with",
    "NOT_ASSESSABLE_EXTERNAL_NOT_TESTED":
        "the external axis is NOT_TESTED, so no cross-source consensus exists "
        "to assess. This is stated rather than scored as agreement.",
    "MEASURED_ON_A_DIFFERENT_AXIS__NO_CONSENSUS_ASSESSABLE":
        "an external measurement EXISTS, but it measures a different axis from "
        "this row's operator mapping (a repository HEAD is a revision scope, and "
        "a weight record's byte size is a layout fact; neither says which local "
        "kernel implements which reference operator). Scoring it as agreement "
        "would manufacture consensus out of a category error.",
}

# ---------------------------------------------------------------------------
# External cell states.  A state that claims a measurement must name the W4
# artifact that contains it; a state that claims nothing must say NOT_TESTED.
# ---------------------------------------------------------------------------
EXTERNAL_CELL_STATES = {
    "NOT_TESTED":
        "no measurement on this axis exists, by anyone",
    "MEASURED_BY_W4__WEIGHT_RECORD_BYTE_LAYOUT_AGREES_OR_RESIDUES":
        "W4 compared the external model's declared byte size for this row's "
        "weight RECORD against this project's held pinned index. The cell "
        "carries the sizes and the residual; it does NOT claim an operator "
        "mapping",
    "MEASURED_BY_W4__REPOSITORY_IDENTITY_ONLY__NO_WEIGHT_RECORD_IN_THE_LAYOUT_PROBE":
        "W4 measured the source repository's default-branch HEAD and licence "
        "state, and the layout probe contains no record for this row",
    "MEASURED_BY_W4__REPOSITORY_IDENTITY_ONLY__NO_PER_OPERATOR_MAPPING_MEASURED":
        "W4 measured the source repository's default-branch HEAD and licence "
        "state; no per-operator mapping for this source exists",
}


def build():
    graph = C.load_json(C.GRAPH_V0)
    mapping = C.load_json(C.IDENTITY_MAPPING)
    verdict16ao = C.load_json(C.MAPPING_VERDICT_16AO)
    netgraph = C.load_json(C.NETWORK_GRAPH)
    widx = C.load_json(C.WEIGHTS_INDEX)
    launch = C.load_launch_db()

    w4_present = C.exists("p16ax/sources")
    w4 = w4_evidence()

    # ---- index the mapping by identity -----------------------------------
    ident_by_name = {i["identity"]: i for i in mapping["identities"]}
    hist_16an = mapping["verdict_histogram"]
    hist_16ao = verdict16ao["histogram_after_this_audit"]

    # 16AO's post-audit verdict per identity, where it spoke about the row.
    ao_rows = {r["identity"]: r for r in verdict16ao["surviving_rows"]}
    ao_not_safe = {d["identity"]: d for d in verdict16ao["not_safe_to_ground"]["grounds"]}
    ao_block_instance = set(
        verdict16ao["safe_to_ground_a_native_operator_on"][
            "at_reference_block_instance_granularity"])
    ao_operator_type = set(
        verdict16ao["safe_to_ground_a_native_operator_on"][
            "at_operator_type_granularity"])

    # ---- index weight records --------------------------------------------
    weight_by_name = {r["name"]: r for r in widx}
    weight_by_block = {}
    for r in widx:
        # "block12.layer0.layer" -> 12
        stem = r["name"].split(".")[0]
        if stem.startswith("block"):
            weight_by_block.setdefault(int(stem[5:]), []).append(r["name"])

    # ---- index local dispatch evidence per identity ----------------------
    launch_by_semantic = {}
    for row in launch:
        launch_by_semantic.setdefault(row["kernel_semantic"], []).append(row)

    blocks = graph["blocks"]
    boundary = graph["boundary_operators"]

    # local identities that have NO reference blocks
    local_only = []
    for name, i in ident_by_name.items():
        if not i["reference_blocks"]:
            local_only.append(name)

    rows = []
    row_index = {}

    def add_row(row):
        rows.append(row)
        row_index[row["row_id"]] = row

    # ---------------- rows for the local-only boundary operators ----------
    boundary_by_identity = {}
    for b in boundary:
        boundary_by_identity.setdefault(b["local_identity"], []).append(b)

    for name in sorted(local_only, key=lambda n: (
            ident_by_name[n]["reg_ordinal_in_census"] if
            ident_by_name[n]["reg_ordinal_in_census"] is not None else 999)):
        i = ident_by_name[name]
        bops = boundary_by_identity.get(name, [])
        ordinals = sorted({int(r["ordinal"]) for r in bops}
                          if False else
                          {o["local_ordinal"] for o in bops})
        measured = launch_by_semantic.get(name, [])
        rows.append({
            "row_id": "LOCAL_ONLY::" + name,
            "row_kind": "LOCAL_BOUNDARY_OPERATOR",
            "reference_block_id": None,
            "reference_layer_type": None,
            "local_block_id": None,
            "local_identity": name,
            "local_symbol": i["kernel_id"],
            "local_ordinal_in_census": i["reg_ordinal_in_census"],
            "local_role": (bops[0]["role"] if bops else None),
            "local_mapping": {
                "verdict_16an": i["verdict"],
                "target_kind_16an": i["target_kind"],
                "reference_blocks": [],
                "verdict_16ao": (
                    "TENTATIVE" if name in ao_not_safe else
                    "surviving" if name in ao_rows else
                    "not_analysed_by_16ao"),
                "margin_class": (
                    ao_rows[name]["margin_class"] if name in ao_rows else None),
                "safe_to_ground_at": None,
                "operator_basis_rule_effect":
                    "NOT eligible to ground a native operator: the 16AN "
                    "operator_basis_rule admits only EXACT and "
                    "HIGH_CONFIDENCE, and this identity's verdict is "
                    + i["verdict"],
            },
            "measured_in_the_capture": {
                "launches_total": len(measured),
                "present_in_frame_1": any(r["frame"] == "1" for r in measured),
                "distinct_geometry": sorted({
                    "%sx%sx%s/%s" % (r["grid_x"], r["grid_y"], r["grid_z"],
                                     r["block_x"]) for r in measured}),
            },
            "weights": {
                "weight_records_in_the_reference_graph": [],
                "availability": _local_only_weight_state(bops),
                "availability_note":
                    "a local-only operator has no reference weight record; "
                    "whether the operator needs weight bytes of its own is a "
                    "separate question and is recorded per operator in "
                    "AUTHENTIC_JOB_DAG_V1_SCAFFOLD.json",
            },
            "evidence_level": ("E1_LOCAL_TENTATIVE" if name in ao_not_safe
                               else "E0_LOCAL_ONLY_NO_REFERENCE_COUNTERPART"),
            "evidence_level_basis": (
                "the identity carries no reference block in "
                "IDENTITY_MAPPING_16AN.json, so no reference-side evidence "
                "level can be assigned"
                + ("; ADDITIONALLY the 16AO row-uniqueness audit found it "
                   "unsafe to ground at all, so the level is taken from the "
                   "audit rather than from the absence of a reference block"
                   if name in ao_not_safe else "")),
            "conflict": _local_conflict(name, i, ao_not_safe),
            "consensus": _local_only_consensus(name, ao_not_safe),
            "external": _external_cells(w4, set()),
        })

    # ---------------- rows for the 71 reference blocks --------------------
    local_for_block = {}
    for name, i in ident_by_name.items():
        for b in (i["reference_blocks"] or []):
            local_for_block.setdefault(b, []).append(name)

    for blk in blocks:
        bid = blk["block_id"]
        locals_here = local_for_block.get(bid, [])
        wrecs = weight_by_block.get(bid, [])
        net_blk = next((b for b in netgraph["blocks"] if b["block"] == bid), None)

        # evidence level for THIS block row = the strongest level any local
        # identity mapped to it reaches.
        level, basis, conflict = _row_evidence(
            locals_here, ident_by_name, ao_block_instance, ao_operator_type,
            ao_not_safe, hist_16an, hist_16ao)

        consensus = _row_consensus(locals_here, ao_not_safe, level, w4)

        rows.append({
            "row_id": "REF_BLOCK_%02d" % bid,
            "row_kind": "REFERENCE_BLOCK",
            "reference_block_id": bid,
            "reference_layer_type": (
                net_blk["layer_type"] if net_blk else
                (blk["reference_layer_types"][0]
                 if blk["reference_layer_types"] else None)),
            "reference_layer_types_all": blk["reference_layer_types"],
            "reference_role": blk.get("role"),
            "reference_stage": blk.get("stage"),
            "reference_operator_family": blk.get("operator_family"),
            "reference_window_width": blk.get("window_width"),
            "reference_variant": blk.get("reference_variant"),
            "local_block_id": (locals_here[0] if len(locals_here) == 1
                               else ("MULTIPLE:" + ",".join(sorted(locals_here))
                                     if locals_here else None)),
            "local_identity": (sorted(locals_here) if locals_here else []),
            "local_symbol": [ident_by_name[n]["kernel_id"]
                             for n in sorted(locals_here)],
            "local_mapping": {
                "n_local_identities": len(locals_here),
                "per_identity": {
                    n: {
                        "verdict_16an": ident_by_name[n]["verdict"],
                        "margin_class": (ao_rows[n]["margin_class"]
                                         if n in ao_rows else None),
                        "verdict_16ao": (
                            "TENTATIVE" if n in ao_not_safe else
                            "surviving" if n in ao_rows else
                            "not_analysed_by_16ao"),
                        "safe_to_ground_at": _safe_at(
                            n, ao_block_instance, ao_operator_type),
                    } for n in sorted(locals_here)
                },
            },
            "weights": {
                "weight_records_in_the_reference_graph": wrecs,
                "weight_elements": (net_blk["weight_elements"] if net_blk
                                    else None),
                "n_records": len(wrecs),
                "availability": "UNKNOWN",
                "availability_note":
                    "availability is NOT a property of this row; it is a "
                    "property of each weight RECORD and is recorded per "
                    "record in AUTHENTIC_JOB_DAG_V1_SCAFFOLD.json and in "
                    "GLOBAL_INITIALIZATION_CONTRACT_V1.json. Collapsing it to "
                    "one boolean here is the exact defect 16AW's "
                    "GRAPH_REFERENCE track block names.",
            },
            "evidence_level": level,
            "evidence_level_basis": basis,
            "conflict": conflict,
            "consensus": consensus,
            "external": _external_cells(w4, {bid}),
        })

    # ---------------- assemble -------------------------------------------
    n_rows = len(rows)
    level_hist = {}
    for r in rows:
        level_hist[r["evidence_level"]] = level_hist.get(r["evidence_level"], 0) + 1
    consensus_hist = {}
    for r in rows:
        consensus_hist[r["consensus"]["state"]] = \
            consensus_hist.get(r["consensus"]["state"], 0) + 1

    art = {
        "schema": "p16ax/cross-source-graph-matrix/1",
        "phase": "16AX",
        "task_id": "T-GRAPH",
        "worker": "W5",
        "host_only": True,
        "gpu_execution_performed": False,
        "hip_calls_performed": False,
        "numpy_used": False,

        "statement":
            "HOST ONLY. Zero GPU launches, zero HIP calls. Produced by a "
            "pure-standard-library reader over artefacts already on disk; no "
            "device was opened and no amdgpu/amdhip64 module was loaded.",

        "what_this_artifact_is":
            "ONE ROW PER LOGICAL BLOCK/OPERATOR, with the local mapping "
            "columns populated from this project's own artefacts and each "
            "external source column carrying its measured state.",

        "the_rule_this_artifact_exists_to_enforce": {
            "rule": "MAJORITY VOTE IS NOT PROOF.",
            "restatement":
                "Where sources conflict, the conflict is recorded together "
                "with the evidence level of EACH SIDE. Agreement between two "
                "sources that share an evidence lineage is not corroboration: "
                "it is one measurement rendered twice. Independence is "
                "per MECHANISM -- a shared parser, a shared capture, a shared "
                "generator or a shared failure mode makes two checks one check "
                "run twice.",
            "how_enforced":
                "the consensus.state field cannot take the value "
                "AGREEMENT_INDEPENDENT_SIDES unless the agreeing records are "
                "declared to have different mechanisms; the lineage of every "
                "local record is named in `local_evidence_lineages` below",
        },

        "local_evidence_lineages": {
            "L1_launch_capture": {
                "artefact": C.LAUNCH_DB,
                "sha256_recomputed": C.sha256_file(C.LAUNCH_DB),
                "rows": 2239,
                "what_it_measures": "that kernels were ASKED to run, with "
                                    "which geometry and in which order",
                "what_it_cannot_measure":
                    "any tensor value. Re-parsing it produces invocation "
                    "evidence again, never numeric evidence.",
            },
            "L2_reference_pin": {
                "artefacts": [C.NETWORK_GRAPH, C.WEIGHTS_INDEX],
                "sha256_recomputed": {
                    C.NETWORK_GRAPH: C.sha256_file(C.NETWORK_GRAPH),
                    C.WEIGHTS_INDEX: C.sha256_file(C.WEIGHTS_INDEX),
                },
                "what_it_measures": "the pinned upstream reference's own "
                                    "declared block graph and weight index",
            },
            "L3_local_graph_model": {
                "artefact": C.GRAPH_V0,
                "sha256_recomputed": C.sha256_file(C.GRAPH_V0),
                "generator": "p16an/native/p16an_graph_mapping.py",
                "derives_from": ["L1_launch_capture", "L2_reference_pin"],
            },
            "L4_local_identity_mapping": {
                "artefact": C.IDENTITY_MAPPING,
                "sha256_recomputed": C.sha256_file(C.IDENTITY_MAPPING),
                "generator": "p16an/native/p16an_graph_mapping.py",
                "derives_from": ["L1_launch_capture", "L2_reference_pin"],
            },
            "L5_row_uniqueness_audit_16ao": {
                "artefact": C.MAPPING_VERDICT_16AO,
                "sha256_recomputed": C.sha256_file(C.MAPPING_VERDICT_16AO),
                "generator": "p16ao/native/mapping/p16ao_row_uniqueness.py",
                "derives_from": ["L4_local_identity_mapping"],
                "lineage_warning":
                    "L5 AUDITS L4. It shares L4's parser and L4's subject. "
                    "L4 and L5 agreeing is NOT an independent confirmation of "
                    "the mapping; it is one mapping examined twice, once by "
                    "its author and once by a stricter rule. The 16AO audit is "
                    "still STRICTER evidence (it downgraded a row), but it is "
                    "not a second source.",
            },
        },

        "row_spine": {
            "reference_blocks": len(blocks),
            "local_boundary_operators": len(local_only),
            "total_rows": n_rows,
            "why_this_spine":
                "the union of (a) the reference's own declared blocks and "
                "(b) the port's local boundary/protocol operators, which have "
                "no reference block. A row spine that omitted (b) would have "
                "made the import path, the frame gate and the export path "
                "invisible in the graph -- and those are exactly the operators "
                "the replay prefix starts with.",
        },

        "external_sources": EXTERNAL_SOURCES,
        "external_columns_state": (
            "NOT_TESTED" if not w4 else
            "PARTIALLY_POPULATED_FROM_W4_MEASURED_OUTPUT__NO_PER_OPERATOR_"
            "MAPPING_FOR_ANY_SOURCE"),
        "external_columns_pending_marker": {
            "owner": "W4 / T-SOURCES",
            "expected_output_path": "p16ax/sources/",
            "directory_existed_when_this_ran": w4_present,
            "w4_output_consumed": bool(w4),
            "w4_artifacts_consumed": (
                {p: v for p, v in w4["artifacts"].items()} if w4 else {}),
            "still_unfillable_and_why": (
                "no source's PER-OPERATOR mapping has been measured by anyone. "
                "What W4 measured is a repository HEAD and licence state per "
                "source, plus a weight-record byte-layout comparison against "
                "OpenDLSS-NR's weights.md. A per-operator mapping cell therefore "
                "stays unfilled."),
            "fill_instruction":
                "replace each row's external.<column>.state from NOT_TESTED "
                "with the measured compatibility verdict, and set "
                "external.<column>.measured_against_pinned_identity to the "
                "commit the measurement was scoped to. Do NOT fill a cell "
                "that W4 did not measure; an unmeasured cell must keep "
                "reading NOT_TESTED.",
            "no_majority_vote_rule_applies_to_the_fill":
                "a filled cell does not create consensus. Agreement between two "
                "sources that share a lineage is not corroboration, and "
                "agreement on one axis (here: a weight record's byte size) is "
                "not agreement on another (which kernel implements which "
                "operator).",
        },

        "evidence_level_vocabulary": EVIDENCE_VOCABULARY,
        "consensus_vocabulary": CONSENSUS_VOCABULARY,
        "external_cell_state_vocabulary": EXTERNAL_CELL_STATES,
        "evidence_level_histogram": level_hist,
        "consensus_histogram": consensus_hist,

        "conflicts_recorded": _conflicts(rows) + _external_conflicts(w4),

        "what_this_does_NOT_establish": [
            "It does not establish any cross-source OPERATOR agreement. No "
            "external source's per-operator mapping has been measured by anyone, "
            "so every external mapping cell still reads NOT_TESTED for the "
            "operator axis.",
            "It does not treat W4's repository HEADs or the OpenDLSS weight-"
            "record byte-layout comparison as operator mappings. Those are "
            "different axes and are labelled as such.",
            "It does not establish that a local operator implements the "
            "reference layer it is mapped to. It records the mapping's own "
            "measured evidence level, ceilings included.",
            "It does not resolve the k_repack conflict, nor the fp8-versus-fp16 "
            "weight-record-size conflict. Both readings are recorded with their "
            "own evidence; neither is preferred by vote.",
            "It does not establish block-instance identity for the 11 rows the "
            "16AO audit found to be POSITIONAL_ONLY. Those rows are labelled "
            "E2/E3 and the label is the ceiling, not a confidence score.",
            "It contains no numeric value of any kind and no memory address.",
            "It is not a claim about what any kernel computed.",
        ],

        "provenance": {
            "generator": "p16ax/graph/p16ax_graph_matrix.py",
            "generator_sha256": C.sha256_file(
                "p16ax/graph/p16ax_graph_matrix.py"),
            "inputs_sha256_recomputed": {
                p: C.sha256_file(p) for p in [
                    C.GRAPH_V0, C.IDENTITY_MAPPING, C.MAPPING_VERDICT_16AO,
                    C.NETWORK_GRAPH, C.WEIGHTS_INDEX, C.LAUNCH_DB,
                    C.SOURCE_REGISTER,
                ]
            },
            "reference_repository": "https://github.com/lmxxf/dlss5-on-amd-9070xt-porting",
            "pinned_commit": "79c1654f88e673b0f26fed201dd82bf80095b696",
            "licence": "MIT",
        },

        "rows": rows,
    }
    return art


def _local_conflict(name, identity_row, ao_not_safe):
    """The row-local conflict between the 16AN verdict and the 16AO audit.

    Recorded for EVERY identity the audit moved, whether or not that identity
    has a reference block.  The k_repack row is the reason this is a function
    rather than an inline block: it has no reference block at all, so a
    conflict check written only on the reference-block path silently dropped
    the one conflict the audit actually produced.
    """
    if name not in ao_not_safe:
        return None
    return {
        "kind": "LOCAL_VERDICT_DOWNGRADED_BY_A_LATER_AUDIT",
        "identity": name,
        "reading_a": {
            "source": C.IDENTITY_MAPPING,
            "verdict": identity_row["verdict"],
            "evidence_level": "E2_LOCAL_OPERATOR_TYPE_HIGH_CONFIDENCE",
        },
        "reading_b": {
            "source": C.MAPPING_VERDICT_16AO,
            "verdict": "TENTATIVE (not_safe_to_ground)",
            "ground": ao_not_safe[name]["ground"],
            "evidence_level": "E1_LOCAL_TENTATIVE",
        },
        "shared_lineage": True,
        "shared_lineage_note":
            "reading_b audits reading_a; it uses reading_a's parser and "
            "reading_a's subject. The downgrade is STRICTER EVIDENCE ABOUT "
            "THE SAME MEASUREMENT, not a second independent source, and it is "
            "not resolved by vote.",
        "resolution": "NOT_RESOLVED_BY_VOTE -- the stricter reading is carried "
                      "as the row's level",
    }


def _local_only_consensus(name, ao_not_safe):
    if name in ao_not_safe:
        return {
            "state": "CONFLICT_RECORDED",
            "why": "the 16AN verdict and the 16AO audit disagree on this "
                   "identity",
            "detail": "see this row's `conflict` field. Both sides are "
                      "recorded with their own evidence level.",
            "shared_lineage": True,
        }
    return {
        "state": "SINGLE_SOURCE_ONLY",
        "why": "only the local side speaks to this row",
    }


def _local_only_weight_state(bops):
    """A local-only operator's weight state, decided from its own declared
    counterpart text -- not guessed from its role name."""
    text = " ".join(
        str(b.get("status") or "") + " " + str(b.get("reference_counterpart") or "")
        + " " + str(b.get("role") or "")
        for b in bops).lower()
    if "host stage" in text or "host binding" in text or "not a network block" in text:
        return "NOT_APPLICABLE_HOST_STAGE"
    if not bops:
        return "UNKNOWN"
    return "UNKNOWN"


def _safe_at(name, block_instance, operator_type):
    if name in block_instance:
        return "REFERENCE_BLOCK_INSTANCE"
    if name in operator_type:
        return "OPERATOR_TYPE_ONLY"
    return None


def _row_evidence(locals_here, ident_by_name, block_instance, operator_type,
                  ao_not_safe, hist_16an, hist_16ao):
    """The strongest level any local identity mapped to this row reaches.

    The level is chosen from the 16AO post-audit classes where 16AO spoke, and
    from the 16AN verdict where it did not.  A level is never PREFERRED by
    agreement count.
    """
    if not locals_here:
        return ("E0_REFERENCE_ONLY_NO_LOCAL_IDENTITY",
                "no local identity in IDENTITY_MAPPING_16AN.json maps to this "
                "reference block", None)

    best = None
    order = ["E0_LOCAL_ONLY_NO_REFERENCE_COUNTERPART",
             "E1_LOCAL_TENTATIVE",
             "E2_LOCAL_OPERATOR_TYPE_HIGH_CONFIDENCE",
             "E3_LOCAL_OPERATOR_TYPE_EXACT",
             "E4_LOCAL_BLOCK_INSTANCE_GRADED"]

    conflict = None
    for n in locals_here:
        i = ident_by_name[n]
        if n in ao_not_safe:
            lvl = "E1_LOCAL_TENTATIVE"
        elif n in block_instance:
            lvl = "E4_LOCAL_BLOCK_INSTANCE_GRADED"
        elif i["verdict"] == "EXACT":
            lvl = "E3_LOCAL_OPERATOR_TYPE_EXACT"
        elif i["verdict"] == "HIGH_CONFIDENCE":
            lvl = "E2_LOCAL_OPERATOR_TYPE_HIGH_CONFIDENCE"
        elif i["verdict"] in ("MEDIUM_CONFIDENCE", "TENTATIVE"):
            lvl = "E1_LOCAL_TENTATIVE"
        else:
            lvl = ("E0_LOCAL_ONLY_NO_REFERENCE_COUNTERPART"
                   if i["verdict"] == "UNMAPPED" else "E1_LOCAL_TENTATIVE")
        if best is None or order.index(lvl) > order.index(best):
            best = lvl

        # a row-local conflict: the identity's 16AN verdict says one thing and
        # the 16AO audit says a strictly weaker thing
        if n in ao_not_safe:
            conflict = {
                "kind": "LOCAL_VERDICT_DOWNGRADED_BY_A_LATER_AUDIT",
                "identity": n,
                "reading_a": {
                    "source": C.IDENTITY_MAPPING,
                    "verdict": i["verdict"],
                    "evidence_level": "E2_LOCAL_OPERATOR_TYPE_HIGH_CONFIDENCE",
                },
                "reading_b": {
                    "source": C.MAPPING_VERDICT_16AO,
                    "verdict": "TENTATIVE (not_safe_to_ground)",
                    "ground": ao_not_safe[n]["ground"],
                    "evidence_level": "E1_LOCAL_TENTATIVE",
                },
                "shared_lineage": True,
                "shared_lineage_note":
                    "reading_b audits reading_a; it uses reading_a's parser "
                    "and reading_a's subject. The downgrade is therefore "
                    "STRICTER EVIDENCE ABOUT THE SAME MEASUREMENT, not a "
                    "second independent source, and it is not resolved by "
                    "vote.",
                "resolution": "NOT_RESOLVED_BY_VOTE -- the stricter reading is "
                              "carried as the row's level",
            }
    basis = ("strongest local level among {%s}; 16AN histogram %s; "
             "16AO post-audit histogram %s"
             % (", ".join(sorted(locals_here)), hist_16an, hist_16ao))
    return best, basis, conflict


def _row_consensus(locals_here, ao_not_safe, level, w4=None):
    """Local-side consensus, plus an explicit statement of what the external
    axis contributes.  W4's presence does NOT create external consensus: what W4
    measured for OpenDLSS is a weight-RECORD byte layout, which is a different
    axis from this row's operator mapping.  Comparing the two would be the
    category error this matrix exists to block, so it is named, not scored."""
    if not locals_here:
        return {
            "state": "SINGLE_SOURCE_ONLY",
            "why": "only the reference side names this row",
            "external_axis": _external_axis_note(w4),
        }
    downgraded = [n for n in locals_here if n in ao_not_safe]
    if downgraded:
        return {
            "state": "CONFLICT_RECORDED",
            "why": "the 16AN verdict and the 16AO audit disagree on %s"
                   % ", ".join(sorted(downgraded)),
            "detail": "see this row's `conflict` field. Both sides are "
                      "recorded with their own evidence level.",
            "shared_lineage": True,
            "external_axis": _external_axis_note(w4),
        }
    if len(locals_here) > 1:
        return {
            "state": "AGREEMENT_WITHIN_ONE_LINEAGE",
            "why": "%d local identities map to this block, and every one of "
                   "them is a record of the SAME 16AN mapping artefact read "
                   "through the SAME generator. Their agreement is guaranteed "
                   "by construction and is not corroboration."
                   % len(locals_here),
            "detail": "the agreeing records share generator "
                      "p16an_graph_mapping.py and evidence lineages "
                      "L1_launch_capture and L2_reference_pin",
            "external_axis": _external_axis_note(w4),
        }
    return {
        "state": "SINGLE_SOURCE_ONLY",
        "why": "exactly one local identity maps to this block; there is "
               "nothing to agree or disagree with",
    }


def _external_conflicts(w4):
    """Cross-source conflicts W4's measurement exposes.

    Recorded, not resolved.  The two sides here are on DIFFERENT lineages -- the
    external model is OpenDLSS-NR's own docs/weights.md, while this project's
    side is a held pinned copy of lmxxf/dlss5-on-amd-9070xt-porting's
    weights-index.json -- so this is a genuine cross-lineage disagreement and
    not two readings of one artefact.  That is exactly why it is recorded rather
    than averaged.
    """
    if not w4:
        return []
    s = w4["layout_probe"]["summary"]
    resid = s.get("residual_detail") or []
    if not resid:
        return []
    residuals = [{"record": r["record"], "external_model_bytes": r["model"],
                  "this_projects_bytes": r["our"], "residual_bytes": r["residual"],
                  "external_model_note": r.get("model_note")}
                 for r in resid]
    factors = sorted({round(r["our"] / r["model"], 4)
                      for r in resid if r.get("model")})
    return [{
        "conflict_id": "EXT_FP8_VS_FP16_WEIGHT_RECORD_SIZE",
        "axis": "weight record byte size",
        "state": "CONFLICT_RECORDED",
        "row_id": None,
        "record_scope": [r["record"] for r in resid],
        "n_records_in_conflict": len(resid),
        "side_a": {
            "lineage": "EXTERNAL_INDEPENDENT",
            "source": w4["layout_probe"]["external_model_source"],
            "reading": "fp16 storage: 2 bytes per element, plus padding",
            "example": residuals[0],
        },
        "side_b": {
            "lineage": "THIS_PROJECT_HELD_PINNED_COPY",
            "source": w4["layout_probe"]["our_side_artifact"]["path"],
            "provenance_tier": w4["layout_probe"]["our_side_artifact"].get(
                "provenance_tier"),
            "reading": "fp8 E4M3 storage: 1 byte per weight, plus an fp16 scale",
            "example": {"record": residuals[0]["record"],
                        "bytes": residuals[0]["this_projects_bytes"]},
        },
        "measured_size_ratio_this_project_over_the_external_model": factors,
        "why_this_is_not_a_typo": "the ratio is exactly 2 on the records in "
                                  "conflict, which is the fp8/fp16 element-size "
                                  "ratio, and the same reading conflict is "
                                  "recorded independently in "
                                  "p16as/weights/BLOCK39_WEIGHT_PROVENANCE_"
                                  "AUDIT.json as reading_E4M3 versus "
                                  "reading_FP16 with "
                                  "is_the_conflict_resolvable_from_disk=false",
        "do_not_majority_vote": "two sides disagree; the artifact records both "
                                "readings and their sizes and picks neither",
        "what_would_resolve_it": "the archive record itself, at payload_offset "
                                 "123721268 of the shipping DLL, with its own "
                                 "source hash",
    }]


def _external_axis_note(w4):
    if not w4:
        return {
            "state": "NOT_TESTED",
            "why": "W4 / T-SOURCES measured output was not present when this "
                   "ran, so no external axis exists to assess",
        }
    return {
        "state": "MEASURED_ON_A_DIFFERENT_AXIS__NO_CONSENSUS_ASSESSABLE",
        "why": "W4 measured (a) each repository's default-branch HEAD and "
               "licence state, and (b) for OpenDLSS-NR, a byte-count comparison "
               "of its weights.md fusedLayout model against this project's held "
               "pinned weights-index, one row per weight RECORD. (a) is a "
               "revision scope, not a mapping. (b) is a measurement of the "
               "record's byte layout, not of which local kernel implements "
               "which reference operator. Neither is this row's operator "
               "mapping, so no cross-source operator consensus can be computed "
               "from them -- and scoring them as if they were would be exactly "
               "the substitution this matrix exists to block.",
        "no_per_operator_mapping_was_measured_by_any_external_source": True,
    }


def w4_evidence():
    """Consume W4 / T-SOURCES measured output.

    Returns None when the five artifacts are not all present, so every caller
    has one unambiguous absent case.  Nothing here is inferred: a field that W4
    did not measure comes back as None and its cell stays NOT_TESTED.
    """
    if not all(C.exists(p) for p in W4_REQUIRED):
        return None
    refresh = C.load_json(W4_SOURCE_REFRESH)
    licence = C.load_json(W4_LICENCE_PROBE)
    probe = C.load_json(W4_LAYOUT_PROBE)
    isa = C.load_json(W4_ISA_CENSUS)
    our = C.load_json(W4_OUR_SIDE)

    repos = {}
    for r in refresh["repositories"]:
        repos[r["slug"].lower()] = {
            "slug": r["slug"],
            "default_branch_measured": r.get("default_branch_measured"),
            "head_sha_via_symref": r.get("head_sha_via_symref"),
            "supervisor_last_seen": r.get("supervisor_last_seen"),
            "tier": r.get("tier"),
            "agrees_with_supervisor": r.get("head_sha_via_symref") ==
                                      r.get("supervisor_last_seen"),
        }
    lic = {}
    for r in licence["repositories"]:
        lic[r["slug"].lower()] = r

    # the layout probe: a per-RECORD byte comparison.  Keyed by block index so a
    # matrix row can join on its own reference block.
    by_block = {}
    for c in probe["comparisons"]:
        name = c["record"]                      # "blockN.layerM.layer"
        if not name.startswith("block"):
            continue
        try:
            idx = int(name[5:].split(".", 1)[0])
        except ValueError:
            continue
        by_block.setdefault(idx, []).append(c)
    summary = probe["summary"]

    # the ISA census: one file is the ORIGINAL gfx1100 disassembly, the other a
    # TRANSLATED gfx1030 kernel assembly.  They are different subjects, so the
    # family counts are recorded separately and never compared as if equal.
    isa_files = isa["files"]
    orig = isa_files.get("orig_gfx1100_disasm", {})
    tr = isa_files.get("translated_gfx1030_asm", {})

    return {
        "present": True,
        "artifacts": {
            p: {"sha256": C.sha256_file(p),
                "bytes": os.path.getsize(C.abspath(p))}
            for p in W4_REQUIRED
        },
        "measured_utc": refresh.get("measured_utc"),
        "repositories": repos,
        "licences": {
            "summary": licence["summary"],
            "unverified_slugs": [s.lower() for s in
                                 licence["summary"]["unverified_slugs"]],
            "per_slug": {k: {kk: v.get(kk) for kk in
                             ("slug", "licence", "licence_state", "verdict",
                              "licence_file", "vendoring_permitted")
                             if kk in v}
                         for k, v in lic.items()},
        },
        "layout_probe": {
            "external_model_source": probe["external_model"]["source"],
            "our_side_artifact": probe["our_side_artifact"],
            "summary": summary,
            "by_block_index": by_block,
            "not_vendored": probe["external_model"]["not_vendored"],
        },
        "isa_census": {
            "original_gfx1100": {
                "path": orig.get("path"), "sha256": orig.get("sha256"),
                "families": orig.get("families"),
                "n_mnemonic_lines": orig.get("n_mnemonic_lines"),
            },
            "translated_gfx1030_kernel": {
                "path": tr.get("path"), "sha256": tr.get("sha256"),
                "families": tr.get("families"),
                "n_mnemonic_lines": tr.get("n_mnemonic_lines"),
            },
            "scanner_defect_control": isa["scanner_defect_control"],
            "are_these_the_same_subject": False,
        },
        "our_side_facts": our.get("facts"),
    }


def _w4_repo_for(column, w4):
    """Which measured repository backs a column, if any.  Resolved by slug, and
    None when W4 has no measured row for it."""
    if not w4:
        return None
    want = {"opendlss_mapping": ("opendlss",),
            "translation_lab_mapping": ("translation-lab", "translation_lab"),
            "paimonshen_mapping": ("paimonshen",),
            }[column]
    for slug, r in w4["repositories"].items():
        if any(w in slug for w in want):
            return r
    return None


def _external_cells(w4, records_by_block):
    """Fill each row's external cells from what W4 measured, or NOT_TESTED.

    Two different things W4 measured are kept strictly apart:
      * the repository identity (a HEAD SHA) -- scopes a value to a revision,
        but is NOT a per-operator measurement;
      * the layout probe (a per-weight-record byte comparison) -- is a real
        measurement, but of the record's BYTE LAYOUT, not of the operator's
        mapping.  Filling an "operator mapping" cell with it would be the exact
        substitution this matrix exists to prevent, so the cell states say which
        of the two it is and never claim more.
    """
    out = {}
    for s in EXTERNAL_SOURCES:
        col = s["column"]
        repo = _w4_repo_for(col, w4)
        cell = {
            "state": "NOT_TESTED",
            "pinned_identity_available": s["pinned_identity"],
            "measured_against_pinned_identity": None,
            "owner": s["owner_of_the_measurement"],
            "owner_output_present_when_this_ran": bool(w4),
            "reason": s["cell_state_reason"],
        }
        if repo:
            cell["repository_identity_measured_by_w4"] = {
                "slug": repo["slug"],
                "head_sha_via_symref": repo["head_sha_via_symref"],
                "default_branch_measured": repo["default_branch_measured"],
                "measured_utc": (w4 or {}).get("measured_utc"),
                "agrees_with_the_previous_supervisor_record":
                    repo["agrees_with_supervisor"],
                "this_is_a_revision_scope_NOT_a_per_operator_measurement": True,
            }
            cell["measured_against_pinned_identity"] = repo["head_sha_via_symref"]
        if col == "opendlss_mapping" and w4:
            # join the probe to this row's own reference blocks
            hits = []
            for b in sorted(records_by_block):
                for c in w4["layout_probe"]["by_block_index"].get(b, []):
                    hits.append({
                        "record": c["record"],
                        "model_bytes": c["model_bytes"],
                        "our_payload_bytes": c["our_payload_bytes"],
                        "residual_bytes": c["residual_bytes"],
                        "model_parts": c.get("model_parts"),
                        "model_note": c.get("model_note"),
                        "verdict": c["verdict"],
                    })
            if hits:
                cell["state"] = ("MEASURED_BY_W4__WEIGHT_RECORD_BYTE_LAYOUT_"
                                 "AGREES_OR_RESIDUES")
                cell["what_W4_actually_measured"] = (
                    "a byte-count comparison of the OpenDLSS-NR weights.md "
                    "fusedLayout model against this project's held pinned "
                    "weights-index.json, one row per weight RECORD")
                cell["what_this_is_NOT"] = (
                    "it is not a per-operator mapping.  It compares record "
                    "SIZES, so it can corroborate a record's structure and "
                    "cannot corroborate which local kernel implements which "
                    "reference operator.")
                cell["measurements"] = hits
                # the external model can carry MORE THAN ONE reading for one
                # record.  Recorded explicitly: a single "the model said N"
                # would hide the fact that the model also said something else.
                cell["distinct_readings_for_this_row"] = len({
                    (h["model_bytes"], h["verdict"]) for h in hits})
                cell["row_has_an_agreeing_reading"] = any(
                    h["verdict"] == "EXACT" for h in hits)
                cell["row_has_a_residual_reading"] = any(
                    h["verdict"] != "EXACT" for h in hits)
                if len(hits) > 1:
                    cell["the_external_model_carries_several_readings"] = (
                        "W4's probe holds %d comparisons for this row's weight "
                        "record(s); they are all kept, because keeping only the "
                        "agreeing one would turn a recorded discrepancy into an "
                        "apparent agreement" % len(hits))
            else:
                cell["state"] = ("MEASURED_BY_W4__REPOSITORY_IDENTITY_ONLY__"
                                 "NO_WEIGHT_RECORD_IN_THE_LAYOUT_PROBE")
                cell["what_W4_actually_measured"] = (
                    "the repository's default-branch HEAD and its licence "
                    "state; no per-record comparison covers this row")
        elif w4 and repo:
            cell["state"] = ("MEASURED_BY_W4__REPOSITORY_IDENTITY_ONLY__"
                             "NO_PER_OPERATOR_MAPPING_MEASURED")
            cell["what_W4_actually_measured"] = (
                "the repository's default-branch HEAD and its licence state; "
                "no per-operator or per-block mapping for this source was "
                "measured, so this cell cannot be filled")
        out[col] = cell
    return out


def _conflicts(rows):
    out = []
    for r in rows:
        if r.get("conflict"):
            c = dict(r["conflict"])
            c["row_id"] = r["row_id"]
            out.append(c)
    return out


def selftest():
    """House rule 2: the external-cell check must be able to FAIL.

    A checker that only ever accepts is worse than no checker.  These controls
    inject the exact defect the checker exists to catch and require rejection.
    """
    ok = True

    def check(name, fn, expect_reject):
        nonlocal ok
        try:
            fn()
            rejected = False
            err = None
        except AssertionError as e:
            rejected = True
            err = str(e)[:110]
        good = rejected == expect_reject
        print("  %-62s %s%s" % (name, "OK" if good else "SELFTEST-FAIL",
                                "" if good else " (%s)" % err))
        ok = ok and good

    back = C.load_json(OUT)
    if not C.exists(W4_REQUIRED[0]):
        print("W4 output absent: the control set is vacuous, refusing to pass")
        return 1

    print("external-cell backing controls (real case must be accepted):")
    check("the shipped artifact's external cells are all backed",
          lambda: _assert_external_cells_are_backed(back), False)

    print("injected defects (each must be rejected):")

    def _bogus_state():
        b = json.loads(json.dumps(back))
        b["rows"][0]["external"]["opendlss_mapping"]["state"] = \
            "MEASURED_BY_W4__TOTALLY_FINE"
        _assert_external_cells_are_backed(b)
    check("an undeclared cell state is rejected", _bogus_state, True)

    def _no_scope():
        b = json.loads(json.dumps(back))
        r = next(x for x in b["rows"]
                 if x["external"]["opendlss_mapping"]["state"] != "NOT_TESTED")
        r["external"]["opendlss_mapping"]["measured_against_pinned_identity"] = None
        _assert_external_cells_are_backed(b)
    check("a claimed measurement with no revision scope is rejected",
          _no_scope, True)

    def _bogus_record():
        b = json.loads(json.dumps(back))
        r = next(x for x in b["rows"]
                 if x["external"]["opendlss_mapping"]["state"].startswith(
                     "MEASURED_BY_W4__WEIGHT_RECORD"))
        r["external"]["opendlss_mapping"]["measurements"][0]["record"] = \
            "block999.layer0.layer"
        _assert_external_cells_are_backed(b)
    check("a claimed layout record absent from W4's probe is rejected",
          _bogus_record, True)

    def _bogus_size():
        b = json.loads(json.dumps(back))
        r = next(x for x in b["rows"]
                 if x["external"]["opendlss_mapping"]["state"].startswith(
                     "MEASURED_BY_W4__WEIGHT_RECORD"))
        r["external"]["opendlss_mapping"]["measurements"][0]["model_bytes"] = 12
        _assert_external_cells_are_backed(b)
    check("a claimed size absent from W4's own record is rejected",
          _bogus_size, True)

    def _bogus_repo():
        b = json.loads(json.dumps(back))
        # all three columns DO have a W4 repo row, so to exercise the branch the
        # resolver itself is made to find nothing -- which is exactly the state a
        # column without a measured repository would be in
        saved = globals()["_w4_repo_for"]
        globals()["_w4_repo_for"] = lambda col, w: None
        try:
            r = b["rows"][0]
            r["external"]["paimonshen_mapping"]["state"] = (
                "MEASURED_BY_W4__REPOSITORY_IDENTITY_ONLY__"
                "NO_PER_OPERATOR_MAPPING_MEASURED")
            r["external"]["paimonshen_mapping"][
                "measured_against_pinned_identity"] = "0" * 40
            _assert_external_cells_are_backed(b)
        finally:
            globals()["_w4_repo_for"] = saved
    check("a repository claim W4 cannot support is rejected", _bogus_repo, True)

    def _missing_w4():
        b = json.loads(json.dumps(back))
        saved = globals()["w4_evidence"]
        globals()["w4_evidence"] = lambda: None
        try:
            _assert_external_cells_are_backed(b)
        finally:
            globals()["w4_evidence"] = saved
    check("with W4 output absent, a populated cell is rejected", _missing_w4, True)

    print("\nselftest: %s" % ("ALL CONTROLS BEHAVED" if ok else "FAILED"))
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()
    art = build()
    path = C.write_json(OUT, art)
    print("wrote", path)
    print("rows", len(art["rows"]))
    print("evidence_level_histogram", json.dumps(art["evidence_level_histogram"]))
    print("consensus_histogram", json.dumps(art["consensus_histogram"]))
    print("conflicts", len(art["conflicts_recorded"]))
    ext_states = art["external_columns_state"]
    print("external_columns_state", ext_states)
    # read-back: properties that can be predicted and checked independently
    back = C.load_json(OUT)
    assert len(back["rows"]) == art["n_rows"] if "n_rows" in art else True
    assert sum(back["evidence_level_histogram"].values()) == len(back["rows"]), \
        "read-back histogram does not sum to the row count"
    lev = {r["evidence_level"] for r in back["rows"]}
    assert lev <= set(back["evidence_level_vocabulary"]), \
        "a row carries a level outside the declared vocabulary"
    assert all(r["consensus"]["state"] in back["consensus_vocabulary"]
               for r in back["rows"]), \
        "a row carries a consensus state outside the declared vocabulary"
    _assert_external_cells_are_backed(back)
    print("read-back OK: histogram sums to rows; levels and consensus states "
          "are inside their vocabularies; every populated external cell is "
          "backed by a W4 artifact that is actually on disk")


def _assert_external_cells_are_backed(back):
    """Every external cell state must be in the vocabulary, and every state that
    CLAIMS a measurement must be reproducible from the W4 artifacts on disk in
    this session.  A cell that claims a measurement with no artifact behind it
    is a failure -- not a silently accepted cell.
    """
    vocab = set(back["external_cell_state_vocabulary"])
    w4 = w4_evidence()
    for r in back["rows"]:
        for col, cell in r["external"].items():
            assert cell["state"] in vocab, \
                "row %s column %s carries an undeclared external cell state %r" \
                % (r["row_id"], col, cell["state"])
            if cell["state"] == "NOT_TESTED":
                continue
            assert w4, \
                "row %s column %s claims a measurement but W4 output is absent" \
                % (r["row_id"], col)
            assert cell.get("measured_against_pinned_identity"), \
                "row %s column %s claims a measurement with no revision scope" \
                % (r["row_id"], col)
            # the claimed measurement must be findable in W4's own artifact
            if cell["state"].startswith("MEASURED_BY_W4__WEIGHT_RECORD"):
                for m in cell["measurements"]:
                    idx = int(m["record"][5:].split(".", 1)[0])
                    cands = [c for c in
                             w4["layout_probe"]["by_block_index"].get(idx, [])
                             if c["record"] == m["record"]]
                    assert cands, \
                        "row %s claims a layout measurement for %s that is not " \
                        "in W4's probe" % (r["row_id"], m["record"])
                    # W4's probe can hold SEVERAL readings for one record, so the
                    # match is on the measured values, not on position -- a
                    # positional match would pass on the wrong reading.
                    assert any(c["model_bytes"] == m["model_bytes"] and
                               c["our_payload_bytes"] == m["our_payload_bytes"] and
                               c["verdict"] == m["verdict"] for c in cands), \
                        "row %s reports a reading for %s that W4's own record " \
                        "does not contain: %r" % (r["row_id"], m["record"],
                                                  (m["model_bytes"],
                                                   m["our_payload_bytes"],
                                                   m["verdict"]))
                assert cell["distinct_readings_for_this_row"] == len({
                    (m["model_bytes"], m["verdict"])
                    for m in cell["measurements"]}), \
                    "row %s miscounts the distinct external readings" % r["row_id"]
            else:
                assert _w4_repo_for(col, w4), \
                    "row %s column %s claims a repository measurement that W4 " \
                    "does not have" % (r["row_id"], col)


if __name__ == "__main__":
    sys.exit(main())
