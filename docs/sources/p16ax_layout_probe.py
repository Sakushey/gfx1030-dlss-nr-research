"""Phase 16AX / T-SOURCES -- OpenDLSS-NR fusedLayout byte-model probe.

HOST ONLY. No network, no GPU. Reads ON-DISK artifacts only.

Purpose: test whether OpenDLSS-NR's published per-record byte layout
(docs/weights.md, "A window block of C channels (fusedLayout)") reproduces
the per-record byte extents measured on THIS project's side.

The external model's vocabulary is translated into a pure-Python model here.
Nothing is imported from any external repository; the model is re-expressed
from the published description so the arithmetic is auditable line by line.

Model units: BYTES. E4M3 weight matrices contribute one byte per weight;
f16 vectors contribute two bytes per element; f32 per-head scales four bytes
per head, padded up to a 16-byte boundary.
"""
import hashlib
import json
import os
import sys

ROOT = r"<PROJECT_ROOT>"


def align_up(v, a):
    return (v + a - 1) // a * a


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- our side
def load_index(rel):
    p = os.path.join(ROOT, rel)
    with open(p, "rb") as fh:
        raw = fh.read()
    recs = json.loads(raw.decode("utf-8"))
    return p, hashlib.sha256(raw).hexdigest(), len(raw), recs


# ------------------------------------------------- OpenDLSS-NR byte model
def window_block(C, pad3=16):
    """fusedLayout for a plain window block of C channels, in bytes."""
    heads = C // 32
    E = C // 32 if C >= 64 else 0
    expand = C * 128 if C < 64 else E * C * 128
    contract = 128 * C if C < 64 else E * 128 * 32 + C * C
    return dict(
        expand=expand,
        contract=contract,
        pad_a=16,
        ffnCosSkip=2 * C,
        pad_b=16,
        qkv=3 * C * C,
        relative=heads * 8192,
        scale=align_up(4 * heads, 16),
        projection=C * C,
        attnCosSkip=2 * C,
        pad_c=pad3,
    )


def total(d):
    return sum(d.values())


def vit_layer(C, heads, layer):
    """ViT record layout. 1024 -> 4096 -> 1024 FFN, heads=32."""
    if layer == 0:
        return {"expand": 4096 * C + 16}
    if layer == 1:
        return {"contract": C * 4096, "skip_scale": 2 * C}
    if layer == 2:
        return {"head_scales": align_up(4 * heads, 16), "qkv": 3 * C * C}
    if layer == 3:
        return {"unread": 2}
    if layer == 4:
        return {"projection": C * C, "skip_scale": 2 * C}
    raise ValueError(layer)


def split512_layer(layer):
    """512-channel block split across four records."""
    C = 512
    if layer == 0:                       # eight branch MLPs 64->256->64
        return {"branches": 8 * (64 * 256 + 256 * 64), "pad": 16}
    if layer == 1:                       # contraction + skip scale
        return {"contraction": C * C, "skip_scale": 2 * C}
    if layer == 2:                       # qkv + priors + head scales
        return {"qkv": 3 * C * C, "relative": 16 * 8192, "scale": 64}
    if layer == 3:                       # projection + skip scale
        return {"projection": C * C, "skip_scale": 2 * C}
    raise ValueError(layer)


def main():
    rel_index = "p16an/native/_fetch/weights-index.json"
    p, sha, nbytes, recs = load_index(rel_index)
    by = {r["name"]: r for r in recs}
    out = {
        "probe": "p16ax/sources/p16ax_layout_probe.py",
        "host_only": True,
        "gpu_calls": 0,
        "network_calls": 0,
        "external_model": {
            "source": "maanHimself/OpenDLSS-NR docs/weights.md (fusedLayout table)",
            "units": "BYTES; E4M3 weights 1 byte/weight; f16 vectors 2 bytes/element; "
                     "f32 per-head scale 4 bytes/head padded to 16",
            "reimplemented_here": True,
            "not_vendored": True,
        },
        "our_side_artifact": {
            "path": rel_index,
            "sha256": sha,
            "bytes": nbytes,
            "n_records": len(recs),
            "provenance_tier": "HELD_PINNED_THIRD_PARTY_COPY (lmxxf/dlss5-on-amd-9070xt-porting "
                               "Development/weights-index.json, held byte-identical in this project)",
        },
        "comparisons": [],
    }
    comp = out["comparisons"]

    def cmp_record(name, model, note=""):
        r = by.get(name)
        row = {"record": name, "model_bytes": total(model), "model_parts": model,
               "model_note": note}
        if r is None:
            row["our_payload_bytes"] = None
            row["verdict"] = "RECORD_ABSENT_LOCALLY"
        else:
            row["our_payload_bytes"] = r["payload_size"]
            row["residual_bytes"] = r["payload_size"] - total(model)
            row["verdict"] = "EXACT" if row["residual_bytes"] == 0 else "RESIDUAL"
        comp.append(row)
        return row

    # --- plain window blocks, one per width, plus the two C=32 anchors
    for name, C in [("block1.layer0.layer", 32), ("block2.layer0.layer", 32),
                    ("block5.layer0.layer", 64), ("block6.layer0.layer", 64),
                    ("block9.layer0.layer", 128), ("block10.layer0.layer", 128),
                    ("block15.layer0.layer", 256), ("block16.layer0.layer", 256),
                    ("block67.layer0.layer", 32), ("block69.layer0.layer", 32),
                    ("block63.layer0.layer", 64), ("block57.layer0.layer", 128),
                    ("block49.layer0.layer", 256)]:
        cmp_record(name, window_block(C))

    # --- the five ViT records, all eight ViT blocks
    for n in range(31, 39):
        for L in range(5):
            cmp_record("block%d.layer%d.layer" % (n, L), vit_layer(1024, 32, L))

    # --- the 512-channel split blocks
    for n in list(range(23, 30)) + list(range(40, 48)):
        for L in range(4):
            cmp_record("block%d.layer%d.layer" % (n, L), split512_layer(L))

    # --- special blocks
    cmp_record("block0.layer0.layer",
               dict(window_block(32), **{}), "preFusedLayout: + 16->32 f16 adapter")
    b0 = window_block(32)
    b0 = dict(b0)
    b0["adapter_16_32_f16"] = 16 * 32 * 2
    cmp_record("block0.layer0.layer", b0, "preFusedLayout incl. plain-f16 16x32 adapter")

    cmp_record("block70.layer0.layer", window_block(32), "postFusedLayout, no additions")
    b70 = dict(window_block(32))
    b70["head_32_4_f16"] = 32 * 4 * 2 + 4 * 2
    b70["blend_scale_vectors_2x32_f16"] = 2 * 32 * 2
    cmp_record("block70.layer0.layer", b70, "postFusedLayout: 32->4 f16 head + two C=32 f16 vectors")

    cmp_record("block70.layer0.blend_scale", {"one_f16": 2}, "named in the external doc")

    # block 30 layer4 = 512->1024 matrix into the ViT
    cmp_record("block30.layer4.layer", {"matrix_512_1024": 512 * 1024})
    # block 39 layer0 = 1024->512 matrix out of the ViT + skip scale
    cmp_record("block39.layer0.layer", {"matrix_1024_512": 1024 * 512, "skip_scale_2C": 2 * 512})

    # --- encoder transition blocks: pad_c replaced by the C->2C matrix
    for name, C in [("block4.layer0.layer", 32), ("block8.layer0.layer", 64),
                    ("block14.layer0.layer", 128), ("block22.layer0.layer", 256),
                    ("block30.layer3.layer", 512)]:
        m = window_block(C)
        base = total(m)
        m_kept = dict(m)
        m_kept["transition_C_2C"] = C * 2 * C
        cmp_record(name, m_kept, "transition: C->2C matrix ADDED, 16-byte pad kept")
        m_repl = dict(m)
        del m_repl["pad_c"]
        m_repl["transition_C_2C"] = C * 2 * C
        cmp_record(name, m_repl, "transition: C->2C matrix REPLACES the 16-byte pad")
        # keep the computed base visible
        comp[-1]["base_with_pad_c"] = base

    # --- first decoder block of a stage: upsampleFusedLayout
    for name, C in [("block66.layer0.layer", 32), ("block62.layer0.layer", 64),
                    ("block56.layer0.layer", 128), ("block48.layer0.layer", 256),
                    ("block39.layer0.layer", 512)]:
        m = window_block(C)
        m2 = dict(m)
        m2["upsample_2C_to_C"] = 2 * C * C
        m2["second_skip_scale_2C"] = 2 * C
        cmp_record(name, m2, "upsampleFusedLayout: 2C->C matrix + second scale vector")

    # --- summary
    exact = [c for c in comp if c["verdict"] == "EXACT"]
    resid = [c for c in comp if c["verdict"] == "RESIDUAL"]
    out["summary"] = {
        "n_comparisons": len(comp),
        "n_exact": len(exact),
        "n_residual": len(resid),
        "n_absent": len([c for c in comp if c["verdict"] == "RECORD_ABSENT_LOCALLY"]),
        "exact_record_names": [c["record"] for c in exact],
        "residual_detail": [
            {"record": c["record"], "model": c["model_bytes"],
             "our": c["our_payload_bytes"], "residual": c.get("residual_bytes"),
             "model_note": c["model_note"]} for c in resid
        ],
    }
    return out


if __name__ == "__main__":
    res = main()
    outp = os.path.join(ROOT, "p16ax", "sources", "LAYOUT_PROBE_RESULT_16AX.json")
    with open(outp, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    s = res["summary"]
    print("comparisons=%d exact=%d residual=%d absent=%d" %
          (s["n_comparisons"], s["n_exact"], s["n_residual"], s["n_absent"]))
    print("--- residuals ---")
    for r in s["residual_detail"]:
        print("  %-28s model=%-9s our=%-9s residual=%-7s %s" %
              (r["record"], r["model"], r["our"], r["residual"], r["model_note"]))
    print("wrote", outp)
