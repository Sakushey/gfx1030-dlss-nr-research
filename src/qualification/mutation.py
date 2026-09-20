"""Aggregate-level mutation testing for a gate suite.

THE QUESTION
    Not "can the checker detect an old bug?" but "does a mutation of a gate's
    DECISIVE EVIDENCE move the FINAL verdict?"  A gate whose evidence can be
    corrupted without the top-level result changing is instrumentation
    theatre -- it can fail, but nothing depends on it failing.

    So the acceptance criterion is:

        every gate has at least one mutation that flips the final verdict

USAGE
    >>> from qualification import Evidence, mutation
    >>> def build(ev):
    ...     ...            # return the aggregate dict
    >>> report = mutation.run_suite(build, MUTATIONS)

    A mutation is ``(name, mutate_fn, intended_gate_id)``; ``mutate_fn`` takes
    ``(rel_path, kind, value)`` and returns the substituted value, where
    ``kind`` is ``"raw"`` (bytes) or ``"json"`` (the parsed object).

CONTROLS
    A known-good control runs with no mutation and must reproduce the baseline.
    Without it, a harness that reported "effective" for everything would look
    perfect.  This is not hypothetical: the first version of the harness in the
    originating project applied field-level mutations to raw bytes, so 29
    mutations silently no-op'd and made a *sound* system look fail-open.
"""

from __future__ import annotations


def combine(*mutators):
    """Chain mutators; each sees the previous one's output."""
    def _m(rel, kind, value):
        for fn in mutators:
            value = fn(rel, kind, value)
        return value
    return _m


def flip_bytes(path_suffix, offset_ratio=0.5):
    """Corrupt one byte in the raw surface of a matching file."""
    def _m(rel, kind, value):
        if not _norm(rel).endswith(_norm(path_suffix)):
            return value
        if not isinstance(value, bytes) or not value:
            return value
        b = bytearray(value)
        i = min(len(b) - 1, int(len(b) * offset_ratio))
        b[i] ^= 0x01
        return bytes(b)
    return _m


def truncate(path_suffix, keep=0.5):
    def _m(rel, kind, value):
        if not _norm(rel).endswith(_norm(path_suffix)) or not isinstance(value, bytes):
            return value
        return value[:int(len(value) * keep)]
    return _m


def malformed_json(path_suffix):
    def _m(rel, kind, value):
        if _norm(rel).endswith(_norm(path_suffix)) and isinstance(value, bytes):
            return b"{ this is not json"
        return value
    return _m


def set_fields(path_suffix, **dotted_values):
    """Set dotted paths inside the PARSED object of a matching file."""
    def _m(rel, kind, value):
        if not _norm(rel).endswith(_norm(path_suffix)):
            return value
        if not isinstance(value, dict):
            return value
        import copy
        obj = copy.deepcopy(value)
        for dotted, new in dotted_values.items():
            node = obj
            parts = dotted.split(".")
            for part in parts[:-1]:
                if not isinstance(node.get(part), dict):
                    node[part] = {}
                node = node[part]
            node[parts[-1]] = new
        return obj
    return _m


def _norm(p):
    return str(p).replace("\\", "/")


def run_suite(build, mutations, baseline_keys=("verdict",)):
    """Run the baseline, then every mutation, and attribute effectiveness.

    ``build(ev)`` must return a dict containing at least the keys named in
    ``baseline_keys`` (the aggregate verdict) and, for orphan detection,
    ``gate_results`` (a list of dicts with ``gate_id`` and ``result``).

    Returns a report dict.  Nothing is written to disk.
    """
    from .gates import Evidence

    def _run(mutate=None):
        out = build(Evidence(mutate=mutate))
        agg = out.get("aggregate", out)
        return out, agg

    base_out, base_agg = _run()
    base_verdict = base_agg.get("verdict")
    gate_ids = [g["gate_id"] for g in base_out.get("gate_results", [])]

    results = []
    for name, mutate, intended in mutations:
        try:
            out, agg = _run(mutate)
            verdict = agg.get("verdict")
            failing = [g["gate_id"] for g in out.get("gate_results", [])
                       if g["result"] not in ("PASS", "NOT_APPLICABLE_PROVEN")]
            results.append({
                "mutation": name,
                "intended_gate": intended,
                "final_verdict_after_mutation": verdict,
                "final_verdict_changed": verdict != base_verdict,
                "failing_gates_after_mutation": failing,
                "intended_gate_actually_failed":
                    any(str(g).startswith(str(intended)) for g in failing),
                "effective": verdict != base_verdict,
            })
        except Exception as exc:                              # noqa: BLE001
            results.append({
                "mutation": name, "intended_gate": intended,
                "error": "%s: %s" % (type(exc).__name__, exc),
                "final_verdict_changed": False, "effective": False,
            })

    per_gate = {}
    for gid in gate_ids:
        eff = [r["mutation"] for r in results
               if r.get("intended_gate") and gid.startswith(str(r["intended_gate"]))
               and r["effective"]]
        per_gate[gid] = {"n_effective_mutants": len(eff), "mutants": eff}
    without = [g for g, v in per_gate.items() if v["n_effective_mutants"] == 0]

    control = {
        "mutation": "KNOWN-GOOD CONTROL: no mutation",
        "final_verdict": base_verdict,
        "reproduces_the_baseline": base_verdict == base_agg.get("verdict"),
        "effective": False,
        "note": ("this control must reproduce the baseline; a harness that flagged "
                 "it would be measuring itself"),
    }

    return {
        "baseline_final_verdict": base_verdict,
        "n_mutations": len(results),
        "n_effective": sum(1 for r in results if r["effective"]),
        "n_ineffective": sum(1 for r in results if not r["effective"]),
        "gates_total": len(gate_ids),
        "gates_with_effective_mutant": len(gate_ids) - len(without),
        "gates_without_effective_mutant": without,
        "every_gate_has_an_effective_mutant": len(without) == 0,
        "per_gate": per_gate,
        "known_good_control": control,
        "results": results,
    }
