"""Cross-LLM overlap — the reliability aggregate (doc 05 §3a, doc 09 §3).

Answers reviewer 40A-W3: does the detector measure the API or the model? It
computes the pairwise Jaccard overlap of *confirmed* findings across every model
run for one target. Because it is an aggregate over the whole model sweep, it has
a hard precondition — every selected model must have a finished run for the
target — enforced in the API (409 until then), not left to the caller.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any

import json

from config import runs_root
from runs import list_runs


def _confirmed_keys(run_id: str) -> set[str]:
    """Confirmed finding keys (class::operation) for one run."""
    findings_path = runs_root() / run_id / "artifacts" / "findings.json"
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    return {
        f"{f['class']}::{f['operation']}"
        for f in data.get("findings", [])
        if f.get("state") == "confirmed"
    }


def _model_of(run: dict[str, Any]) -> str:
    """A run's generator model label, for grouping the sweep."""
    return run.get("providers", {}).get("generator", "heuristic")


def overlap_for_target(target: str, ablation: str | None = None) -> dict[str, Any]:
    """Cross-model Jaccard for one target, or a 'not ready' report.

    ``ready`` is false until at least two distinct models have a completed run,
    which is what the API turns into a 409. ``ablation`` optionally scopes the
    sweep to one ablation mode, so "do models agree within BASE vs within full?"
    is a facet rather than a separate endpoint.
    """
    runs = [r for r in list_runs()
            if r["target"] == target and r["status"] == "completed"
            and r["mode"] in ("security", "chains", "full")
            and (ablation in (None, "", "all") or r.get("ablation") == ablation)]
    by_model: dict[str, set[str]] = {}
    for run in runs:
        model = _model_of(run)
        by_model.setdefault(model, set()).update(_confirmed_keys(run["run_id"]))

    models = sorted(by_model)
    if len(models) < 2:
        scope = f" in ablation {ablation!r}" if ablation not in (None, "", "all") else ""
        return {"target": target, "ready": False, "models": models,
                "reason": f"need >=2 models with a completed run{scope}; have {len(models)}"}

    # Pairwise Jaccard matrix.
    matrix = {a: {b: _jaccard(by_model[a], by_model[b]) for b in models} for a in models}
    all_findings = set().union(*by_model.values())
    consensus = set.intersection(*by_model.values()) if by_model else set()

    # Per-finding: how many models found it (singletons are likely hallucinations).
    coverage_count: dict[str, int] = {}
    for keys in by_model.values():
        for key in keys:
            coverage_count[key] = coverage_count.get(key, 0) + 1

    pair_scores = [matrix[a][b] for a, b in combinations(models, 2)]
    return {
        "target": target,
        "ready": True,
        "models": models,
        "matrix": matrix,
        "mean_pairwise_jaccard": round(sum(pair_scores) / len(pair_scores), 4)
        if pair_scores else None,
        "union": sorted(all_findings),
        "consensus": sorted(consensus),
        "found_by": {k: coverage_count[k] for k in sorted(coverage_count)},
        "n_models": len(models),
    }


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return round(len(a & b) / len(union), 4) if union else 0.0


def targets_with_runs() -> list[dict[str, Any]]:
    """Targets that have completed security-bearing runs, with model counts.

    Drives the reliability picker: a target is only worth opening once at least
    two distinct models have finished a run against it.
    """
    seen: dict[str, set[str]] = {}
    ablations: dict[str, set[str]] = {}
    for run in list_runs():
        if run["status"] != "completed" or run["mode"] not in ("security", "chains", "full"):
            continue
        seen.setdefault(run["target"], set()).add(_model_of(run))
        if run.get("ablation"):
            ablations.setdefault(run["target"], set()).add(run["ablation"])
    return [
        {"target": target, "models": sorted(models), "ready": len(models) >= 2,
         "ablations": sorted(ablations.get(target, set()))}
        for target, models in sorted(seen.items())
    ]
