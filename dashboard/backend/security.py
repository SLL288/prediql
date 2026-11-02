"""Security results aggregate — the detection study (RQ3), read-only.

Collects every run that scored findings against ground truth, grouped by model
(backbone) and labelled app, and reports the confirmed-only and
confirmed+potential confusion matrices, the false-positive rate on the labelled
negatives, the per-class breakdown, and — where a truth file carries post-hoc
labels — the same metrics as they stood *before* those labels were added. This
is the dashboard counterpart of ``scripts/security_scores.py``, reading only the
JSON the pipeline already writes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import runs as runs_mod

# Persisted GraphQLer detection scores (scripts/score_graphqler.py --out), scored
# with our scorer against the identical ground truth, so it is directly
# comparable to PrediQL on the same apps.
_GRAPHQLER_DETECTION = Path(__file__).resolve().parents[2] / "security_benchmark" / "graphqler_detection.json"


def _fpr(m: dict[str, Any]) -> float | None:
    denom = (m.get("fp") or 0) + (m.get("tn") or 0)
    return (m["fp"] / denom) if denom else None


def _matrix(m: dict[str, Any]) -> dict[str, Any]:
    """The reportable subset of a confusion matrix, FP rate included."""
    keys = ("tp", "fp", "fn", "tn", "precision", "recall", "f1",
            "coverage_conditioned_recall")
    out = {k: m.get(k) for k in keys}
    out["fp_rate"] = _fpr(m)
    return out


def _app_row(run: dict[str, Any]) -> dict[str, Any] | None:
    """One (app, model, trial) row from a run that scored findings, or None."""
    score = run.get("score")
    if not score or not isinstance(score, dict) or "confirmed" not in score:
        return None
    manifest = run.get("manifest", {})
    config = manifest.get("config", {})
    model = (config.get("providers") or {}).get("generator", "?").split(":")[-1]
    findings = (run.get("findings") or {}).get("findings", [])
    row: dict[str, Any] = {
        "run_id": run["run_id"],
        "app": config.get("alias", run["run_id"]),
        "model": model,
        "trial": config.get("trial", 1),
        "status": run.get("status"),
        "certification": score.get("certification"),
        "code_version": config.get("code_version")
            or (manifest.get("provenance") or {}).get("code_version"),
        "truth_file": score.get("truth_file"),
        "confirmed": _matrix(score["confirmed"]),
        "with_potential": _matrix(score.get("with_potential", {})),
        "post_hoc_labels": score.get("post_hoc_labels", []),
        "unlabelled_confirmed": score.get("unlabelled_confirmed_cells", []),
        "by_class": score.get("by_class", {}),
        "fn_cells": score.get("confirmed", {}).get("fn_cells", []),
        "fn_uncovered_cells": score.get("confirmed", {}).get("fn_uncovered_cells", []),
        "confirmed_findings": sum(1 for f in findings if f.get("state") == "confirmed"),
        "potential_findings": sum(1 for f in findings if f.get("state") == "potential"),
    }
    without = score.get("without_post_hoc")
    if without and without.get("confirmed"):
        row["without_post_hoc"] = _matrix(without["confirmed"])
    return row


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Pooled confusion matrix over a set of rows (micro-average)."""
    agg = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for row in rows:
        for k in agg:
            agg[k] += row["confirmed"].get(k) or 0
    tp, fp, fn = agg["tp"], agg["fp"], agg["fn"]
    agg["precision"] = tp / (tp + fp) if (tp + fp) else None
    agg["recall"] = tp / (tp + fn) if (tp + fn) else None
    p, r = agg["precision"], agg["recall"]
    agg["f1"] = (2 * p * r / (p + r)) if (p and r) else None
    agg["fp_rate"] = _fpr(agg)
    return agg


def _pool(matrices: list[dict[str, Any]]) -> dict[str, Any]:
    """Micro-average a set of confusion matrices."""
    agg = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for m in matrices:
        for k in agg:
            agg[k] += m.get(k) or 0
    tp, fp, fn = agg["tp"], agg["fp"], agg["fn"]
    agg["precision"] = tp / (tp + fp) if (tp + fp) else None
    agg["recall"] = tp / (tp + fn) if (tp + fn) else None
    p, r = agg["precision"], agg["recall"]
    agg["f1"] = (2 * p * r / (p + r)) if (p and r) else None
    agg["fp_rate"] = _fpr(agg)
    return agg


def _graphqler_comparison(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """PrediQL vs GraphQLer on the identical apps GraphQLer was scored on.

    GraphQLer's detection is a fixed published artifact and PrediQL's confirmed
    detection is backbone-independent (the oracle is deterministic), so we line up
    one representative PrediQL row per shared app and pool both over the same set.
    """
    if not _GRAPHQLER_DETECTION.exists():
        return None
    try:
        gql = json.loads(_GRAPHQLER_DETECTION.read_text())
    except (OSError, ValueError):
        return None
    apps = gql.get("scored_apps", [])
    prediql_apps: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["app"] in apps and row["app"] not in prediql_apps:
            prediql_apps[row["app"]] = row["confirmed"]
    if not prediql_apps:
        return None
    pooled = _pool([prediql_apps[a] for a in apps if a in prediql_apps])
    return {
        "scored_apps": apps,
        "note": gql.get("source", ""),
        "graphqler": {"apps": gql.get("apps", {}), "aggregate": gql.get("aggregate", {})},
        "prediql": {"apps": prediql_apps, "aggregate": pooled},
    }


def summary() -> dict[str, Any]:
    """Every scored security run, grouped by backbone model, with pooled totals."""
    rows: list[dict[str, Any]] = []
    for summary_row in runs_mod.list_runs():
        if summary_row.get("mode") not in ("security", "full", "chains"):
            # score can still exist (re-scored), so fall through on any run that
            # actually carries one, but skip pure coverage runs cheaply first.
            if summary_row.get("precision") is None and summary_row.get("recall") is None:
                continue
        detail = runs_mod.get_run(summary_row["run_id"])
        if detail is None:
            continue
        row = _app_row(detail)
        if row is not None:
            rows.append(row)

    by_model: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_model.setdefault(row["model"], []).append(row)

    models = []
    for model in sorted(by_model):
        model_rows = sorted(by_model[model], key=lambda r: (r["app"], r["trial"]))
        models.append({
            "model": model,
            "rows": model_rows,
            "aggregate": _aggregate(model_rows),
            "has_post_hoc": any(r.get("post_hoc_labels") for r in model_rows),
        })

    apps = sorted({r["app"] for r in rows})
    return {
        "models": models,
        "apps": apps,
        "run_count": len(rows),
        "any_post_hoc": any(r.get("post_hoc_labels") for r in rows),
        "comparison": _graphqler_comparison(rows),
    }
