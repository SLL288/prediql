"""Coverage comparison matrix — ablations across APIs and models, read-only.

Builds a single table from every coverage run so the ablation arms (full vs
no-bandit vs no-bucket) and the Fuzz4All baseline can be compared across all
APIs and models at once, without hand-picking runs on the Compare page. Reads
only the JSON the pipeline already writes.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import runs as runs_mod

# The 7 coverage APIs the ablation campaign runs on; the ablation arms only
# exist here, so the matrix is restricted to them (other baselines and the
# security apps live on their own pages).
COVERAGE_APIS = {
    "countries", "ehri", "graphqlzero", "pokeapi",
    "rickandmorty", "tcgdex", "userwallet",
    # Extensions toward GraphQLer's public set.
    "fooddelivery", "jsongraphql", "anilist",
}

# Canonical arm order for the columns.
ARM_ORDER = ["full", "no-bandit", "no-bucket", "fuzz4all"]
ARM_LABEL = {
    "full": "Full (bandit+reuse)",
    "no-bandit": "− bandit (+RandomArm)",
    "no-bucket": "− value reuse (+NoBucket)",
    "fuzz4all": "Fuzz4All baseline",
}


def _arm(summary: dict[str, Any]) -> str | None:
    """The ablation arm a run belongs to, or None to exclude it from the matrix."""
    providers = summary.get("providers") or {}
    gen = providers.get("generator", "")
    if gen == "baseline:fuzz4all":
        return "fuzz4all"
    if gen.startswith("baseline:"):
        return None  # graphqler/zap/evomaster — shown on the Baselines page
    arms = tuple((summary.get("arms") or ()))
    if "+RandomArm" in arms:
        return "no-bandit"
    if "+NoBucket" in arms:
        return "no-bucket"
    if arms:
        return None  # some other arm combo — not part of this comparison
    # Imported v1 ablation tags (base/aqg/scl/full) use a separate scheme and
    # model set; keep them out of this engine-arm matrix.
    if summary.get("ablation"):
        return None
    return "full"


def _model(summary: dict[str, Any]) -> str:
    providers = summary.get("providers") or {}
    gen = providers.get("generator", "")
    # A Fuzz4All run's generator is the literal "baseline:fuzz4all"; its real
    # backbone is in fuzz4all_model, so resolve to that — otherwise every
    # baseline run collapses onto a single "fuzz4all" model and the per-model
    # Fuzz4All column reads empty.
    if gen == "baseline:fuzz4all" or not gen:
        gen = summary.get("fuzz4all_model", "") or gen
    return gen.split("openrouter:")[-1].split(":")[-1] or "?"


def matrix() -> dict[str, Any]:
    """Per (api, model, arm) mean coverage over trials, plus the best model."""
    runs = runs_mod.list_runs()
    # cell[api][model][arm] -> list of (element, operation, field_path)
    cell: dict[str, dict[str, dict[str, list]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list)))
    apps: set[str] = set()
    models: set[str] = set()
    arms_seen: set[str] = set()

    for r in runs:
        if r.get("mode") not in ("coverage", "full", ""):
            # coverage lives on coverage/full runs; a security-only run has none
            if r.get("element_coverage") is None:
                continue
        if r.get("element_coverage") is None:
            continue
        arm = _arm(r)
        if arm is None:
            continue
        # fuzz4all alias may carry a suffix; use the API field
        api = r.get("api") or r.get("alias")
        if api not in COVERAGE_APIS:
            continue
        model = _model(r)
        apps.add(api)
        models.add(model)
        arms_seen.add(arm)
        cell[api][model][arm].append((
            r.get("element_coverage"), r.get("operation_coverage"), r.get("field_path_coverage")))

    def agg(rows: list) -> dict[str, Any] | None:
        els = [x[0] for x in rows if x[0] is not None]
        ops = [x[1] for x in rows if x[1] is not None]
        fps = [x[2] for x in rows if x[2] is not None]
        if not els and not ops and not fps:
            return None
        return {
            "element": sum(els) / len(els) if els else None,
            "operation": sum(ops) / len(ops) if ops else None,
            "field_path": sum(fps) / len(fps) if fps else None,
            "trials": len(rows),
        }

    out_cells: dict[str, dict[str, dict[str, Any]]] = {}
    for api in cell:
        out_cells[api] = {}
        for model in cell[api]:
            out_cells[api][model] = {}
            for arm, rows in cell[api][model].items():
                a = agg(rows)
                if a:
                    out_cells[api][model][arm] = a

    # Per-model mean of each metric over the FULL arm across all APIs, so the
    # frontend can rank by whichever metric is toggled on.
    per_model_full: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: {"element": [], "operation": [], "field_path": []})
    for api in out_cells:
        for model, byarm in out_cells[api].items():
            full = byarm.get("full")
            if not full:
                continue
            for metric in ("element", "operation", "field_path"):
                if full.get(metric) is not None:
                    per_model_full[model][metric].append(full[metric])

    def _mean(xs: list[float]) -> float | None:
        return sum(xs) / len(xs) if xs else None

    ranking = sorted(
        ({"model": m,
          "mean_element": _mean(v["element"]),
          "mean_operation": _mean(v["operation"]),
          "mean_field_path": _mean(v["field_path"]),
          "apis": len(v["element"])}
         for m, v in per_model_full.items()),
        key=lambda x: x["mean_element"] or 0, reverse=True)

    arms = [a for a in ARM_ORDER if a in arms_seen]
    return {
        "apps": sorted(apps),
        "models": sorted(models),
        "arms": arms,
        "arm_labels": {a: ARM_LABEL.get(a, a) for a in arms},
        "cells": out_cells,
        "ranking": ranking,
        "best_model": ranking[0]["model"] if ranking else None,
    }
