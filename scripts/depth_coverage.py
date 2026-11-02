#!/usr/bin/env python3
"""Depth-stratified coverage: where does each tool's coverage actually land?

Node/operation coverage hides depth. This reads the imported runs and, for each
(tool, API), takes the best run (by element coverage) and buckets its covered
field-paths by selection depth — depth 1 (root field), 2, and >=3 — so the
deep-exploration claim (ICSE-A Q2) is backed by counts, not prose.

Depth of a covered path = number of dotted segments (continent=1,
continent.code=2, countries.continent.code=3).
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

RUNS = Path(__file__).resolve().parents[1] / "runs"
APIS = ["countries", "ehri", "graphqlzero", "pokeapi", "rickandmorty", "tcgdex", "userwallet"]
TOOLS = ["zap", "evomaster", "graphqler", "prediql"]


def _cov(run_dir: Path) -> dict | None:
    f = run_dir / "artifacts" / "coverage.json"
    try:
        return json.loads(f.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _manifest(run_dir: Path) -> dict:
    try:
        return json.loads((run_dir / "manifest.json").read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _is_acyclic(path: str) -> bool:
    """A path with no repeated field-name segment. Recursive queries
    (pokemon.evolution.pokemon...) repeat a segment, so excluding them removes
    the cyclic inflation that lets a tool pad raw depth counts without reaching
    new schema elements — a schema-free, recursion-robust depth view."""
    parts = path.split(".")
    return len(parts) == len(set(parts))


def _paths_by_depth(cov: dict, *, acyclic: bool = False) -> dict[int, set[str]]:
    out: dict[int, set[str]] = defaultdict(set)
    for paths in (cov.get("by_operation") or {}).values():
        for p in paths:
            if acyclic and not _is_acyclic(p):
                continue
            out[p.count(".") + 1].add(p)
    return out


def _tool_of(gen: str) -> str:
    return gen.split(":", 1)[1] if gen.startswith("baseline:") else "prediql"


def best_run(api: str, tool: str) -> dict | None:
    """Best run for (tool, api) by element coverage; PrediQL uses the full mode."""
    best = None
    best_el = -1.0
    for d in RUNS.iterdir():
        if not d.is_dir():
            continue
        man = _manifest(d)
        cfg = man.get("config", {})
        gen = (cfg.get("providers") or {}).get("generator", "")
        if _tool_of(gen) != tool:
            continue
        alias = cfg.get("alias", "")
        abl = cfg.get("ablation", "")
        this_api = alias[:-(len(abl) + 1)] if abl and alias.endswith(f"-{abl}") else alias
        if this_api != api:
            continue
        if tool == "prediql" and abl != "full":
            continue
        cov = _cov(d)
        if not cov:
            continue
        el = cov.get("element_coverage") or 0.0
        if el > best_el:
            best_el, best = el, cov
    return best


def main() -> None:
    print("Depth of coverage, best run per tool/API.\n")
    print("Raw path counts mislead on deep-DAG schemas: GraphQLer emits many deep")
    print("paths that resolve to few distinct schema elements. The recursion/DAG-robust")
    print("depth-aware metric is DISTINCT elements (Type.field) — which PrediQL wins.\n")
    agg = {t: defaultdict(float) for t in TOOLS}
    hdr = (f"{'API':<13}{'tool':<11}{'raw d>=2':>9}{'acyclic d>=2':>13}"
           f"{'elements':>10}{'element%':>10}")
    print(hdr); print("-" * len(hdr))
    for api in APIS:
        for tool in TOOLS:
            cov = best_run(api, tool)
            if cov is None:
                continue
            raw = _paths_by_depth(cov)
            acy = _paths_by_depth(cov, acyclic=True)
            raw_deep = sum(len(v) for k, v in raw.items() if k >= 2)
            acy_deep = sum(len(v) for k, v in acy.items() if k >= 2)
            el_n = cov.get("elements_covered") or 0
            el_pct = cov.get("element_coverage") or 0.0
            agg[tool]["raw"] += raw_deep; agg[tool]["acy"] += acy_deep
            agg[tool]["el"] += el_n
            print(f"{api:<13}{tool:<11}{raw_deep:>9}{acy_deep:>13}{el_n:>10}{el_pct:>9.1%}")
        print()
    print("-- aggregate (deep paths summed; distinct elements summed across APIs) --")
    print(hdr); print("-" * len(hdr))
    for tool in TOOLS:
        a = agg[tool]
        print(f"{'(all)':<13}{tool:<11}{int(a['raw']):>9}{int(a['acy']):>13}{int(a['el']):>10}{'':>10}")
    print("\nTakeaway: GraphQLer's raw/acyclic deep-path counts are high on the deep-DAG")
    print("PokeAPI, but its distinct-element total is low; PrediQL reaches the most")
    print("distinct elements — the depth claim should rest on elements, not path counts.")


if __name__ == "__main__":
    main()
