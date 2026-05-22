"""
Offline analysis of PrediQL ``output/<api>/<model>/`` run directories.

Used by ``prediql_jaccard.py`` and ``prediql_output_analyze.py`` after runs complete,
especially for cross-model LLM finding comparison (Jaccard on finding-type keys).
"""

from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from finding_jaccard import finding_type_keys, jaccard_pair_report

ALL_DETECTOR_CSV = "all_detector_detections_final.csv"
DUAL_COMPARISON_GLOB = "*_dual_detection_comparison.csv"
NODE_STATS = "node_stats_final.csv"


def _dual_comparison_csv_paths(run_dir: Path) -> List[Path]:
    """Legacy run-root ``*_dual_detection_comparison.csv`` plus ``nodes/<op>/dual_detection_comparison.csv``."""
    out: List[Path] = []
    out.extend(sorted(run_dir.glob(DUAL_COMPARISON_GLOB)))
    nd = run_dir / "nodes"
    if nd.is_dir():
        out.extend(sorted(nd.glob("*/dual_detection_comparison.csv")))
    return sorted(set(out), key=lambda p: str(p))


def default_output_root() -> Path:
    return Path(os.getcwd()) / "output"


def _looks_like_model_run(d: Path) -> bool:
    if not d.is_dir():
        return False
    if (d / ALL_DETECTOR_CSV).is_file():
        return True
    if any(d.glob(DUAL_COMPARISON_GLOB)):
        return True
    if _dual_comparison_csv_paths(d):
        return True
    nodes = d / "nodes"
    if nodes.is_dir():
        for child in nodes.iterdir():
            if child.is_dir() and (child / "llama_queries.json").is_file():
                return True
    for child in d.iterdir():
        if child.is_dir() and (child / "llama_queries.json").is_file():
            return True
    return False


def _looks_like_api_dir(d: Path) -> bool:
    if not d.is_dir():
        return False
    subs = [c for c in d.iterdir() if c.is_dir()]
    return any(_looks_like_model_run(s) for s in subs)


def discover_api_dirs(root: Path) -> List[Path]:
    if not root.is_dir():
        return []
    return sorted([p for p in root.iterdir() if p.is_dir() and _looks_like_api_dir(p)])


def discover_model_runs(api_dir: Path) -> List[Tuple[str, Path]]:
    out: List[Tuple[str, Path]] = []
    for p in sorted(api_dir.iterdir()):
        if p.is_dir() and _looks_like_model_run(p):
            out.append((p.name, p))
    return out


def _iter_llm_rows_from_all_detector_csv(run_dir: Path) -> Iterator[Dict[str, Any]]:
    path = run_dir / ALL_DETECTOR_CSV
    if not path.is_file():
        return
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if (row.get("detector") or "").strip().lower() != "llm":
                continue
            yield {
                "detection_name": row.get("detection_name") or "",
                "detection": row.get("detection") or "",
                "category": row.get("category") or "",
            }


def _iter_llm_results_from_dual_csvs(run_dir: Path) -> Iterator[Dict[str, Any]]:
    for path in _dual_comparison_csv_paths(run_dir):
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = row.get("llm_results") or ""
                try:
                    items = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(items, list):
                    continue
                for item in items:
                    if isinstance(item, dict):
                        yield item


def load_llm_finding_dicts(run_dir: Path) -> List[Dict[str, Any]]:
    """
    Prefer ``all_detector_detections_final.csv`` (detector=llm); else parse
    ``*_dual_detection_comparison.csv`` ``llm_results`` JSON columns.
    """
    rows = list(_iter_llm_rows_from_all_detector_csv(run_dir))
    if rows:
        return rows
    return list(_iter_llm_results_from_dual_csvs(run_dir))


def llm_finding_keys_union(findings: List[Dict[str, Any]]) -> set:
    return finding_type_keys(findings, exclude_safe=True)


def llm_findings_by_node(run_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """node_name -> list of LLM finding dicts (for per-node Jaccard alignment)."""
    by_node: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    path = run_dir / ALL_DETECTOR_CSV
    if path.is_file():
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if (row.get("detector") or "").strip().lower() != "llm":
                    continue
                n = (row.get("node_name") or "").strip() or "_unknown"
                by_node[n].append(
                    {
                        "detection_name": row.get("detection_name") or "",
                        "detection": row.get("detection") or "",
                        "category": row.get("category") or "",
                    }
                )
        return dict(by_node)
    # Fallback: dual CSVs carry node in node_name column
    for csv_path in _dual_comparison_csv_paths(run_dir):
        with csv_path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                n = (row.get("node_name") or "").strip() or "_unknown"
                raw = row.get("llm_results") or ""
                try:
                    items = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(items, list):
                    continue
                for item in items:
                    if isinstance(item, dict):
                        by_node[n].append(item)
    return dict(by_node)


def pairwise_cross_llm_for_api(
    api_slug: str, models: Dict[str, List[Dict[str, Any]]]
) -> Dict[str, Any]:
    """
    ``models``: model_slug -> list of LLM finding dicts for that run.
    Returns pairwise Jaccard (global union keys) and per-node mean Jaccard where nodes align.
    """
    names = sorted(models.keys())
    global_keys = {m: llm_finding_keys_union(models[m]) for m in names}
    pairwise: List[Dict[str, Any]] = []
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            rep = jaccard_pair_report(
                models[a],
                models[b],
                label_a=a,
                label_b=b,
                comparison_kind="cross_llm",
            )
            pairwise.append(
                {
                    "model_a": a,
                    "model_b": b,
                    "jaccard": rep.get("jaccard"),
                    "interpretation": rep.get("interpretation"),
                    "|A|": rep.get("|A|"),
                    "|B|": rep.get("|B|"),
                    "|A ∩ B|": rep.get("|A ∩ B|"),
                    "|A ∪ B|": rep.get("|A ∪ B|"),
                }
            )

    # Per-node mean Jaccard (requires run dirs for by-node map)
    return {
        "api_slug": api_slug,
        "models": names,
        "global_key_counts": {m: len(global_keys[m]) for m in names},
        "pairwise_global_union_jaccard": pairwise,
    }


def _per_node_mean_jaccard(run_paths: Dict[str, Path]) -> List[Dict[str, Any]]:
    """For each unordered pair of models, mean Jaccard over nodes present in both runs."""
    if len(run_paths) < 2:
        return []
    names = sorted(run_paths.keys())
    by_model = {m: llm_findings_by_node(run_paths[m]) for m in names}
    rows: List[Dict[str, Any]] = []
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            common = set(by_model[a]) & set(by_model[b])
            scores: List[float] = []
            for node in sorted(common):
                ja = by_model[a].get(node) or []
                jb = by_model[b].get(node) or []
                rep = jaccard_pair_report(
                    ja, jb, label_a=a, label_b=b, comparison_kind="cross_llm"
                )
                scores.append(float(rep.get("jaccard", 0.0)))
            mean_j = sum(scores) / len(scores) if scores else None
            rows.append(
                {
                    "model_a": a,
                    "model_b": b,
                    "common_nodes": len(common),
                    "mean_jaccard_over_nodes": round(mean_j, 6) if mean_j is not None else None,
                }
            )
    return rows


def run_jaccard_scan(
    output_root: Path,
    *,
    api_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    For each API under ``output_root``, compare every pair of model runs using
    LLM finding keys (same definition as ``finding_jaccard.finding_type_keys``).
    """
    report: Dict[str, Any] = {"output_root": str(output_root.resolve()), "apis": []}
    for api_dir in discover_api_dirs(output_root):
        slug = api_dir.name
        if api_filter and slug != api_filter:
            continue
        model_runs = discover_model_runs(api_dir)
        if len(model_runs) < 2:
            report["apis"].append(
                {
                    "api_slug": slug,
                    "skipped": True,
                    "reason": "need_at_least_two_model_run_directories",
                    "models_found": [m for m, _ in model_runs],
                }
            )
            continue
        models_data: Dict[str, List[Dict[str, Any]]] = {}
        run_paths: Dict[str, Path] = {}
        for model_slug, run_path in model_runs:
            findings = load_llm_finding_dicts(run_path)
            models_data[model_slug] = findings
            run_paths[model_slug] = run_path
        block = pairwise_cross_llm_for_api(slug, models_data)
        pnode = _per_node_mean_jaccard(run_paths)
        if pnode:
            block["per_node_alignment"] = pnode
        report["apis"].append(block)
    return report


def summarize_run_dir(run_dir: Path) -> Dict[str, Any]:
    """Lightweight stats for one ``output/<api>/<model>/`` directory."""
    node_dirs: List[Path] = []
    nr = run_dir / "nodes"
    if nr.is_dir():
        node_dirs = [p for p in nr.iterdir() if p.is_dir() and (p / "llama_queries.json").is_file()]
    if not node_dirs:
        node_dirs = [
            p
            for p in run_dir.iterdir()
            if p.is_dir() and (p / "llama_queries.json").is_file()
        ]
    findings = load_llm_finding_dicts(run_dir)
    keys = llm_finding_keys_union(findings)
    stats_path = run_dir / NODE_STATS
    return {
        "path": str(run_dir.resolve()),
        "node_folders_with_llama_queries": len(node_dirs),
        "llm_finding_rows_or_results": len(findings),
        "distinct_llm_finding_keys": len(keys),
        "has_node_stats_final_csv": stats_path.is_file(),
        "has_all_detector_csv": (run_dir / ALL_DETECTOR_CSV).is_file(),
        "dual_comparison_csv_count": len(_dual_comparison_csv_paths(run_dir)),
    }


def summarize_output_folder(output_root: Path) -> Dict[str, Any]:
    """Inventory APIs and model runs under ``output_root``."""
    summary: Dict[str, Any] = {
        "output_root": str(output_root.resolve()),
        "apis": [],
    }
    for api_dir in discover_api_dirs(output_root):
        entry: Dict[str, Any] = {
            "api_slug": api_dir.name,
            "model_runs": [],
        }
        for model_slug, run_path in discover_model_runs(api_dir):
            entry["model_runs"].append(
                {"model_slug": model_slug, "stats": summarize_run_dir(run_path)}
            )
        summary["apis"].append(entry)
    return summary


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
