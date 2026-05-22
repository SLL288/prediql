#!/usr/bin/env python3
"""
Cross-model Jaccard over LLM detector findings across PrediQL run folders.

Scans ``output/<api-slug>/<model-slug>/`` (see ``config.configure_run_artifacts``),
loads LLM rows from ``all_detector_detections_final.csv`` when present, else from
``*_dual_detection_comparison.csv`` ``llm_results`` JSON.

Example:
  python prediql_jaccard.py
  python prediql_jaccard.py --root ./output --api portal.ehri-project.eu_api_graphql
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from output_folder_analysis import default_output_root, run_jaccard_scan, write_json


def _print_report(report: dict) -> None:
    root = report.get("output_root", "")
    print(f"Output root: {root}\n")
    apis = report.get("apis") or []
    if not apis:
        print(
            "No API directories found under this root (expected layout: "
            "output/<api-slug>/<model-slug>/ with run artifacts)."
        )
        return
    for api in apis:
        if api.get("skipped"):
            print(f"API {api.get('api_slug')}: skipped — {api.get('reason')}")
            print(f"  models: {api.get('models_found', [])}\n")
            continue
        print(f"API {api.get('api_slug')}")
        print(f"  models: {', '.join(api.get('models', []))}")
        counts = api.get("global_key_counts") or {}
        print(f"  distinct LLM finding keys (per model): {counts}")
        for row in api.get("pairwise_global_union_jaccard", []):
            print(
                f"  {row.get('model_a')} vs {row.get('model_b')}: "
                f"Jaccard={row.get('jaccard')}  |A|={row.get('|A|')} |B|={row.get('|B|')}"
            )
            print(f"    {row.get('interpretation', '')}")
        for row in api.get("per_node_alignment", []) or []:
            print(
                f"  [per-node mean] {row.get('model_a')} vs {row.get('model_b')}: "
                f"common_nodes={row.get('common_nodes')} mean_jaccard={row.get('mean_jaccard_over_nodes')}"
            )
        print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Cross-model Jaccard on LLM findings under output/<api>/<model>/."
    )
    p.add_argument(
        "--root",
        type=Path,
        default=None,
        help="PrediQL output root (default: ./output)",
    )
    p.add_argument(
        "--api",
        type=str,
        default=None,
        metavar="SLUG",
        help="Only this API directory name (e.g. portal.ehri-project.eu_api_graphql)",
    )
    p.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Write full JSON report (default: <root>/cross_model_jaccard_report.json)",
    )
    args = p.parse_args(argv)
    root = args.root or default_output_root()
    if not root.is_dir():
        print(f"❌ Output root not found or not a directory: {root}", file=sys.stderr)
        return 2
    report = run_jaccard_scan(root, api_filter=args.api)
    out_path = args.json_out or (root / "cross_model_jaccard_report.json")
    write_json(out_path, report)
    print(f"Wrote JSON report to {out_path}\n")
    _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
