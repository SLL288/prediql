#!/usr/bin/env python3
"""
Inventory and analyze the PrediQL ``output/`` tree (API → model runs).

Includes per-run file counts and optional cross-model LLM Jaccard (same logic as
``prediql_jaccard.py``).

Example:
  python prediql_output_analyze.py
  python prediql_output_analyze.py --root ./output --no-jaccard
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from output_folder_analysis import (
    default_output_root,
    run_jaccard_scan,
    summarize_output_folder,
    write_json,
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Analyze PrediQL output/<api>/<model>/ folders (inventory + optional Jaccard)."
    )
    p.add_argument(
        "--root",
        type=Path,
        default=None,
        help="PrediQL output root (default: ./output)",
    )
    p.add_argument(
        "--no-jaccard",
        action="store_true",
        help="Skip cross-model LLM Jaccard section",
    )
    p.add_argument(
        "--api",
        type=str,
        default=None,
        metavar="SLUG",
        help="Limit Jaccard section to one API slug (inventory still lists all)",
    )
    p.add_argument(
        "--json-summary-out",
        type=Path,
        default=None,
        help="Write inventory JSON (default: <root>/prediql_output_inventory.json)",
    )
    p.add_argument(
        "--json-jaccard-out",
        type=Path,
        default=None,
        help="Write Jaccard JSON (default: <root>/cross_model_jaccard_report.json when not skipped)",
    )
    args = p.parse_args(argv)
    root = args.root or default_output_root()
    if not root.is_dir():
        print(f"❌ Output root not found or not a directory: {root}", file=sys.stderr)
        return 2

    summary = summarize_output_folder(root)
    summary_path = args.json_summary_out or (root / "prediql_output_inventory.json")
    write_json(summary_path, summary)
    print(f"Wrote inventory to {summary_path}")

    if not summary.get("apis"):
        print("\nNo API run directories found under this root.")
    for api in summary.get("apis", []):
        print(f"\n=== API {api.get('api_slug')} ===")
        for mr in api.get("model_runs", []):
            ms = mr.get("stats") or {}
            print(
                f"  model={mr.get('model_slug')}: "
                f"nodes={ms.get('node_folders_with_llama_queries')} "
                f"llm_rows={ms.get('llm_finding_rows_or_results')} "
                f"distinct_keys={ms.get('distinct_llm_finding_keys')} "
                f"stats_csv={ms.get('has_node_stats_final_csv')}"
            )

    if not args.no_jaccard:
        jrep = run_jaccard_scan(root, api_filter=args.api)
        jpath = args.json_jaccard_out or (root / "cross_model_jaccard_report.json")
        write_json(jpath, jrep)
        print(f"\nWrote cross-model Jaccard report to {jpath}")
        for api in jrep.get("apis", []):
            if api.get("skipped"):
                continue
            print(f"\n--- Jaccard {api.get('api_slug')} ---")
            for row in api.get("pairwise_global_union_jaccard", []):
                print(
                    f"  {row.get('model_a')} vs {row.get('model_b')}: Jaccard={row.get('jaccard')}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
