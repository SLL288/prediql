#!/usr/bin/env python3
"""Seed baseline tool results as runs the Baselines page can render.

The operation-level (node) coverage for Burp only (ZAP/EvoMaster/GraphQLer are computed from saved responses by their own import scripts) is
taken from PrediQL v1's published comparison (Table IV). That metric is exactly
the new engine's ``operation_coverage`` (|operations with >=1 valid response| /
|operations|), so it is directly comparable to the imported PrediQL runs.

Element and field-path coverage are **response-grounded** and cannot be
recovered from a published percentage — they are left ``null`` ("needs a logged
run"). To fill them, replay a tool's queries through PrediQL2's own GraphQL
target and fold the responses through ``prediql.model.coverage`` (see the
Baselines page note / scripts/replay_graphqler.py once a GraphQLer run exists).

Each baseline is written as a coverage-only run tagged
``providers.generator = "baseline:<tool>"`` and ``config.tool_kind = "baseline"``.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# PrediQL v1 Table IV — operation-level node coverage (%). None = FAILED (tool
# could not run the API), kept distinct from 0.0 (ran, covered nothing).
TABLE_IV: dict[str, dict[str, float | None]] = {
    #  alias          zap     burp    evomaster  graphqler
    "userwallet":   {"burp":  7.69},
    "countries":    {"burp": 50.00},
    "rickandmorty": {"burp":  0.00},
    "graphqlzero":  {"burp": 93.75},
    "ehri":         {"burp":  0.00},
    "tcgdex":       {"burp": 33.33},
    "pokeapi":      {"burp": None},
}

TARGET = {
    "userwallet": "http://localhost:8080/graphql",
    "countries": "https://countries.trevorblades.com/graphql",
    "rickandmorty": "https://rickandmortyapi.com/graphql",
    "graphqlzero": "https://graphqlzero.almansi.me/api",
    "ehri": "https://portal.ehri-project.eu/api/graphql",
    "tcgdex": "https://api.tcgdex.net/v2/graphql",
    "pokeapi": "https://beta.pokeapi.co/graphql/v1beta",
}

SOURCE = "PrediQL v1 Table IV (operation-level node coverage)"


def write_baseline(runs_root: Path, alias: str, tool: str, op_pct: float | None) -> str:
    rid = f"{alias}__{tool}"
    out = runs_root / rid
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    failed = op_pct is None
    coverage = {
        "operation_coverage": None if failed else round(op_pct / 100, 4),
        "element_coverage": None,       # response-grounded; needs a logged run
        "field_path_coverage": None,
        "source": SOURCE,
        "failed": failed,
    }
    (out / "artifacts" / "coverage.json").write_text(json.dumps(coverage, indent=2))
    manifest = {
        "run_id": rid,
        "config": {
            "target": TARGET.get(alias, ""),
            "alias": alias,
            "trial": 1,
            "mode": "coverage",
            "providers": {"generator": f"baseline:{tool}"},
            "tool_kind": "baseline",
            "baseline_source": SOURCE,
        },
        "plan": ["cover"],
        "started_at": "2026-01-01T00:00:00Z",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    reason = "failed" if failed else "completed"
    events = [{"seq": 1, "event": "run_start", "mode": "coverage", "plan": ["cover"]},
              {"seq": 2, "event": "run_finish", "reason": reason}]
    (out / "journal.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return rid


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-root", default=REPO / "runs", type=Path)
    args = ap.parse_args()
    args.runs_root.mkdir(parents=True, exist_ok=True)
    n = 0
    for alias, tools in TABLE_IV.items():
        for tool, pct in tools.items():
            rid = write_baseline(args.runs_root, alias, tool, pct)
            n += 1
            shown = "FAILED" if pct is None else f"{pct:.2f}%"
            print(f"  {rid:<28} op={shown}")
    print(f"\nSeeded {n} baseline runs (operation metric; element/field-path = null). "
          f"-> {args.runs_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
