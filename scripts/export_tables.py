#!/usr/bin/env python3
"""Export paper-ready tables (CSV + LaTeX) from the runs directory.

Produces the baseline comparison (tools x APIs, best run per tool) for each
coverage metric. Writes to an output dir; the LaTeX is a booktabs tabular ready
to \\input. Reruns (ablation, Fuzz4All) flow in automatically — just re-run this.

Usage:
    python scripts/export_tables.py [--out paper_tables]
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

RUNS = Path(__file__).resolve().parents[1] / "runs"
APIS = ["countries", "ehri", "graphqlzero", "pokeapi", "rickandmorty", "tcgdex", "userwallet", "dvga"]
TOOLS = ["zap", "burp", "evomaster", "graphqler", "fuzz4all", "prediql"]
LABEL = {"zap": "ZAP", "burp": "Burp", "evomaster": "EvoMaster", "graphqler": "GraphQLer",
         "fuzz4all": "Fuzz4All", "prediql": "PrediQL"}
METRICS = {"operation_coverage": "Operation", "element_coverage": "Element",
           "field_path_coverage": "Field-path"}


def _read(p: Path):
    try:
        return json.loads(p.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _rows():
    for d in RUNS.iterdir():
        if not d.is_dir():
            continue
        man = _read(d / "manifest.json")
        cov = _read(d / "artifacts" / "coverage.json")
        if not man or not cov:
            continue
        cfg = man.get("config", {})
        gen = (cfg.get("providers") or {}).get("generator", "")
        tool = gen.split(":", 1)[1] if gen.startswith("baseline:") else "prediql"
        alias, abl = cfg.get("alias", ""), cfg.get("ablation", "")
        api = alias[:-(len(abl) + 1)] if abl and alias.endswith(f"-{abl}") else alias
        # PrediQL: compare the full pipeline
        if tool == "prediql" and abl not in ("", "full", None):
            continue
        yield api, tool, cfg, cov


def best(metric: str) -> dict[tuple[str, str], float | None]:
    out: dict[tuple[str, str], float | None] = {}
    for api, tool, _cfg, cov in _rows():
        v = cov.get(metric)
        if v is None:
            continue
        k = (api, tool)
        out[k] = max(out.get(k, 0.0), v)
    return out


def fmt(v):
    return "--" if v is None else f"{v*100:.1f}"


def export(metric: str, out: Path) -> None:
    data = best(metric)
    apis = [a for a in APIS if any((a, t) in data for t in TOOLS)]
    tools = [t for t in TOOLS if any((a, t) in data for a in apis)]

    # CSV
    csv_path = out / f"baseline_{metric}.csv"
    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["API"] + [LABEL[t] for t in tools])
        for a in apis:
            w.writerow([a] + [fmt(data.get((a, t))) for t in tools])

    # LaTeX (booktabs), PrediQL and the row max in bold
    lines = [f"% {METRICS.get(metric, metric)} coverage (%), best run per tool. Auto-generated.",
             "\\begin{tabular}{l" + "r" * len(tools) + "}", "\\toprule",
             "API & " + " & ".join(LABEL[t] for t in tools) + " \\\\", "\\midrule"]
    for a in apis:
        vals = {t: data.get((a, t)) for t in tools}
        hi = max((v for v in vals.values() if v is not None), default=None)
        cells = []
        for t in tools:
            v = vals[t]
            s = fmt(v)
            if v is not None and hi is not None and abs(v - hi) < 1e-9:
                s = f"\\textbf{{{s}}}"
            cells.append(s)
        lines.append(f"{a} & " + " & ".join(cells) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    (out / f"baseline_{metric}.tex").write_text("\n".join(lines) + "\n")
    print(f"  {metric}: {csv_path.name}, baseline_{metric}.tex  "
          f"({len(apis)} APIs x {len(tools)} tools)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="paper_tables", type=Path)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    print(f"Exporting tables to {args.out}/")
    for metric in METRICS:
        export(metric, args.out)
    print("Done. Re-run after new sweeps to refresh.")


if __name__ == "__main__":
    main()
