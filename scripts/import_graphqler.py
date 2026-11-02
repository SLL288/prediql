#!/usr/bin/env python3
"""Import GraphQLer coverage runs (Zenodo artifact) into PrediQL2's runs/ as
`baseline:graphqler` runs, computed with the **same** coverage logic PrediQL uses.

Input: the extracted ``test_coverage/data/graphqler/`` tree from the GraphQLer
Zenodo artifact — ``<api>/run_N/{introspection_result.json, unique_responses.txt,
stats.json}``. GraphQLer saves every unique response body in ``unique_responses.txt``
(a ``Response:`` line with a Python-dict repr, then an ``Endpoints:`` line), so
element/field-path coverage is recoverable offline, with no re-run.

We fold each successful response through the pipeline's own ``_returned_paths``
(the exact routine behind ``covered_paths``), keep only paths rooted at a real
schema operation (GraphQLer sometimes aliases the root as ``s``; those responses
carry no data anyway), and report via the same ``CoverageState`` the engine
writes — so GraphQLer and PrediQL are measured by identical code.

Usage:
    python scripts/import_graphqler.py --src <.../test_coverage/data/graphqler>
"""
from __future__ import annotations

import argparse
import ast
import json
import signal
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from prediql.model.coverage import (  # noqa: E402
    CoverageState,
    _returned_paths,
    count_reachable_paths,
)
from prediql.model.schema import from_introspection  # noqa: E402

# GraphQLer's API dir name -> PrediQL alias. Only APIs PrediQL also tested are
# imported, so the Baselines matrix lines up; extras (anilist, universe, …) are
# skipped (no PrediQL counterpart).
ALIAS = {
    "countries": "countries",
    "ehri-project": "ehri",
    "graphqlzero": "graphqlzero",
    "pokeapi": "pokeapi",
    "rickandmorty": "rickandmorty",
    "tcgdex": "tcgdex",
    "user-wallet": "userwallet",
    # Extensions toward GraphQLer's public set (now have PrediQL counterparts).
    "food-delivery": "fooddelivery",
    "json-graphql": "jsongraphql",
    "anilist": "anilist",
}
DEPTH = 5
FIELD_PATH_TIMEOUT_S = 120
SOURCE = "GraphQLer Zenodo artifact v8 (test_coverage, unique_responses)"


class _Timeout(Exception):
    pass


def _time_boxed(seconds: int):
    def handler(signum, frame):
        raise _Timeout()
    class _Ctx:
        def __enter__(self):
            if hasattr(signal, "SIGALRM"):
                signal.signal(signal.SIGALRM, handler)
                signal.alarm(seconds)
        def __exit__(self, *a):
            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)
            return False
    return _Ctx()


def parse_unique_responses(path: Path):
    """Yield each response dict from a unique_responses.txt file."""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("Response: "):
            continue
        try:
            obj = ast.literal_eval(line[len("Response: "):])
        except (ValueError, SyntaxError):
            continue
        if isinstance(obj, dict):
            yield obj


def coverage_for_run(run_dir: Path) -> dict | None:
    intro = run_dir / "introspection_result.json"
    uniq = run_dir / "unique_responses.txt"
    if not intro.exists() or not uniq.exists():
        return None
    schema = from_introspection(json.loads(intro.read_text(encoding="utf-8")))
    if not schema.operations:
        return None
    op_names = set(schema.operations)   # dict keyed by operation name

    # GraphQLer's own (lax) operation coverage, for the old-metric column and to
    # show the lax-vs-strict gap. It counts an op covered on any HTTP-200 success,
    # even when the payload is null/empty.
    reported = None
    successes = failures = None
    stats_path = run_dir / "stats.json"
    if stats_path.exists():
        try:
            st = json.loads(stats_path.read_text(encoding="utf-8"))
            reported = (st.get("operation_coverage") or {}).get("rate")
            successes = st.get("number_of_successes")
            failures = st.get("number_of_failures")
        except (json.JSONDecodeError, OSError):
            pass

    cov = CoverageState(depth=DEPTH)
    folded = 0
    for resp in parse_unique_responses(uniq):
        if resp.get("errors") or "data" not in resp:
            continue
        data = resp.get("data")
        if not isinstance(data, dict):
            continue
        out: set[str] = set()
        _returned_paths(data, (), {}, out, DEPTH_BUDGET)
        # Attribute paths to their root operation; drop aliased/non-schema roots.
        kept = False
        for p in out:
            root = p.split(".", 1)[0]
            if root in op_names:
                cov.by_operation.setdefault(root, set()).add(p)
                kept = True
        folded += 1 if kept else 0

    # operation + element coverage are cheap; field-path is time-boxed (PokeAPI).
    report = {
        "depth": DEPTH,
        "operation_coverage": round(cov.operation_coverage(schema), 4),
        "element_coverage": round(cov.element_coverage(schema), 4),
        "operations_covered": len(cov.covered_operations()),
        "operations_total": len(schema.operations),
        "by_operation": {op: sorted(p) for op, p in sorted(cov.by_operation.items()) if p},
        "operation_coverage_reported": reported,   # GraphQLer's own (lax) metric
        "graphqler_successes": successes,
        "graphqler_failures": failures,
        "source": SOURCE,
        "_responses_folded": folded,
    }
    from prediql.model.coverage import covered_schema_elements, total_schema_elements
    report["elements_covered"] = len(covered_schema_elements(schema, cov.all_paths(), depth=DEPTH))
    report["elements_total"] = total_schema_elements(schema)
    try:
        with _time_boxed(FIELD_PATH_TIMEOUT_S):
            total = count_reachable_paths(schema, depth=DEPTH)
            covered = cov._covered_reachable(schema)
        report["field_paths_reachable"] = total
        report["field_paths_covered"] = covered
        report["field_path_coverage"] = round(covered / total, 8) if total else 0.0
    except (_Timeout, Exception):
        report["field_paths_reachable"] = None
        report["field_paths_covered"] = None
        report["field_path_coverage"] = None
    return report


# ``_returned_paths`` takes a depth *budget*; match the metric's max_depth.
DEPTH_BUDGET = 20


def write_run(runs_root: Path, alias: str, trial: int, coverage: dict, src: Path) -> str:
    rid = f"{alias}__graphqler__r{trial}"
    out = runs_root / rid
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    (out / "artifacts" / "coverage.json").write_text(json.dumps(coverage, indent=2))
    manifest = {
        "run_id": rid,
        "config": {
            "target": "", "alias": alias, "trial": trial, "mode": "coverage",
            "providers": {"generator": "baseline:graphqler"},
            "tool_kind": "baseline", "baseline_source": SOURCE,
            "imported_from": str(src),
        },
        "plan": ["cover"],
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(src.stat().st_mtime)),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (out / "journal.jsonl").write_text(
        json.dumps({"seq": 1, "event": "run_start", "mode": "coverage", "plan": ["cover"]}) + "\n"
        + json.dumps({"seq": 2, "event": "run_finish", "reason": "completed"}) + "\n")
    return rid


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, type=Path,
                    help="extracted .../test_coverage/data/graphqler directory")
    ap.add_argument("--runs-root", default=REPO / "runs", type=Path)
    args = ap.parse_args()
    args.runs_root.mkdir(parents=True, exist_ok=True)

    ok = skipped = 0
    for api_dir in sorted(p for p in args.src.iterdir() if p.is_dir()):
        alias = ALIAS.get(api_dir.name)
        if alias is None:
            continue  # extra API with no PrediQL counterpart
        runs = sorted(d for d in api_dir.iterdir() if d.is_dir() and d.name.startswith("run_"))
        for i, run_dir in enumerate(runs, start=1):
            try:
                cov = coverage_for_run(run_dir)
            except Exception as exc:
                print(f"  SKIP {api_dir.name}/{run_dir.name}: {type(exc).__name__}: {exc}")
                skipped += 1
                continue
            if cov is None:
                skipped += 1
                continue
            write_run(args.runs_root, alias, i, cov, run_dir)
            ok += 1
            fp = "n/a" if cov["field_path_coverage"] is None else f"{cov['field_path_coverage']:.4f}"
            print(f"  OK  {alias:<14} r{i:<2} op={cov['operation_coverage']:.3f} "
                  f"el={cov['element_coverage']:.3f} fp={fp} ({cov['_responses_folded']} resp)")
    print(f"\nImported {ok} GraphQLer runs, skipped {skipped}. -> {args.runs_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
