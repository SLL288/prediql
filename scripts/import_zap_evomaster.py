#!/usr/bin/env python3
"""Compute ZAP and EvoMaster element/field-path coverage from the GraphQLer
Zenodo artifact, in PrediQL's own metric.

Both tools save enough to recover response-grounded coverage offline:

* **ZAP** — ``zap/<api>/run_N/messages.json`` holds every HTTP message with the
  request body (the GraphQL query) and the response body, so we fold them through
  the pipeline's real ``covered_paths(document, data)`` — identical to PrediQL.
* **EvoMaster** — ``evomaster/<api>/run_N/*successes_Test.py`` encodes what each
  call returned as assertions (``res.json()["data"]["countries"][0]["continent"]
  ["code"] == "EU"``). Each such access chain *is* a covered field path, so we
  extract them directly.

The schema (needed for the element/field-path denominators) is taken from the
GraphQLer coverage artifact's ``introspection_result.json`` for the same API.
Burp is not in the archive, so it is not imported here.

Usage:
    python scripts/import_zap_evomaster.py \
        --data <.../test_coverage/data>   # dir with zap/, evomaster/, graphqler/
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import signal
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from prediql.model.coverage import (  # noqa: E402
    CoverageState, count_reachable_paths, covered_paths,
    covered_schema_elements, total_schema_elements,
)
from prediql.model.schema import from_introspection  # noqa: E402

ALIAS = {
    "countries": "countries", "ehri-project": "ehri", "graphqlzero": "graphqlzero",
    "pokeapi": "pokeapi", "rickandmorty": "rickandmorty", "tcgdex": "tcgdex",
    "user-wallet": "userwallet",
    "food-delivery": "fooddelivery", "json-graphql": "jsongraphql", "anilist": "anilist",
}
DEPTH = 5
TIMEOUT_S = 120


class _Timeout(Exception):
    pass


def _time_boxed(seconds: int):
    def handler(signum, frame):
        raise _Timeout()
    class _Ctx:
        def __enter__(self):
            if hasattr(signal, "SIGALRM"):
                signal.signal(signal.SIGALRM, handler); signal.alarm(seconds)
        def __exit__(self, *a):
            if hasattr(signal, "SIGALRM"):
                signal.alarm(0)
            return False
    return _Ctx()


def load_schema(graphqler_api_dir: Path):
    for run in sorted(graphqler_api_dir.glob("run_*")):
        intro = run / "introspection_result.json"
        if intro.exists():
            return from_introspection(json.loads(intro.read_text(encoding="utf-8")))
    return None


def _with_prefixes(path: str) -> set[str]:
    """A covered leaf path implies its composite ancestors are covered too."""
    parts = path.split(".")
    return {".".join(parts[:i]) for i in range(1, len(parts) + 1)}


def _bucket(cov: CoverageState, op_names: set[str], paths: set[str]) -> bool:
    kept = False
    for p in paths:
        root = p.split(".", 1)[0]
        if root in op_names:
            cov.by_operation.setdefault(root, set()).add(p)
            kept = True
    return kept


# -- ZAP --------------------------------------------------------------------

def zap_paths(messages_file: Path, cov: CoverageState, op_names: set[str]) -> int:
    raw = json.loads(messages_file.read_text(encoding="utf-8"))
    msgs = raw.get("messages", raw)
    if isinstance(msgs, str):
        msgs = ast.literal_eval(msgs)
    folded = 0
    for m in msgs:
        try:
            req = json.loads(m.get("requestBody") or "{}")
            doc = req.get("query")
            resp = json.loads(m.get("responseBody") or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        if not doc or resp.get("errors") or not isinstance(resp.get("data"), dict):
            continue
        paths = covered_paths(doc, resp["data"])     # pipeline's own routine
        if _bucket(cov, op_names, paths):
            folded += 1
    return folded


# -- EvoMaster --------------------------------------------------------------

_ACCESS = re.compile(r'\.json\(\)\["data"\]((?:\[(?:"[^"]*"|\d+)\])+)')
_KEY = re.compile(r'\["([^"]+)"\]')

def evomaster_paths(test_file: Path, cov: CoverageState, op_names: set[str]) -> int:
    text = test_file.read_text(encoding="utf-8", errors="replace")
    paths: set[str] = set()
    for chain in _ACCESS.findall(text):
        keys = _KEY.findall(chain)          # string keys only; [0]/[1] indices dropped
        if keys:
            paths |= _with_prefixes(".".join(keys))
    return 1 if _bucket(cov, op_names, paths) else 0


# -- shared -----------------------------------------------------------------

def finalize(cov: CoverageState, schema, folded: int, source: str) -> dict:
    rep = {
        "depth": DEPTH,
        "operation_coverage": round(cov.operation_coverage(schema), 4),
        "element_coverage": round(cov.element_coverage(schema), 4),
        "operations_covered": len(cov.covered_operations()),
        "operations_total": len(schema.operations),
        "elements_covered": len(covered_schema_elements(schema, cov.all_paths(), depth=DEPTH)),
        "elements_total": total_schema_elements(schema),
        "by_operation": {op: sorted(p) for op, p in sorted(cov.by_operation.items()) if p},
        "source": source,
        "_responses_folded": folded,
    }
    try:
        with _time_boxed(TIMEOUT_S):
            total = count_reachable_paths(schema, depth=DEPTH)
            covered = cov._covered_reachable(schema)
        rep["field_paths_reachable"] = total
        rep["field_paths_covered"] = covered
        rep["field_path_coverage"] = round(covered / total, 8) if total else 0.0
    except (_Timeout, Exception):
        rep["field_paths_reachable"] = rep["field_paths_covered"] = None
        rep["field_path_coverage"] = None
    return rep


def write_run(runs_root: Path, tool: str, alias: str, trial: int, cov: dict, src: Path) -> str:
    rid = f"{alias}__{tool}__r{trial}"
    out = runs_root / rid
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    (out / "artifacts" / "coverage.json").write_text(json.dumps(cov, indent=2))
    (out / "manifest.json").write_text(json.dumps({
        "run_id": rid,
        "config": {"target": "", "alias": alias, "trial": trial, "mode": "coverage",
                   "providers": {"generator": f"baseline:{tool}"},
                   "tool_kind": "baseline", "baseline_source": cov["source"],
                   "imported_from": str(src)},
        "plan": ["cover"], "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2))
    (out / "journal.jsonl").write_text(
        json.dumps({"seq": 1, "event": "run_start", "mode": "coverage", "plan": ["cover"]}) + "\n"
        + json.dumps({"seq": 2, "event": "run_finish", "reason": "completed"}) + "\n")
    return rid


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, type=Path,
                    help="test_coverage/data dir (has zap/, evomaster/, graphqler/)")
    ap.add_argument("--runs-root", default=REPO / "runs", type=Path)
    args = ap.parse_args()
    gql_root = args.data / "graphqler"

    def schema_for(api_dir_name: str):
        d = gql_root / api_dir_name
        return load_schema(d) if d.is_dir() else None

    ok = skipped = 0
    for tool, subdir, source, runner in [
        ("zap", "zap", "GraphQLer Zenodo artifact v8 (ZAP messages.json)", "zap"),
        ("evomaster", "evomaster", "GraphQLer Zenodo artifact v8 (EvoMaster successes tests)", "evo"),
    ]:
        root = args.data / subdir
        if not root.is_dir():
            continue
        for api_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            alias = ALIAS.get(api_dir.name)
            if alias is None:
                continue
            schema = schema_for(api_dir.name)
            if schema is None or not schema.operations:
                skipped += 1
                continue
            op_names = set(schema.operations)
            for i, run_dir in enumerate(sorted(d for d in api_dir.glob("run_*") if d.is_dir()), 1):
                cov = CoverageState(depth=DEPTH)
                try:
                    if runner == "zap":
                        mf = run_dir / "messages.json"
                        if not mf.exists():
                            skipped += 1; continue
                        folded = zap_paths(mf, cov, op_names)
                    else:
                        tests = list(run_dir.glob("*successes_Test.py"))
                        if not tests:
                            skipped += 1; continue
                        folded = sum(evomaster_paths(t, cov, op_names) for t in tests)
                except Exception as exc:
                    print(f"  SKIP {tool}/{api_dir.name}/{run_dir.name}: {type(exc).__name__}: {exc}")
                    skipped += 1; continue
                rep = finalize(cov, schema, folded, source)
                write_run(args.runs_root, tool, alias, i, rep, run_dir)
                ok += 1
                fp = "n/a" if rep["field_path_coverage"] is None else f"{rep['field_path_coverage']:.4f}"
                print(f"  OK  {tool:<9} {alias:<13} r{i:<2} op={rep['operation_coverage']:.3f} "
                      f"el={rep['element_coverage']:.3f} fp={fp} ({folded} resp)")
    print(f"\nImported {ok} ZAP/EvoMaster runs, skipped {skipped}. -> {args.runs_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
