#!/usr/bin/env python3
"""Import PrediQL v1 ``output/`` coverage runs into the PrediQL2 ``runs/`` layout.

Fully offline. For each old run it re-parses the saved introspection and the
stored query/response pairs through the **same** coverage logic the live
pipeline uses (``prediql.model.coverage``), then writes a coverage-only run the
dashboard can render: ``manifest.json`` + ``journal.jsonl`` + ``artifacts/coverage.json``.
No network, no LLM, no API key.

The four v1 ablation modes (prediql, -base, -aqg, -scl) are kept distinct by
folding the ablation tag into the run alias, so each is its own labelled run
(the engine's own run-id deliberately collapses mode/steps, which would merge them).

Usage:
    python scripts/import_v1_runs.py --v1 /path/to/prediql/output [--depth 5] [--dry-run]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Iterator

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from prediql.model.coverage import CoverageState  # noqa: E402
from prediql.model.schema import from_introspection  # noqa: E402

MODE_TAG = {
    "prediql": "full",
    "prediql-base": "base",
    "prediql-aqg": "aqg",
    "prediql-scl": "scl",
}

# Known host-dir -> (friendly alias, reconstructed target URL).
KNOWN = {
    "countries.trevorblades.com": ("countries", "https://countries.trevorblades.com/graphql"),
    "portal.ehri-project.eu_api_graphql": ("ehri", "https://portal.ehri-project.eu/api/graphql"),
    "rickandmortyapi.com_graphql": ("rickandmorty", "https://rickandmortyapi.com/graphql"),
    "graphqlzero.almansi.me_api": ("graphqlzero", "https://graphqlzero.almansi.me/api"),
    "api.tcgdex.net_v2_graphql": ("tcgdex", "https://api.tcgdex.net/v2/graphql"),
    "beta.pokeapi.co_graphql_v1beta": ("pokeapi", "https://beta.pokeapi.co/graphql/v1beta"),
    "DVGA": ("dvga", "http://localhost:5013/graphql"),
    "wallet": ("userwallet", "http://localhost:8080/graphql"),
    "UserWallet": ("userwallet", "http://localhost:8080/graphql"),
}

# The five v1 OpenRouter model directories that belong in the dataset. Legacy
# local runs (e.g. ``llama3.1_8b``) are pruned unless ``--include-extras`` is set.
VALID_MODEL_DIRS = {
    "deepseek_deepseek-v4-flash",
    "google_gemini-3.1-flash-lite",
    "meta-llama_llama-3.1-8b-instruct",
    "openai_gpt-5.4-nano",
    "qwen_qwen3-32b",
}

# Field-path coverage enumerates the reachable set at depth D; on a very large
# schema (PokeAPI ~2000 types) that is expensive, so it is time-boxed and the
# cheaper operation/element metrics (what the dashboard shows) are always kept.
FIELD_PATH_TIMEOUT_S = 90


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


def alias_and_target(host_dir: str) -> tuple[str, str]:
    if host_dir in KNOWN:
        return KNOWN[host_dir]
    alias = host_dir.lower().replace("_", "-").replace(".", "-")
    target = "https://" + host_dir.replace("_", "/")
    return alias, target


def model_ref(model_dir: str) -> str:
    """``deepseek_deepseek-v4-flash`` -> ``openrouter:deepseek/deepseek-v4-flash``."""
    slug = model_dir.replace("_", "/", 1) if "_" in model_dir else model_dir
    return f"openrouter:{slug}"


def _is_extra(host_dir: str, model_dir: str) -> bool:
    """A run outside the core dataset: a non-API host (localhost/pentest-ground,
    the mislabelled ``wrong-pke``) or a legacy/local model directory."""
    if host_dir not in KNOWN:
        return True
    return model_dir not in VALID_MODEL_DIRS


def find_runs(v1_output: Path, include_extras: bool = False) -> Iterator[tuple[str, str, str, Path]]:
    """Yield (mode, host_dir, model_dir, run_path) for every v1 run directory.

    A run directory is any dir holding both ``introspection_result.json`` and a
    ``nodes/`` subdir, which is robust to the two nesting shapes v1 produced.
    Runs outside the core dataset are skipped unless ``include_extras`` is set.
    """
    for mode in MODE_TAG:
        mode_root = v1_output / mode
        if not mode_root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(mode_root):
            p = Path(dirpath)
            if "introspection_result.json" in filenames and (p / "nodes").is_dir():
                rel = p.relative_to(mode_root).parts
                host_dir = rel[0] if rel else p.parent.name
                model_dir = p.name
                dirnames[:] = []  # do not descend into a run's own subtree
                if not include_extras and _is_extra(host_dir, model_dir):
                    continue
                yield mode, host_dir, model_dir, p


def successful_responses(run_path: Path) -> Iterator[tuple[str, str, dict]]:
    """Yield (operation, query_document, response_data) for each successful coverage call."""
    nodes = run_path / "nodes"
    for node in sorted(nodes.iterdir()):
        if not node.is_dir():
            continue
        for qf in sorted(node.glob("*queries*.json")):
            try:
                entries = json.loads(qf.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(entries, list):
                continue
            for e in entries:
                if e.get("vulnerability_type") != "basic_call" or not e.get("success"):
                    continue
                doc = (e.get("query") or {}).get("query")
                data = (e.get("response_body") or {}).get("data")
                if doc and isinstance(data, dict):
                    yield node.name, doc, data


def build_coverage(schema, responses, depth: int) -> dict[str, Any]:
    cov = CoverageState(depth=depth)
    folded = 0
    for op, doc, data in responses:
        try:
            cov.observe(op, doc, data)
            folded += 1
        except Exception:
            continue  # a single malformed document must not sink the run
    # Cheap, always-available metrics (these are what the dashboard reads).
    report = {
        "depth": depth,
        "operation_coverage": round(cov.operation_coverage(schema), 4),
        "element_coverage": round(cov.element_coverage(schema), 4),
        "operations_covered": len(cov.covered_operations()),
        "operations_total": len(schema.operations),
        "by_operation": {op: sorted(p) for op, p in sorted(cov.by_operation.items()) if p},
        "_responses_folded": folded,
    }
    from prediql.model.coverage import (
        count_reachable_paths,
        covered_schema_elements,
        total_schema_elements,
    )
    elements = covered_schema_elements(schema, cov.all_paths(), depth=depth)
    report["elements_covered"] = len(elements)
    report["elements_total"] = total_schema_elements(schema)
    # Depth-bounded field-path coverage, time-boxed for huge schemas.
    try:
        with _time_boxed(FIELD_PATH_TIMEOUT_S):
            total = count_reachable_paths(schema, depth=depth)
            covered = cov._covered_reachable(schema)
        report["field_paths_reachable"] = total
        report["field_paths_covered"] = covered
        report["field_path_coverage"] = round(covered / total, 8) if total else 0.0
    except (_Timeout, Exception):
        report["field_paths_reachable"] = None
        report["field_paths_covered"] = None
        report["field_path_coverage"] = None
    return report


def run_id_for(alias: str, model_dir: str, host_dir: str, mode: str) -> str:
    h = hashlib.sha256(f"{mode}|{host_dir}|{model_dir}".encode()).hexdigest()[:12]
    return f"{alias}__t1__{h}"


def write_run(runs_root: Path, mode: str, host_dir: str, model_dir: str,
              run_path: Path, depth: int) -> dict[str, Any] | None:
    raw = json.loads((run_path / "introspection_result.json").read_text(encoding="utf-8"))
    schema = from_introspection(raw)
    if not schema.operations:
        return None
    coverage = build_coverage(schema, successful_responses(run_path), depth)

    base_alias, target = alias_and_target(host_dir)
    tag = MODE_TAG[mode]
    alias = f"{base_alias}-{tag}"
    rid = run_id_for(alias, model_dir, host_dir, mode)
    out = runs_root / rid
    (out / "artifacts").mkdir(parents=True, exist_ok=True)

    (out / "artifacts" / "coverage.json").write_text(json.dumps(coverage, indent=2))

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime((run_path / "introspection_result.json").stat().st_mtime))
    plan = ["introspect", "compile", "seed_identities", "cover", "validate"]
    manifest = {
        "run_id": rid,
        "config": {
            "target": target,
            "alias": alias,
            "trial": 1,
            "mode": "coverage",
            "steps": [],
            "providers": {"generator": model_ref(model_dir)},
            "identities": [{"name": "anon", "role": "anonymous", "header_keys": []}],
            "families": [],
            "graph_backend": "native",
            "allow_destructive": False,
            "strategy": {
                "arms": [], "rounds": 5, "requests_per_operation": 5, "seed": 42,
                "temperature": 0.0, "coverage_depth": depth, "judge_samples": 1,
                "max_operations": None,
            },
            "ablation": tag,
            "imported_from": str(run_path),
        },
        "budgets": {"max_tokens": None, "max_usd": None},
        "plan": plan,
        "started_at": started,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    cover_metrics = {
        "operation_coverage": coverage["operation_coverage"],
        "element_coverage": coverage["element_coverage"],
        "operations_covered": coverage["operations_covered"],
        "operations_total": coverage["operations_total"],
        "elements_covered": coverage["elements_covered"],
        "elements_total": coverage["elements_total"],
        "requests": coverage["_responses_folded"],
    }
    note = (f"{coverage['operations_covered']}/{coverage['operations_total']} operations, "
            f"element coverage {coverage['element_coverage']:.1%}")
    events = [
        {"seq": 1, "event": "run_start", "mode": "coverage", "plan": plan, "forced": []},
    ]
    for i, step in enumerate(plan, start=2):
        metrics = cover_metrics if step == "cover" else {}
        events.append({"seq": i, "event": "step_finish", "step": step, "outcome": "ok",
                       "produces": [], "seconds": 0.0, "metrics": metrics,
                       "note": note if step == "cover" else "imported"})
    events.append({"seq": len(plan) + 2, "event": "step_progress", "step": "cover",
                   "phase": "coverage", "round": 5, "total_rounds": 5,
                   "covered": coverage["operations_covered"],
                   "total": coverage["operations_total"]})
    events.append({"seq": len(plan) + 3, "event": "run_finish", "reason": "completed",
                   "budget": {"calls": 0, "total_tokens": 0, "usd": 0.0, "wall_seconds": 0.0}})
    with (out / "journal.jsonl").open("w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")

    return {"run_id": rid, "alias": alias, "model": model_ref(model_dir),
            "op_cov": coverage["operation_coverage"], "el_cov": coverage["element_coverage"],
            "fp_cov": coverage["field_path_coverage"], "folded": coverage["_responses_folded"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--v1", required=True, type=Path, help="v1 output/ directory")
    ap.add_argument("--runs-root", default=REPO / "runs", type=Path)
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--include-extras", action="store_true",
                    help="also import non-core hosts (localhost/pentest/wrong-pke) and legacy models")
    args = ap.parse_args()

    found = list(find_runs(args.v1, include_extras=args.include_extras))
    print(f"Discovered {len(found)} v1 run director{'y' if len(found)==1 else 'ies'}")
    if args.dry_run:
        for mode, host, model, path in found:
            base_alias, _ = alias_and_target(host)
            print(f"  [{MODE_TAG[mode]:>4}] {base_alias:<14} {model_ref(model):<42} <- {path}")
        return 0

    args.runs_root.mkdir(parents=True, exist_ok=True)
    ok = skipped = 0
    for mode, host, model, path in found:
        try:
            res = write_run(args.runs_root, mode, host, model, path, args.depth)
        except Exception as exc:  # one bad run must not abort the batch
            print(f"  SKIP {mode}/{host}/{model}: {type(exc).__name__}: {exc}")
            skipped += 1
            continue
        if res is None:
            print(f"  SKIP {mode}/{host}/{model}: no operations in schema")
            skipped += 1
            continue
        ok += 1
        fp = "n/a" if res["fp_cov"] is None else f"{res['fp_cov']:.4f}"
        print(f"  OK  {res['alias']:<16} {res['model']:<42} "
              f"op={res['op_cov']:.3f} el={res['el_cov']:.3f} fp={fp} "
              f"({res['folded']} responses)")
    print(f"\nImported {ok} runs, skipped {skipped}. -> {args.runs_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
