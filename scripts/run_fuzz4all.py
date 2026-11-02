#!/usr/bin/env python3
"""A Fuzz4All-style LLM fuzzer adapted to GraphQL — an independent baseline.

Fuzz4All targets input *languages* for local binaries; it has no GraphQL/HTTP
mode. This is a faithful adaptation of its loop to a GraphQL endpoint, kept
deliberately distinct from PrediQL so it is a fair separate baseline:

  * autoprompt once from the schema (Fuzz4All's "documentation" input),
  * then iterate: the LLM generates a batch of queries, optionally *mutating* or
    *combining* previously valid ones (Fuzz4All's generate / mutate / combine
    strategies), with recent valid queries kept as in-context examples.

What it deliberately does NOT use (those are PrediQL's contributions): no
retrieval over observed typed values, no bandit arm selection, no coverage-reward
feedback into generation, no operation-local sub-schema. Coverage is measured
*externally* with the same CoverageState, so results are comparable and land as a
``baseline:fuzz4all`` run the dashboard reads.

Usage:
    python scripts/run_fuzz4all.py --target URL --alias NAME --model vendor:model \
        --run-id NAME__fuzz4all__r1 [--budget 20] [--batch 5] [--depth 5]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from prediql.engine.config import Identity  # noqa: E402
from prediql.model.coverage import CoverageState, covered_paths  # noqa: E402
from prediql.model.schema import from_introspection  # noqa: E402
from prediql.providers.base import LLMRequest  # noqa: E402
from prediql.providers.registry import build_provider  # noqa: E402
from prediql.targets.graphql import GraphQLTarget  # noqa: E402

ANON = Identity(name="anon", role="anonymous")
SYSTEM = (
    "You are a GraphQL fuzzer. Given a schema, emit diverse, syntactically valid "
    "GraphQL operations that exercise as many fields as possible. Output only the "
    "operations, each in its own ```graphql code block. No prose."
)
STRATEGIES = ["generate new operations that touch fields not yet tried",
              "mutate these example operations: deepen selections and vary arguments",
              "combine fields from several examples into new operations"]
_BLOCK = re.compile(r"```(?:graphql|gql)?\s*(.+?)```", re.DOTALL | re.IGNORECASE)


def extract_queries(text: str) -> list[str]:
    blocks = _BLOCK.findall(text)
    if not blocks:  # fall back to brace-balanced top-level operations
        blocks = re.findall(r"((?:query|mutation)?\s*\{.*?\})", text, re.DOTALL)
    out, seen = [], set()
    for b in blocks:
        q = b.strip()
        if q and q not in seen and "{" in q:
            seen.add(q); out.append(q)
    return out


def schema_digest(schema, limit: int = 120) -> str:
    """A compact schema description for the prompt (the 'documentation')."""
    lines = []
    for name, op in list(schema.operations.items())[:limit]:
        args = ", ".join(f"{a}: {t.name}" for a, t in op.args)
        lines.append(f"{op.kind} {name}({args}): {op.type.name}")
    return "\n".join(lines)


async def run(args) -> None:
    run_dir = Path(args.runs_root) / args.run_id
    (run_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    journal = (run_dir / "journal.jsonl").open("w", encoding="utf-8")
    seq = [0]

    def emit(event, **kw):
        seq[0] += 1
        journal.write(json.dumps({"seq": seq[0], "event": event, "ts": time.time(), **kw}) + "\n")
        journal.flush()

    emit("run_start", mode="fuzz4all", plan=["introspect", "cover"])
    # Minimal manifest up front so the dashboard sees the run while it is still
    # in flight (the engine writes its manifest at start too); the final write
    # below replaces it with the complete config and metrics.
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": args.run_id,
        "config": {"target": args.target, "alias": args.alias, "trial": args.trial,
                   "mode": "coverage", "providers": {"generator": "baseline:fuzz4all"},
                   "tool_kind": "baseline", "baseline_source": "fuzz4all",
                   "fuzz4all_model": args.model},
        "plan": ["introspect", "cover"],
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=2))
    target = GraphQLTarget(args.target)
    provider = build_provider(args.model)
    try:
        raw = await target.introspect(ANON)
        schema = from_introspection(raw)
        if not schema.operations:
            emit("run_finish", reason="no operations in schema"); return
        op_names = set(schema.operations)
        digest = schema_digest(schema)
        (run_dir / "artifacts" / "schema.raw.json").write_text(json.dumps(raw))

        cov = CoverageState(depth=args.depth)
        examples: list[str] = []
        sent = valid = 0
        for i in range(args.budget):
            strat = STRATEGIES[i % len(STRATEGIES)]
            ex = ("\n\n".join(f"```graphql\n{e}\n```" for e in examples[-3:])
                  if examples and i % len(STRATEGIES) != 0 else "")
            prompt = (f"GraphQL schema (operations):\n{digest}\n\n"
                      f"Task: {strat}. Produce {args.batch} operations.\n{ex}")
            try:
                # Generous token budget: a reasoning backbone (e.g. deepseek)
                # spends output tokens on hidden reasoning before emitting the
                # operations, and the 2048 default can be fully consumed by
                # reasoning on a larger schema — leaving empty content and zero
                # extracted queries. The budget is the harness's, not a PrediQL
                # advantage, so raising it keeps the baseline faithful.
                resp = await provider.complete(LLMRequest(
                    role="generator", prompt=prompt, system=SYSTEM, max_tokens=6000))
            except Exception as exc:
                emit("step_progress", step="cover", phase="fuzz4all", note=f"llm error: {exc}")
                continue
            for q in extract_queries(resp.text)[: args.batch]:
                res = await target.send(q, ANON)
                sent += 1
                body = res.body or {}
                if res.status == 200 and not body.get("errors") and isinstance(body.get("data"), dict):
                    data = body["data"]
                    if any(v is not None for v in data.values()):
                        valid += 1
                        if len(examples) < 50:
                            examples.append(q)
                        for p in covered_paths(q, data):
                            root = p.split(".", 1)[0]
                            if root in op_names:
                                cov.by_operation.setdefault(root, set()).add(p)
            emit("step_progress", step="cover", phase="fuzz4all", round=i + 1, total_rounds=args.budget,
                 covered=len(cov.covered_operations()), total=len(schema.operations),
                 requests=sent)

        report = cov.report(schema)
        report.update(source="Fuzz4All-style GraphQL baseline (independent loop)",
                      queries_sent=sent, queries_valid=valid)
        (run_dir / "artifacts" / "coverage.json").write_text(json.dumps(report, indent=2))
        (run_dir / "manifest.json").write_text(json.dumps({
            "run_id": args.run_id,
            "config": {"target": args.target, "alias": args.alias, "trial": args.trial,
                       "mode": "coverage", "providers": {"generator": "baseline:fuzz4all"},
                       "tool_kind": "baseline", "baseline_source": "fuzz4all",
                       "fuzz4all_model": args.model},
            "plan": ["introspect", "cover"],
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, indent=2))
        emit("step_finish", step="cover", outcome="ok", seconds=0.0,
             metrics={"operation_coverage": report["operation_coverage"],
                      "element_coverage": report["element_coverage"],
                      "queries_sent": sent, "queries_valid": valid},
             note=f"{report['operations_covered']}/{report['operations_total']} ops, "
                  f"element {report['element_coverage']:.1%}, {valid}/{sent} valid")
        emit("run_finish", reason="completed")
        print(f"fuzz4all {args.alias}: op={report['operation_coverage']:.3f} "
              f"el={report['element_coverage']:.3f} ({valid}/{sent} valid)")
    finally:
        journal.close()
        await target.aclose()
        await provider.aclose()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--alias", required=True)
    ap.add_argument("--model", required=True, help="vendor:model, e.g. openrouter:openai/gpt-5.4-nano")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--trial", type=int, default=1)
    ap.add_argument("--budget", type=int, default=20, help="LLM generation calls")
    ap.add_argument("--batch", type=int, default=5, help="queries requested per call")
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--runs-root", default=str(REPO / "runs"))
    args = ap.parse_args()
    asyncio.run(run(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
