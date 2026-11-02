"""Step: iterative security probing (doc 02 §3).

Fans out across (covered operation × applicable family) and drives each pair
through the refinement loop. Produces ``probe_results`` — the full trace of every
payload, verdict, and reasoning step — which the dashboard renders and
``adjudicate`` turns into findings.

Only *covered* operations are probed: an operation the fuzzer could never reach
with a valid request cannot host a meaningful injection, and probing it wastes
budget. Destructive operations are excluded here too, independently of the
``cover`` gate, so a probe never issues a DELETE with a real id.
"""

from __future__ import annotations

from typing import Any

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.model.coverage import CoverageState
from prediql.model.graph import Action, DependencyGraph
from prediql.model.schema import Schema
from prediql.oracle.evidence import Oracle
from prediql.security.loop import run_family
from prediql.security.registry import build_families


@register
class ProbeStep(Step):
    name = "probe"
    requires = frozenset({A.SCHEMA, A.GRAPH, A.COVERAGE, A.BASELINE, A.IDENTITIES})
    produces = frozenset({A.PROBE_RESULTS})
    parallelizable = True
    cost_class = "io"
    description = "Iteratively probe covered operations with applicable families."

    def config_signature(self, ctx: RunContext) -> dict:
        return {
            "families": list(ctx.config.families),
            "requests": ctx.config.strategy.requests_per_operation,
            "allow_destructive": ctx.config.allow_destructive,
        }

    async def run(self, ctx: RunContext) -> StepResult:
        schema = Schema.from_dict(ctx.get(A.SCHEMA))
        graph = DependencyGraph.from_dict(ctx.get(A.GRAPH) or {})
        coverage = CoverageState.from_dict(_coverage_state(ctx.get(A.COVERAGE)))
        baselines = ctx.get(A.BASELINE) or {}
        # Out-of-band collaborator: enables the near-zero-FP callback oracle for
        # blind SSRF and blind OS-command. Inert (not started) when unconfigured.
        oob = None
        if ctx.config.oob_host:
            from prediql.security.oob import OOBServer
            oob = OOBServer(host=ctx.config.oob_host).start()
        families = build_families(ctx.config.families, oob=oob, auth_args=ctx.config.auth_args)
        oracle = Oracle(oob=oob)
        target = ctx.services["target"]
        identity = self._probe_identity(ctx)
        budget = ctx.config.strategy.requests_per_operation

        covered = sorted(coverage.covered_operations())
        # Build the work list: one (operation, family) job per applicable pair.
        jobs: list[tuple[str, Any]] = []
        for op_name in covered:
            operation = schema.operations.get(op_name)
            if operation is None:
                continue
            if not ctx.config.allow_destructive and graph.actions.get(op_name) is Action.DELETE:
                continue
            for family in families:
                if family.applies(operation, schema, graph):
                    jobs.append((op_name, family))

        results: list[dict[str, Any]] = []
        confirmed = 0
        signals = 0
        done = 0
        jobs_total = len(jobs)

        def _tick() -> None:
            snap = ctx.ledger.snapshot()
            ctx.progress(
                self.name, phase="security",
                jobs_done=done, jobs_total=jobs_total,
                confirmed=confirmed, signals=signals, requests=len(results),
                tokens=snap["total"]["total_tokens"], usd=snap["total"]["usd"],
                budget_tokens=ctx.config.budgets.max_tokens,
                budget_usd=ctx.config.budgets.max_usd,
                consumed=snap["consumed_fraction"],
            )

        # Announce the work up front so the security bar appears immediately,
        # before the first probe returns.
        if jobs_total:
            _tick()

        async def probe_pair(job: tuple[str, Any]) -> None:
            nonlocal confirmed, signals, done
            op_name, family = job
            operation = schema.operations[op_name]

            async def executor(document: str):
                return await target.send(document, identity)

            outcome = await run_family(
                family, operation, schema,
                executor=executor, oracle=oracle, identity=identity.name,
                baseline=baselines.get(op_name), max_payloads=budget,
            )
            for result in outcome.results:
                results.append(result.to_dict())
            confirmed += len(outcome.confirmations)
            signals += len(outcome.signals)
            done += 1
            _tick()

        try:
            outcomes = await ctx.limiter.map(probe_pair, jobs, slot="http")
        finally:
            if oob is not None:
                oob.stop()   # callbacks arrive during the sends above, not after
        errors = [str(o) for o in outcomes if isinstance(o, BaseException)]
        for message in errors:
            ctx.progress(self.name, error=message)

        return StepResult(
            artifacts={A.PROBE_RESULTS: {
                "results": results,
                "jobs": len(jobs),
                "operations_probed": len({r["operation"] for r in results}),
                "families": [f.id for f in families],
                "oob": bool(oob),
            }},
            metrics={
                "jobs": len(jobs),
                "payloads": len(results),
                "confirmations": confirmed,
                "signals": signals,
                "errors": len(errors),
            },
            note=f"{confirmed} confirmed, {signals} signals across {len(jobs)} probes",
        )

    @staticmethod
    def _probe_identity(ctx: RunContext):
        live = {i["name"] for i in (ctx.get(A.IDENTITIES) or []) if i.get("usable")}
        for identity in ctx.config.identities:
            if identity.name in live:
                return identity
        return ctx.config.identities[0]


def _coverage_state(coverage: dict[str, Any] | None) -> dict[str, Any]:
    """Recover the CoverageState payload embedded in the coverage artifact."""
    coverage = coverage or {}
    return {"depth": coverage.get("depth", 5), "by_operation": coverage.get("by_operation", {})}
