"""Step: synthesize IDOR and UAF chains from the dependency graph (doc 02 §4)."""

from __future__ import annotations

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.model.graph import DependencyGraph
from prediql.model.schema import Schema
from prediql.security.chains import synthesize


@register
class PlanChainsStep(Step):
    name = "plan_chains"
    requires = frozenset({A.SCHEMA, A.GRAPH, A.IDENTITIES})
    produces = frozenset({A.CHAINS})
    cost_class = "cpu"
    description = "Synthesize IDOR and UAF chains from graph edges."

    def config_signature(self, ctx: RunContext) -> dict:
        return {"allow_destructive": ctx.config.allow_destructive}

    async def run(self, ctx: RunContext) -> StepResult:
        schema = Schema.from_dict(ctx.get(A.SCHEMA))
        graph = DependencyGraph.from_dict(ctx.get(A.GRAPH) or {})
        usable = [i["name"] for i in (ctx.get(A.IDENTITIES) or []) if i.get("usable")]

        plans = synthesize(
            graph, schema,
            usable_identities=usable,
            allow_destructive=ctx.config.allow_destructive,
        )
        runnable = [p for p in plans if not p.blocked]
        by_reason: dict[str, int] = {}
        for plan in plans:
            if plan.blocked:
                by_reason[plan.blocked] = by_reason.get(plan.blocked, 0) + 1

        return StepResult(
            artifacts={A.CHAINS: {
                "chains": [p.to_dict() for p in plans],
                "runnable": len(runnable),
                "blocked": {k: v for k, v in sorted(by_reason.items())},
            }},
            metrics={
                "total": len(plans),
                "runnable": len(runnable),
                "idor": sum(1 for p in plans if p.strategy == "idor"),
                "uaf": sum(1 for p in plans if p.strategy == "uaf"),
                "blocked_needs_identities": by_reason.get("needs_identities", 0),
                "blocked_needs_destructive": by_reason.get("needs_destructive", 0),
            },
            note=(f"{len(runnable)} runnable chains "
                  f"({len(plans) - len(runnable)} blocked)"),
        )
