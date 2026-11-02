"""Step: execute synthesized chains and record the outcomes (doc 02 §4).

Blocked chains (unmet preconditions) are recorded as coverage gaps, never run.
Runnable chains are executed under their identities and judged by the disclosure
oracle; the results are emitted as ``chain_results`` for ``adjudicate`` to fold
into findings alongside the single-operation probe results.
"""

from __future__ import annotations

from typing import Any

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.model.bucket import ObjectsBucket
from prediql.model.schema import Schema
from prediql.security.chain_exec import execute_chain
from prediql.security.chains import ChainPlan


@register
class ExecuteChainsStep(Step):
    name = "execute_chains"
    requires = frozenset({A.SCHEMA, A.CHAINS, A.IDENTITIES})
    produces = frozenset({A.CHAIN_RESULTS})
    parallelizable = True
    cost_class = "io"
    description = "Run IDOR/UAF chains and judge disclosure."

    def config_signature(self, ctx: RunContext) -> dict:
        return {"allow_destructive": ctx.config.allow_destructive}

    async def run(self, ctx: RunContext) -> StepResult:
        schema = Schema.from_dict(ctx.get(A.SCHEMA))
        plans = [ChainPlan.from_dict(p) for p in (ctx.get(A.CHAINS) or {}).get("chains", [])]
        bucket = ObjectsBucket.from_dict(ctx.get(A.BUCKET) or {})
        target = ctx.services["target"]
        identity_for_role = self._role_map(ctx)

        async def sender(document: str, identity_name: str):
            identity = ctx.config.identity(identity_name)
            return await target.send(document, identity)

        runnable = [p for p in plans if not p.blocked]
        results: list[dict[str, Any]] = []
        confirmed = 0
        blocked = len(plans) - len(runnable)

        async def run_one(plan: ChainPlan) -> None:
            nonlocal confirmed
            outcome = await execute_chain(
                plan, schema, sender=sender,
                identity_for_role=identity_for_role, bucket=bucket,
            )
            row = outcome.to_probe_result()
            results.append(row)
            if row["verdict"] == "confirmed":
                confirmed += 1

        outcomes = await ctx.limiter.map(run_one, runnable, slot="http")
        errors = [str(o) for o in outcomes if isinstance(o, BaseException)]
        for message in errors:
            ctx.progress(self.name, error=message)

        return StepResult(
            artifacts={A.CHAIN_RESULTS: {
                "results": results,
                "runnable": len(runnable),
                "blocked": blocked,
            }},
            metrics={
                "executed": len(runnable),
                "confirmed": confirmed,
                "blocked": blocked,
                "errors": len(errors),
            },
            note=f"{confirmed} chain findings from {len(runnable)} chains ({blocked} blocked)",
        )

    def _role_map(self, ctx: RunContext) -> dict[str, str]:
        """Map chain roles (primary/secondary) to concrete identity names.

        Primary is the first usable identity; secondary the next distinct one.
        """
        usable = [i["name"] for i in (ctx.get(A.IDENTITIES) or []) if i.get("usable")]
        if not usable:
            usable = [ctx.config.identities[0].name]
        primary = usable[0]
        secondary = usable[1] if len(usable) > 1 else usable[0]
        return {"primary": primary, "secondary": secondary}
