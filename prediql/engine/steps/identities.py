"""Step: verify which auth profiles actually work against the target."""

from __future__ import annotations

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.targets.base import is_success

_PROBE = "query { __typename }"


@register
class SeedIdentitiesStep(Step):
    name = "seed_identities"
    produces = frozenset({A.IDENTITIES})
    cost_class = "io"
    description = "Probe each auth profile and record which are usable."

    def config_signature(self, ctx: RunContext) -> dict:
        return {"identities": [i.signature() for i in ctx.config.identities]}

    async def run(self, ctx: RunContext) -> StepResult:
        target = ctx.services["target"]
        live: list[dict] = []

        for identity in ctx.config.identities:
            async with ctx.limiter.http:
                result = await target.send(_PROBE, identity)
            usable = is_success(result) or result.status == 200
            live.append({
                "name": identity.name,
                "role": identity.role,
                "usable": usable,
                "status": result.status,
            })

        usable_names = [i["name"] for i in live if i["usable"]]
        return StepResult(
            artifacts={A.IDENTITIES: live},
            metrics={"total": len(live), "usable": len(usable_names)},
            # Chain strategies require >= 2 usable identities; surfacing the count
            # here is what lets plan_chains explain a skip instead of silently
            # producing nothing.
            note=f"{len(usable_names)}/{len(live)} usable: {', '.join(usable_names) or 'none'}",
        )
