"""Step: fetch and normalize the target schema."""

from __future__ import annotations

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.errors import StepError
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.model.schema import from_introspection


@register
class IntrospectStep(Step):
    name = "introspect"
    produces = frozenset({A.SCHEMA_RAW, A.SCHEMA})
    cost_class = "io"
    description = "Fetch the schema by introspection and normalize it."

    def config_signature(self, ctx: RunContext) -> dict:
        # Re-introspecting a different endpoint must invalidate everything below.
        return {"target": ctx.config.target_url}

    async def run(self, ctx: RunContext) -> StepResult:
        target = ctx.services["target"]
        identity = ctx.config.identities[0]

        async with ctx.limiter.http:
            raw = await target.introspect(identity)

        schema = from_introspection(raw)
        if not schema.operations:
            raise StepError(self.name, "introspection returned no operations")

        return StepResult(
            artifacts={A.SCHEMA_RAW: raw, A.SCHEMA: schema.to_dict()},
            metrics={
                "operations": len(schema.operations),
                "types": len(schema.types),
                "queries": len(schema.operations_of("query")),
                "mutations": len(schema.operations_of("mutation")),
            },
            note=f"{len(schema.operations)} operations, {len(schema.types)} types",
        )
