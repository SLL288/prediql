"""Step: build the typed dependency graph."""

from __future__ import annotations

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.model.graph import Action, build_graph
from prediql.model.schema import Schema


@register
class CompileStep(Step):
    name = "compile"
    requires = frozenset({A.SCHEMA})
    produces = frozenset({A.GRAPH})
    cost_class = "cpu"
    description = "Infer operation/object dependency edges and action labels."

    def config_signature(self, ctx: RunContext) -> dict:
        # Resolution changes the graph, so a resolver provider is part of the
        # signature — configuring it invalidates and rebuilds the graph.
        return {"backend": ctx.config.graph_backend,
                "resolver": ctx.config.providers.get("resolver", "")}

    async def run(self, ctx: RunContext) -> StepResult:
        schema = Schema.from_dict(ctx.get(A.SCHEMA))
        graph = build_graph(schema)

        unknown = [op for op, action in graph.actions.items() if action is Action.UNKNOWN]
        resolved = await self._resolve_unknowns(ctx, schema, unknown)
        for name, action in resolved.items():
            graph.actions[name] = action

        still_unknown = [op for op, a in graph.actions.items() if a is Action.UNKNOWN]
        return StepResult(
            artifacts={A.GRAPH: graph.to_dict()},
            metrics={
                "objects": len(graph.objects),
                "edges": len(graph.edges),
                "hard_edges": sum(1 for e in graph.edges if e.kind == "hard"),
                "soft_edges": sum(1 for e in graph.edges if e.kind == "soft"),
                # The ambiguous subset before and after the LLM resolver.
                "unknown_actions_heuristic": len(unknown),
                "resolved_by_llm": len(resolved),
                "unknown_actions": len(still_unknown),
                "unresolved_args": sum(len(v) for v in graph.unresolved.values()),
            },
            note=(f"{len(graph.edges)} edges, {len(unknown)} unlabeled mutations"
                  + (f", {len(resolved)} resolved by LLM" if resolved else "")),
        )

    async def _resolve_unknowns(self, ctx: RunContext, schema, unknown_names: list[str]) -> dict:
        """LLM-resolve UNKNOWN mutation labels, if a resolver provider is set.

        No resolver configured, or nothing ambiguous, means the heuristic labels
        stand — so a provider-free run is unchanged and deterministic.
        """
        router = ctx.services.get("router")
        if router is None or "resolver" not in ctx.config.providers or not unknown_names:
            return {}
        from prediql.generation.resolver import resolve_actions

        operations = [schema.operations[name] for name in unknown_names
                      if name in schema.operations]
        try:
            return await resolve_actions(router, operations, schema)
        except Exception as exc:  # noqa: BLE001 - resolution is a bonus, never fatal
            ctx.progress(self.name, resolver_error=str(exc))
            return {}
