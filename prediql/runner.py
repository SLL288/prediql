"""Assembly: turn a :class:`RunConfig` into an executed run.

The single place that wires live collaborators (target adapter, generator) into
a context. Keeping it out of the orchestrator means tests can substitute a
replay target without touching the driver, and the driver stays free of any
knowledge about the target transport or the providers.
"""

from __future__ import annotations

from pathlib import Path

import prediql.engine.steps  # noqa: F401  (import registers every step)
from prediql.engine.config import RunConfig
from prediql.engine.context import RunContext
from prediql.engine.orchestrator import Orchestrator, RunReport
from prediql.engine.stepgraph import mode_steps, resolve
from prediql.generation.generator import CandidateGenerator, HeuristicGenerator
from prediql.generation.llm_generator import LLMGenerator
from prediql.providers.registry import build_provider
from prediql.providers.router import Router
from prediql.targets.base import TargetAdapter
from prediql.targets.graphql import GraphQLTarget


def build_context(
    config: RunConfig, runs_root: Path | str = "runs", run_id: str | None = None
) -> RunContext:
    return RunContext(config, runs_root=runs_root, run_id=run_id)


async def execute(
    config: RunConfig,
    *,
    runs_root: Path | str = "runs",
    target: TargetAdapter | None = None,
    generator: CandidateGenerator | None = None,
    force: set[str] | None = None,
    truth_path: str | None = None,
    score_operations: list[str] | None = None,
    run_id: str | None = None,
) -> RunReport:
    """Run ``config`` end to end and return the report.

    ``target``/``generator`` are injection points: production passes neither and
    gets a live HTTP adapter plus the heuristic generator; tests pass a
    :class:`~prediql.targets.replay.ReplayTarget` for deterministic runs.
    """
    ctx = build_context(config, runs_root, run_id)
    if truth_path or config.truth_path:
        ctx.services["truth_path"] = truth_path or config.truth_path
    if score_operations:
        ctx.services["score_operations"] = score_operations

    step_names = config.steps or mode_steps(config.mode)

    # score/report run purely over on-disk artifacts: no target adapter needed,
    # which is what lets `predql score` re-score a finished run with no network.
    needs_target = any(
        s in step_names for s in ("introspect", "seed_identities", "cover", "validate", "probe")
    )
    owns_target = target is None and needs_target
    adapter = target or (GraphQLTarget(config.target_url, config.limits) if needs_target else None)
    if adapter is not None:
        ctx.services["target"] = adapter
    router = _build_router(ctx) if config.providers else None
    if router is not None:
        ctx.services["router"] = router
    if generator is not None:
        ctx.services["generator"] = generator
    elif router is not None and "generator" in config.providers:
        # LLM-driven generation only when a *generator* provider is set. A
        # judge-only config (LLM used just to triage) keeps heuristic generation,
        # so configuring the judge does not silently change how coverage works.
        ctx.services["generator"] = LLMGenerator(router)
    else:
        ctx.services["generator"] = HeuristicGenerator()

    plan = resolve(step_names, available=ctx.available())

    try:
        return await Orchestrator(ctx).run(plan, force=force)
    finally:
        if owns_target and adapter is not None:
            await adapter.aclose()
        if router is not None:
            await router.aclose()


def _build_router(ctx) -> Router:
    """Construct the provider router for a run from its config.

    Responses are cached under the run directory, and every call meters into the
    run's budget ledger, so token spend is accounted by construction. Prices come
    from the model catalog unless the run supplies an override (a custom model).
    """
    # No key is resolved here: build_provider resolves per vendor, so a run whose
    # roles span vendors authenticates each with the right credential.
    overrides = ctx.config.model_prices or {}
    providers = {
        role: build_provider(spec, price=overrides.get(spec))
        for role, spec in ctx.config.providers.items()
    }
    return Router(providers, ledger=ctx.ledger, cache=ctx.run_dir / "llm_cache",
                  log_path=ctx.run_dir / "llm_calls.jsonl")
