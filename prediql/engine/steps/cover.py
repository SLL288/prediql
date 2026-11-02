"""Step: discover reachable operations (coverage).

Fans out across operations and runs bounded rounds per operation. Each round the
bandit picks a prompt/selection strategy, the generator proposes candidates, and
the arm is rewarded **only** when a candidate produced a successful response that
also increased response-grounded coverage.

Termination is explicit: an operation stops on success, on a
coverage plateau, on its request budget, or on the run's token budget — and the
reason is recorded per operation rather than left implicit in a loop condition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.generation.bandit import BASE_ARM, DEFAULT_ARMS, WIDE_ARMS, RandomSelector, ThompsonBandit
from prediql.generation.feedback import missing_arguments
from prediql.generation.generator import CandidateGenerator, HeuristicGenerator
from prediql.generation.prioritize import diversity_report, prioritize
from prediql.model.bucket import ObjectsBucket
from prediql.model.graph import Action, DependencyGraph
from prediql.model.coverage import CoverageState
from prediql.model.schema import Operation, Schema
from prediql.targets.base import HttpResult, is_success


@dataclass
class _OperationState:
    """Per-operation progress and the reason it stopped."""

    covered: bool = False
    requests: int = 0
    rounds: int = 0
    plateau: int = 0
    stop_reason: str = ""
    known_good: str = ""
    error: str = ""
    arms_used: list[str] = field(default_factory=list)
    server_required: set[str] = field(default_factory=set)
    """Optional-in-schema arguments the server's errors said it needs."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "covered": self.covered,
            "requests": self.requests,
            "rounds": self.rounds,
            "stop_reason": self.stop_reason,
            "known_good": self.known_good,
            "error": self.error,
            "arms_used": self.arms_used,
            "server_required_args": sorted(self.server_required),
        }


@register
class CoverStep(Step):
    name = "cover"
    # GRAPH is required, not optional: its action labels are what identify a
    # destructive operation, and that gate must be enforced at the planner
    # rather than left to the fuzzer (docs/01 §8).
    requires = frozenset({A.SCHEMA, A.GRAPH, A.IDENTITIES})
    produces = frozenset({A.COVERAGE, A.BUCKET, A.KNOWN_GOOD, A.BANDIT})
    parallelizable = True
    cost_class = "llm-cheap"
    description = "Reach operations and record which schema fields actually return data."

    def config_signature(self, ctx: RunContext) -> dict:
        strategy = ctx.config.strategy
        return {
            "rounds": strategy.rounds,
            "requests": strategy.requests_per_operation,
            "seed": strategy.seed,
            "arms": list(strategy.arms),
            "depth": strategy.coverage_depth,
            "allow_destructive": ctx.config.allow_destructive,
        }

    async def run(self, ctx: RunContext) -> StepResult:
        config = ctx.config
        strategy = config.strategy
        schema = Schema.from_dict(ctx.get(A.SCHEMA))
        target = ctx.services["target"]
        generator: CandidateGenerator = ctx.services.get("generator") or HeuristicGenerator()

        # The bandit is shared across the fan-out. select()/update() never await,
        # so on a single-threaded event loop each is atomic — no lock needed.
        # Arm-selection policy is an ablation axis: the default Thompson bandit,
        # or a uniform-random control (+RandomArm) that isolates the bandit's
        # contribution from the arm space and from retrieval.
        # +WideCover widens the arm space with deeper maximal-selection arms and
        # (below) keeps an operation in play until its coverage plateaus rather
        # than dropping it after the first success — the two levers that lift
        # element coverage on schemas with large return types.
        wide_cover = strategy.has("+WideCover")
        arms = WIDE_ARMS if wide_cover else DEFAULT_ARMS
        # +Base is the minimal-prompt LLM baseline: one fixed arm (so no
        # selection policy), and none of value reuse, self-correction, the
        # syntactic seed, the arm directives, or the heuristic fallback.
        if strategy.has("+Base"):
            arms = (BASE_ARM,)
            bandit = RandomSelector(arms, seed=strategy.seed)
        elif strategy.has("+RandomArm"):
            bandit = RandomSelector(arms, seed=strategy.seed)
        else:
            bandit = ThompsonBandit(
                arms,
                seed=strategy.seed,
                gamma=1.0,
                hierarchical=strategy.has("+HierMAB"),
            )
        coverage = CoverageState(depth=strategy.coverage_depth)
        bucket = ObjectsBucket()
        states: dict[str, _OperationState] = {name: _OperationState() for name in schema.operations}

        # Refuse destructive operations unless explicitly permitted. This runs
        # before any request is generated: `cover` reuses real identifiers
        # harvested from earlier responses, so an ungated DELETE would be issued
        # against a live resource with a valid id.
        graph = DependencyGraph.from_dict(ctx.get(A.GRAPH) or {})
        blocked: list[str] = []
        if not config.allow_destructive:
            for name in schema.operations:
                if graph.actions.get(name) is Action.DELETE:
                    states[name].stop_reason = "destructive_blocked"
                    blocked.append(name)
        if blocked:
            ctx.progress(self.name, destructive_blocked=sorted(blocked))

        identity = self._primary_identity(ctx)

        # Order operations for shape diversity and optionally cap them. On a
        # large schema this is what puts distinct surface in front of the budget
        # instead of a long tail of near-duplicate variants.
        selected = prioritize(schema, graph, limit=strategy.max_operations)
        selected_names = [op.name for op in selected]
        if strategy.max_operations is not None:
            for name in schema.operations:
                if name not in set(selected_names):
                    states[name].stop_reason = "not_selected"

        for round_index in range(1, strategy.rounds + 1):
            # Default: an operation drops out once it is covered (first valid
            # response). +WideCover keeps it pending until it stops gaining
            # coverage — the plateau rule below sets its stop_reason — so later
            # rounds re-probe it with deeper, broader selections and cover more
            # of its return type's fields.
            pending = [
                op for op in selected
                if not states[op.name].stop_reason
                and (wide_cover or not states[op.name].covered)
            ]
            if not pending:
                break
            if ctx.ledger.exhausted():
                for op in pending:
                    states[op.name].stop_reason = "budget_exhausted"
                break

            async def cover_one(operation: Operation) -> None:
                await self._cover_operation(
                    ctx, operation, schema, target, generator, bandit,
                    coverage, bucket, states[operation.name], identity, round_index,
                )
                # Emit after each operation so the coverage bar advances smoothly
                # within a round, not only at the round boundary.
                snap = ctx.ledger.snapshot()
                ctx.progress(
                    self.name, phase="coverage",
                    round=round_index, total_rounds=strategy.rounds,
                    covered=len(coverage.covered_operations()),
                    total=len(schema.operations),
                    requests=sum(s.requests for s in states.values()),
                    tokens=snap["total"]["total_tokens"], usd=snap["total"]["usd"],
                    budget_tokens=ctx.config.budgets.max_tokens,
                    budget_usd=ctx.config.budgets.max_usd,
                    consumed=snap["consumed_fraction"],
                )

            outcomes = await ctx.limiter.map(cover_one, pending, slot="http")
            # A fan-out unit that raised must not vanish. Without this the
            # operation simply looks unreachable, and a generator bug is
            # indistinguishable from an unresponsive API.
            for operation, outcome in zip(pending, outcomes, strict=True):
                if isinstance(outcome, BaseException):
                    states[operation.name].stop_reason = "error"
                    states[operation.name].error = f"{type(outcome).__name__}: {outcome}"
                    ctx.progress(self.name, operation=operation.name,
                                 error=states[operation.name].error)
            snap = ctx.ledger.snapshot()
            ctx.progress(
                self.name,
                phase="coverage",
                round=round_index,
                total_rounds=strategy.rounds,
                covered=len(coverage.covered_operations()),
                total=len(schema.operations),
                requests=sum(s.requests for s in states.values()),
                tokens=snap["total"]["total_tokens"],
                usd=snap["total"]["usd"],
                budget_tokens=ctx.config.budgets.max_tokens,
                budget_usd=ctx.config.budgets.max_usd,
                consumed=snap["consumed_fraction"],
            )

        for state in states.values():
            if not state.stop_reason:
                state.stop_reason = "covered" if state.covered else "rounds_exhausted"

        report = coverage.report(schema)
        known_good = {name: s.known_good for name, s in states.items() if s.known_good}
        return StepResult(
            artifacts={
                A.COVERAGE: {**report, "operations": {n: s.as_dict() for n, s in states.items()}},
                A.BUCKET: bucket.to_dict(),
                A.KNOWN_GOOD: known_good,
                A.BANDIT: bandit.stats(),
            },
            metrics={
                **{f"selection_{k}": v for k, v in
                   diversity_report(selected, graph).items()},
                "destructive_blocked": len(blocked),
                "errors": sum(1 for s in states.values() if s.error),
                "operation_coverage": report["operation_coverage"],
                "element_coverage": report["element_coverage"],
                "operations_covered": report["operations_covered"],
                "operations_total": report["operations_total"],
                "requests": sum(s.requests for s in states.values()),
                "bucket_objects": len(bucket),
            },
            note=(
                f"{report['operations_covered']}/{report['operations_total']} operations, "
                f"element coverage {report['element_coverage']:.1%}"
            ),
        )

    # -- internals --------------------------------------------------------

    @staticmethod
    def _primary_identity(ctx: RunContext):
        """First usable identity, falling back to the first configured one."""
        live = {i["name"] for i in (ctx.get(A.IDENTITIES) or []) if i.get("usable")}
        for identity in ctx.config.identities:
            if identity.name in live:
                return identity
        return ctx.config.identities[0]

    async def _cover_operation(
        self, ctx, operation, schema, target, generator, bandit,
        coverage, bucket, state, identity, round_index,
    ) -> None:
        """One operation, one round: select an arm, execute, reward."""
        budget = ctx.config.strategy.requests_per_operation
        if state.requests >= budget * round_index:
            state.stop_reason = "request_budget"
            return

        arm = bandit.select(operation.name)
        state.arms_used.append(arm.name)
        state.rounds += 1

        strategy = ctx.config.strategy
        base = strategy.has("+Base")
        budget_left = max(1, budget * round_index - state.requests)
        candidates = await generator.generate(
            schema=schema, operation=operation, arm=arm, bucket=bucket,
            context={"round": round_index, "max_candidates": budget_left,
                     "required_args": sorted(state.server_required),
                     "minimal_prompt": base},
        )
        if not candidates:
            bandit.update(operation.name, arm.name, 0.0)
            state.stop_reason = "no_candidate"
            return

        gained = 0
        succeeded = False
        for candidate in candidates:
            if state.requests >= budget * round_index:
                break
            result: HttpResult = await target.send(candidate.document, identity)
            state.requests += 1

            ok = is_success(result)
            new_paths = coverage.observe(operation.name, candidate.document, result.data) if ok else 0
            _log_exchange(ctx, operation.name, round_index, candidate, result, ok, new_paths)

            if not ok:
                # Self-correction: a schema-optional argument the resolver
                # demanded is supplied from the next round on. +NoFeedback (and
                # +Base) is the ablation axis that turns this off, so the
                # error is still logged but never fed back into generation.
                if not (base or strategy.has("+NoFeedback")):
                    state.server_required |= missing_arguments(
                        (result.body or {}).get("errors"), operation)
                continue
            succeeded = True
            gained += new_paths
            # Value reuse (the rewrite's "RAG") is an ablation axis: +NoBucket
            # leaves the bucket empty so the generator cannot reuse observed
            # identifiers, isolating retrieval's contribution from the bandit's.
            if not (base or strategy.has("+NoBucket")):
                bucket.harvest(
                    result.data, operation=operation.name, identity=identity.name,
                    schema=schema, root_type=operation.type.name,
                )
            if not state.known_good:
                state.known_good = candidate.document

        # The reward rule, stated once: a successful response AND new coverage.
        # A 200 carrying errors[] is not a success; a repeat of known ground is
        # not new coverage. Either failure scores zero.
        reward = 1.0 if (succeeded and gained > 0) else 0.0
        bandit.update(operation.name, arm.name, reward)

        if succeeded:
            state.covered = True
        if gained == 0:
            state.plateau += 1
            if state.plateau >= ctx.config.strategy.plateau_rounds and state.covered:
                state.stop_reason = "coverage_plateau"
        else:
            state.plateau = 0


def _clip(value: Any, limit: int = 800) -> str:
    """Compact, bounded string form of a response payload."""
    import json as _json

    text = value if isinstance(value, str) else _json.dumps(value, default=str)
    text = text or ""
    return text if len(text) <= limit else text[:limit] + f" … [{len(text) - limit} more]"


def _log_exchange(ctx, operation, round_index, candidate, result, ok, new_paths) -> None:
    """Persist one query→server exchange for the dashboard."""
    body = result.body or {}
    ctx.log_exchange({
        "operation": operation,
        "round": round_index,
        "phase": "cover",
        "source": candidate.source,           # "llm" | "heuristic"
        "arm": candidate.arm,
        "identity": result.identity,
        "document": candidate.document,
        "status": result.status,
        "success": ok,
        "new_coverage": new_paths,             # how many new field-paths this query reached
        "elapsed_ms": round(result.elapsed_ms, 1),
        "error": result.error,
        "errors": _clip(body.get("errors"), 400) if body.get("errors") else "",
        "data": _clip(body.get("data")) if body.get("data") is not None else "",
    })
