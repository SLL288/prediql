"""The run driver: resume, cascade invalidation, journaling.

Deliberately thin (autosec's ``pipeline.py`` discipline): it resolves a plan,
decides per step whether to skip or run, and records the outcome. All branching
lives in step definitions and mode profiles, never here — adding a capability
must never mean editing the driver.
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from typing import Any

from prediql.engine.context import RunContext
from prediql.engine.errors import PrediQLError
from prediql.engine.journal import Event, Outcome
from prediql.engine.limiter import Limiter
from prediql.engine.stepgraph import Plan, Step, dependents


@dataclass
class StepReport:
    """Per-step outcome, as surfaced on the dashboard step rail."""

    name: str
    outcome: Outcome
    seconds: float = 0.0
    note: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class RunReport:
    """Terminal summary of one run."""

    run_id: str
    steps: list[StepReport] = field(default_factory=list)
    stopped_reason: str = "completed"
    budget: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return all(step.outcome is not Outcome.FAILED for step in self.steps)


class Orchestrator:
    """Executes a :class:`Plan` against a :class:`RunContext`."""

    def __init__(self, ctx: RunContext) -> None:
        self.ctx = ctx

    async def run(self, plan: Plan, *, force: set[str] | None = None) -> RunReport:
        """Run the plan, skipping steps whose inputs are unchanged.

        ``force`` names steps to re-run unconditionally; their downstream
        consumers are re-run too, so an explicitly refreshed step never leaves a
        stale artifact behind it.
        """
        ctx = self.ctx
        ctx.limiter = Limiter(ctx.config.limits)  # bound to the active event loop
        ctx.write_manifest({"plan": list(plan.names)})

        forced = set(force or set())
        if forced:
            forced |= dependents(plan, forced)

        completed = ctx.journal.completed()
        report = RunReport(run_id=ctx.run_id)
        ctx.journal.append(
            Event.RUN_START, mode=ctx.config.mode, plan=list(plan.names), forced=sorted(forced)
        )

        for step in plan.steps:
            decision = self._decide(step, completed, forced)
            if decision is None:
                ctx.journal.append(Event.STEP_SKIP, step=step.name, reason="unchanged")
                report.steps.append(StepReport(step.name, Outcome.SKIPPED, note="unchanged"))
                continue

            if step.name in forced:
                # Clear the journal's completion record first: a crash between
                # here and the finish event must not let a resume skip this step.
                ctx.journal.append(
                    Event.STEP_INVALIDATE, step=step.name, reason="forced re-run"
                )
            report.steps.append(await self._execute(step, decision))

            if report.steps[-1].outcome is Outcome.FAILED:
                report.stopped_reason = f"step_failed:{step.name}"
                break
            if ctx.ledger.exhausted():
                report.stopped_reason = "budget_exhausted"
                break

        report.budget = ctx.ledger.snapshot()
        ctx.journal.append(
            Event.RUN_FINISH, reason=report.stopped_reason, budget=report.budget["total"]
        )
        return report

    # -- internals --------------------------------------------------------

    def _decide(self, step: Step, completed: dict, forced: set[str]) -> str | None:
        """Return this step's fingerprint if it must run, else ``None`` to skip."""
        fp = step.fingerprint(self.ctx)
        if step.name in forced:
            return fp
        prior = completed.get(step.name)
        if prior is None or prior.fingerprint != fp:
            return fp
        if not all(self.ctx.has(key) for key in step.produces):
            return fp  # journal says done, but an output is missing — rebuild it
        return None

    async def _execute(self, step: Step, fingerprint: str) -> StepReport:
        ctx = self.ctx
        ctx.journal.append(Event.STEP_START, step=step.name, fingerprint=fingerprint)
        started = time.perf_counter()
        try:
            result = await step.run(ctx)
        except PrediQLError as exc:
            return self._fail(step, started, str(exc))
        except Exception as exc:  # noqa: BLE001 - a crashed step still yields a verdict
            return self._fail(step, started, f"{exc!r}\n{traceback.format_exc()}")

        unexpected = set(result.artifacts) - set(step.produces)
        if unexpected:
            return self._fail(
                step, started, f"step wrote undeclared artifacts: {sorted(unexpected)}"
            )
        for key, value in result.artifacts.items():
            ctx.put(key, value, step=step.name)

        seconds = time.perf_counter() - started
        ctx.journal.append(
            Event.STEP_FINISH,
            step=step.name,
            outcome=Outcome.OK,
            fingerprint=fingerprint,
            produces=sorted(result.artifacts),
            seconds=round(seconds, 3),
            metrics=result.metrics,
            note=result.note,
        )
        return StepReport(step.name, Outcome.OK, seconds, result.note, result.metrics)

    def _fail(self, step: Step, started: float, error: str) -> StepReport:
        seconds = time.perf_counter() - started
        self.ctx.journal.append(
            Event.STEP_FINISH,
            step=step.name,
            outcome=Outcome.FAILED,
            seconds=round(seconds, 3),
            error=error,
        )
        return StepReport(step.name, Outcome.FAILED, seconds, error=error)
