"""Engine-core tests: plan resolution, resume, cascade invalidation, isolation.

These encode the M0 exit criteria from docs/08: a killed run resumes without
repeating work, a re-run upstream step forces its dependents, and two runs share
one process without touching each other's state.
"""

from __future__ import annotations

import asyncio

import pytest

from prediql.engine.config import RunConfig, Strategy
from prediql.engine.context import RunContext
from prediql.engine.errors import PlanError
from prediql.engine.journal import Outcome
from prediql.engine.orchestrator import Orchestrator
from prediql.engine.stepgraph import (
    STEP_REGISTRY,
    Plan,
    Step,
    StepResult,
    dependents,
    resolve,
)

# --------------------------------------------------------------------------
# Fixtures: a tiny three-step chain A -> B -> C, with a call counter so tests
# can assert *what actually re-ran* rather than trusting the reported outcome.
# --------------------------------------------------------------------------

CALLS: dict[str, int] = {}


class _Counting(Step):
    payload = "v1"

    async def run(self, ctx):
        CALLS[self.name] = CALLS.get(self.name, 0) + 1
        return StepResult(
            artifacts={key: {"from": self.name, "payload": self.payload} for key in self.produces},
            note=f"{self.name} ran",
        )


class AlphaStep(_Counting):
    name = "alpha"
    produces = frozenset({"a"})


class BetaStep(_Counting):
    name = "beta"
    requires = frozenset({"a"})
    produces = frozenset({"b"})


class GammaStep(_Counting):
    name = "gamma"
    requires = frozenset({"b"})
    produces = frozenset({"c"})


class OrphanStep(_Counting):
    name = "orphan"
    requires = frozenset({"never_produced"})
    produces = frozenset({"z"})


class LiarStep(Step):
    """Writes an artifact it never declared — the orchestrator must reject it."""

    name = "liar"
    produces = frozenset({"declared"})

    async def run(self, ctx):
        return StepResult(artifacts={"declared": 1, "undeclared": 2})


@pytest.fixture(autouse=True)
def _register_test_steps():
    """Register the fixtures for the duration of a test, then clean up."""
    added = []
    for cls in (AlphaStep, BetaStep, GammaStep, OrphanStep, LiarStep):
        if cls.name not in STEP_REGISTRY:
            STEP_REGISTRY[cls.name] = cls
            added.append(cls.name)
    CALLS.clear()
    AlphaStep.payload = "v1"
    yield
    for name in added:
        STEP_REGISTRY.pop(name, None)


def _ctx(tmp_path, **overrides) -> RunContext:
    config = RunConfig(target_url="https://api.test/graphql", mode="coverage", **overrides)
    return RunContext(config, runs_root=tmp_path)


# --------------------------------------------------------------------------
# Plan resolution
# --------------------------------------------------------------------------


def test_resolve_orders_by_dependency_not_input_order():
    plan = resolve(["gamma", "alpha", "beta"])
    assert plan.names == ("alpha", "beta", "gamma")


def test_resolve_rejects_unsatisfiable_plan_before_any_work():
    with pytest.raises(PlanError, match="missing artifact"):
        resolve(["orphan"])


def test_resolve_accepts_step_when_artifact_already_on_disk():
    plan = resolve(["beta"], available={"a"})
    assert plan.names == ("beta",)


def test_resolve_rejects_unknown_step_and_duplicates():
    with pytest.raises(PlanError, match="unknown step"):
        resolve(["does_not_exist"])
    with pytest.raises(PlanError, match="more than once"):
        resolve(["alpha", "alpha"])


def test_dependents_propagate_transitively():
    plan = resolve(["alpha", "beta", "gamma"])
    assert dependents(plan, {"alpha"}) == {"beta", "gamma"}
    assert dependents(plan, {"beta"}) == {"gamma"}
    assert dependents(plan, {"gamma"}) == set()


# --------------------------------------------------------------------------
# Execution, resume, cascade
# --------------------------------------------------------------------------


async def test_run_executes_all_steps_once(tmp_path):
    ctx = _ctx(tmp_path)
    report = await Orchestrator(ctx).run(resolve(["alpha", "beta", "gamma"]))
    assert report.ok
    assert CALLS == {"alpha": 1, "beta": 1, "gamma": 1}
    assert ctx.get("c")["from"] == "gamma"


async def test_resume_skips_unchanged_steps(tmp_path):
    plan_names = ["alpha", "beta", "gamma"]
    ctx = _ctx(tmp_path)
    await Orchestrator(ctx).run(resolve(plan_names))
    assert CALLS == {"alpha": 1, "beta": 1, "gamma": 1}

    # Second pass in a *fresh* context over the same run dir == resume.
    CALLS.clear()
    ctx2 = _ctx(tmp_path)
    report = await Orchestrator(ctx2).run(resolve(plan_names))
    assert CALLS == {}, "nothing should re-run when inputs are unchanged"
    assert all(s.outcome is Outcome.SKIPPED for s in report.steps)


async def test_changed_upstream_output_cascades_downstream(tmp_path):
    plan_names = ["alpha", "beta", "gamma"]
    ctx = _ctx(tmp_path)
    await Orchestrator(ctx).run(resolve(plan_names))

    # Alpha now produces different content; beta and gamma consume it
    # transitively, so all three must re-run.
    CALLS.clear()
    AlphaStep.payload = "v2"
    ctx2 = _ctx(tmp_path)
    await Orchestrator(ctx2).run(resolve(plan_names), force={"alpha"})
    assert CALLS == {"alpha": 1, "beta": 1, "gamma": 1}
    assert ctx2.get("a")["payload"] == "v2"


async def test_force_step_reruns_dependents_even_when_output_identical(tmp_path):
    """--force-step must cascade even though fingerprints are unchanged."""
    plan_names = ["alpha", "beta", "gamma"]
    ctx = _ctx(tmp_path)
    await Orchestrator(ctx).run(resolve(plan_names))

    CALLS.clear()
    ctx2 = _ctx(tmp_path)
    await Orchestrator(ctx2).run(resolve(plan_names), force={"beta"})
    assert CALLS == {"beta": 1, "gamma": 1}, "alpha unchanged; beta forced; gamma cascaded"


async def test_missing_artifact_forces_rebuild_even_if_journal_says_done(tmp_path):
    ctx = _ctx(tmp_path)
    await Orchestrator(ctx).run(resolve(["alpha", "beta"]))

    CALLS.clear()
    ctx2 = _ctx(tmp_path)
    ctx2.store.drop("b")  # artifact deleted out from under the journal
    await Orchestrator(ctx2).run(resolve(["alpha", "beta"]))
    assert CALLS == {"beta": 1}, "beta must rebuild its missing output; alpha stays skipped"


async def test_crashed_step_yields_a_verdict_and_stops_the_run(tmp_path):
    class Boom(_Counting):
        name = "boom"
        requires = frozenset({"a"})
        produces = frozenset({"boom_out"})

        async def run(self, ctx):
            raise RuntimeError("detonated")

    STEP_REGISTRY["boom"] = Boom
    try:
        ctx = _ctx(tmp_path)
        report = await Orchestrator(ctx).run(resolve(["alpha", "boom"]))
        assert not report.ok
        assert report.stopped_reason == "step_failed:boom"
        assert "detonated" in (report.steps[-1].error or "")
    finally:
        STEP_REGISTRY.pop("boom", None)


async def test_step_writing_undeclared_artifact_is_rejected(tmp_path):
    ctx = _ctx(tmp_path)
    report = await Orchestrator(ctx).run(resolve(["liar"]))
    assert not report.ok
    assert "undeclared" in (report.steps[-1].error or "")
    assert not ctx.has("undeclared"), "undeclared artifact must not be persisted"


# --------------------------------------------------------------------------
# Isolation — the property v1 needed subprocesses to fake
# --------------------------------------------------------------------------


async def test_two_runs_share_a_process_without_sharing_state(tmp_path):
    ctx_a = RunContext(
        RunConfig(target_url="https://a.test/graphql", strategy=Strategy(seed=1)),
        runs_root=tmp_path,
    )
    ctx_b = RunContext(
        RunConfig(target_url="https://b.test/graphql", strategy=Strategy(seed=2)),
        runs_root=tmp_path,
    )
    assert ctx_a.run_id != ctx_b.run_id

    await asyncio.gather(
        Orchestrator(ctx_a).run(resolve(["alpha"])),
        Orchestrator(ctx_b).run(resolve(["alpha"])),
    )
    assert ctx_a.run_dir != ctx_b.run_dir
    assert ctx_a.get("a") is not None and ctx_b.get("a") is not None
    # Ledgers are per-run instances, not a module global (v1's bug).
    assert ctx_a.ledger is not ctx_b.ledger


# --------------------------------------------------------------------------
# Run identity — modes compose, strategies don't collide
# --------------------------------------------------------------------------


def test_run_id_is_stable_across_modes_so_steps_compose():
    """`coverage` then `security` must continue one run, not fork two."""
    coverage = RunConfig(target_url="https://a.test/graphql", mode="coverage")
    security = RunConfig(target_url="https://a.test/graphql", mode="security")
    assert coverage.run_id() == security.run_id()


def test_run_id_separates_different_experiments():
    base = RunConfig(target_url="https://a.test/graphql")
    assert base.run_id() != base.with_(strategy=Strategy(seed=99)).run_id()
    assert base.run_id() != base.with_(strategy=Strategy(arms=("+HierMAB",))).run_id()
    assert base.run_id() != RunConfig(target_url="https://b.test/graphql").run_id()
