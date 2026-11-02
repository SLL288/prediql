"""End-to-end coverage run against a recorded API.

This is the M0/M1 exit criterion from docs/08: a full `coverage` mode run,
deterministic and offline, that resumes without repeating work.
"""

from __future__ import annotations

from prediql.engine.config import Budgets, RunConfig, Strategy
from prediql.engine.journal import Outcome
from prediql.runner import execute


def _config(**overrides) -> RunConfig:
    base = dict(
        target_url="https://replay.test/graphql",
        mode="coverage",
        strategy=Strategy(rounds=2, requests_per_operation=4, seed=11, coverage_depth=2),
    )
    base.update(overrides)
    return RunConfig(**base)


async def test_full_coverage_run(tmp_path, replay_target):
    report = await execute(_config(), runs_root=tmp_path, target=replay_target)

    assert report.ok, [s.error for s in report.steps if s.error]
    assert [s.name for s in report.steps] == [
        "introspect", "compile", "seed_identities", "cover", "validate",
    ]
    assert all(s.outcome is Outcome.OK for s in report.steps)

    run_dir = tmp_path / report.run_id
    assert (run_dir / "manifest.json").exists()
    assert (run_dir / "journal.jsonl").exists()
    for artifact in ("schema.normalized", "graph", "coverage", "bucket", "known_good", "baseline"):
        assert (run_dir / "artifacts" / f"{artifact.replace('.', '.')}.json").exists() or \
               (run_dir / "artifacts" / f"{artifact}.json".replace("/", "_")).exists()


async def test_errored_operation_is_not_counted_as_covered(tmp_path, replay_target):
    """`brokenField` returns 200 with errors[] — the 200-with-errors case."""
    from prediql.engine.context import RunContext

    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)
    ctx = RunContext(config, runs_root=tmp_path)
    coverage = ctx.get("coverage")

    assert coverage["operations_covered"] == 2, "continents + country only"
    assert coverage["operations_total"] == 5
    assert "brokenField" not in coverage["by_operation"]
    assert coverage["operations"]["brokenField"]["covered"] is False


async def test_coverage_reports_every_metric_with_its_denominator(tmp_path, replay_target):
    """No metric is quotable without the denominator that defines it."""
    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)
    from prediql.engine.context import RunContext

    coverage = RunContext(config, runs_root=tmp_path).get("coverage")
    assert 0.0 < coverage["operation_coverage"] <= 1.0
    assert 0.0 < coverage["element_coverage"] <= 1.0
    assert 0.0 < coverage["field_path_coverage"] <= 1.0
    assert coverage["depth"] == 2, "the depth bound must be published with the metric"
    for covered, total in (
        ("operations_covered", "operations_total"),
        ("elements_covered", "elements_total"),
        ("field_paths_covered", "field_paths_reachable"),
    ):
        assert coverage[covered] <= coverage[total]
        assert coverage[total] > 0


async def test_bandit_recorded_and_rewarded(tmp_path, replay_target):
    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)
    from prediql.engine.context import RunContext

    bandit = RunContext(config, runs_root=tmp_path).get("bandit")
    assert bandit["pulls"] > 0
    assert bandit["total_reward"] > 0, "reachable operations should earn reward"
    assert bandit["regret_vs_best_arm"] >= 0.0


async def test_bucket_harvests_identifiers_for_chains(tmp_path, replay_target):
    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)
    from prediql.engine.context import RunContext

    bucket = RunContext(config, runs_root=tmp_path).get("bucket")
    assert "country" in bucket or "Country" in bucket, bucket
    entries = bucket.get("country") or bucket.get("Country")
    assert entries and entries[0]["identifier"] == "CA"
    assert entries[0]["identity"] == "anon"


async def test_validate_records_latency_baseline_and_control(tmp_path, replay_target):
    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)
    from prediql.engine.context import RunContext

    baseline = RunContext(config, runs_root=tmp_path).get("baseline")
    assert baseline, "known-good operations should have baselines"
    for entry in baseline.values():
        assert entry["repeatable"] is True
        assert entry["latency_median_ms"] > 0
        assert entry["negative_control"] is not None, "oracles need a control response"
        assert "latency_mad_ms" in entry


async def test_graph_infers_actions_and_edges(tmp_path, replay_target):
    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)
    from prediql.engine.context import RunContext

    graph = RunContext(config, runs_root=tmp_path).get("graph")
    assert graph["actions"]["createCountry"] == "CREATE"
    assert graph["actions"]["deleteCountry"] == "DELETE"
    assert graph["actions"]["continents"] == "READ"
    # `countryId` must resolve to the Country object -> the edge a UAF chain needs.
    hard = [e for e in graph["edges"] if e["kind"] == "hard"]
    assert any(e["source"] == "Country" and e["target"] == "deleteCountry" for e in hard), hard


async def test_resume_skips_completed_steps(tmp_path, replay_target):
    config = _config()
    first = await execute(config, runs_root=tmp_path, target=replay_target)
    assert all(s.outcome is Outcome.OK for s in first.steps)

    sent_before = len(replay_target.sent)
    second = await execute(config, runs_root=tmp_path, target=replay_target)
    assert all(s.outcome is Outcome.SKIPPED for s in second.steps)
    assert len(replay_target.sent) == sent_before, "resume must issue no new requests"


async def test_force_step_reruns_downstream(tmp_path, replay_target):
    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)

    third = await execute(config, runs_root=tmp_path, target=replay_target, force={"cover"})
    outcomes = {s.name: s.outcome for s in third.steps}
    assert outcomes["introspect"] is Outcome.SKIPPED
    assert outcomes["cover"] is Outcome.OK
    assert outcomes["validate"] is Outcome.OK, "validate consumes known_good -> must cascade"


async def test_budget_ceiling_is_recorded(tmp_path, replay_target):
    config = _config(budgets=Budgets(max_tokens=1_000_000))
    report = await execute(config, runs_root=tmp_path, target=replay_target)
    assert report.budget["limits"]["max_tokens"] == 1_000_000
    assert report.budget["compression_level"] == "FULL", "no LLM spend yet -> full context"


async def test_steps_can_run_individually_against_an_existing_run(tmp_path, replay_target):
    """`coverage first, then more` — the composability requirement."""
    await execute(_config(mode="compile"), runs_root=tmp_path, target=replay_target)

    # A second invocation asks only for the remaining steps; introspect's
    # artifacts already exist, so the plan resolves against them.
    config = _config(mode="coverage")
    report = await execute(config, runs_root=tmp_path, target=replay_target)
    assert report.ok
    outcomes = {s.name: s.outcome for s in report.steps}
    assert outcomes["introspect"] is Outcome.SKIPPED, "reuses the earlier compile-mode run"
    assert outcomes["cover"] is Outcome.OK


# --------------------------------------------------------------------------
# Safety and failure visibility
# --------------------------------------------------------------------------


async def test_delete_mutations_are_blocked_by_default(tmp_path, replay_target):
    """`cover` reuses real harvested ids, so an ungated DELETE hits real data."""
    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)

    sent = [" ".join(d.split()) for d in replay_target.sent]
    assert not any("deleteCountry" in d for d in sent), \
        f"a destructive mutation was issued without --allow-destructive: {sent}"

    from prediql.engine.context import RunContext

    coverage = RunContext(config, runs_root=tmp_path).get("coverage")
    assert coverage["operations"]["deleteCountry"]["stop_reason"] == "destructive_blocked"
    # Non-destructive mutations are still exercised.
    assert any("createCountry" in d for d in sent)


async def test_destructive_operations_run_when_explicitly_allowed(tmp_path, replay_target):
    config = _config(allow_destructive=True)
    await execute(config, runs_root=tmp_path, target=replay_target)
    sent = [" ".join(d.split()) for d in replay_target.sent]
    assert any("deleteCountry" in d for d in sent)


async def test_allowing_destructive_is_a_different_run(tmp_path, replay_target):
    """Safety posture is part of a run's identity, not a silent re-use."""
    safe = _config()
    unsafe = _config(allow_destructive=True)
    assert safe.run_id() != unsafe.run_id()


async def test_a_failing_operation_is_recorded_not_silently_dropped(tmp_path, replay_target):
    """A raised exception inside the fan-out must surface as an error."""
    from prediql.engine.context import RunContext
    from prediql.generation.generator import HeuristicGenerator

    class Exploding(HeuristicGenerator):
        async def generate(self, *, schema, operation, arm, bucket, context=None):
            if operation.name == "continents":
                raise RuntimeError("generator blew up")
            return await super().generate(
                schema=schema, operation=operation, arm=arm, bucket=bucket, context=context
            )

    config = _config()
    report = await execute(
        config, runs_root=tmp_path, target=replay_target, generator=Exploding()
    )
    assert report.ok, "one failing operation must not fail the whole step"

    coverage = RunContext(config, runs_root=tmp_path).get("coverage")
    state = coverage["operations"]["continents"]
    assert state["stop_reason"] == "error"
    assert "generator blew up" in state["error"]
    assert coverage["operations"]["country"]["covered"] is True, "others still proceed"


# --------------------------------------------------------------------------
# Large-schema prioritization
# --------------------------------------------------------------------------


async def test_max_operations_caps_work_and_records_the_rest(tmp_path, replay_target):
    """A capped run attempts only the selected operations; others are recorded."""
    from prediql.engine.context import RunContext
    from prediql.engine.config import Strategy

    config = _config(strategy=Strategy(rounds=1, requests_per_operation=4, seed=11,
                                       coverage_depth=2, max_operations=2))
    await execute(config, runs_root=tmp_path, target=replay_target)
    coverage = RunContext(config, runs_root=tmp_path).get("coverage")

    attempted = [n for n, s in coverage["operations"].items() if s["requests"] > 0]
    assert len(attempted) <= 2, f"cap not respected: {attempted}"
    not_selected = [n for n, s in coverage["operations"].items()
                    if s["stop_reason"] == "not_selected"]
    assert not_selected, "deselected operations must be recorded, not silently dropped"


async def test_uncapped_run_attempts_every_operation(tmp_path, replay_target):
    from prediql.engine.context import RunContext

    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)
    coverage = RunContext(config, runs_root=tmp_path).get("coverage")
    assert not any(s["stop_reason"] == "not_selected"
                   for s in coverage["operations"].values())


async def test_every_generated_query_exchange_is_logged(tmp_path, replay_target):
    """The request each generated query made to the server, and the response."""
    import json
    config = _config()
    await execute(config, runs_root=tmp_path, target=replay_target)
    log = tmp_path / config.run_id() / "http_calls.jsonl"
    rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert rows, "coverage must log its server exchanges"
    for r in rows:
        assert r["document"] and "status" in r and "success" in r
        assert r["phase"] == "cover" and r["source"] in ("llm", "heuristic")
    # a successful exchange carries the response data and its coverage gain
    ok = [r for r in rows if r["success"]]
    assert ok and any(r["data"] for r in ok)
    assert any(r["new_coverage"] > 0 for r in ok), "coverage-adding queries are marked"


# --------------------------------------------------------------------------
# Ablation toggles: isolate the bandit (+RandomArm) and value-reuse (+NoBucket),
# so the bandit and value reuse are measured separately.
# --------------------------------------------------------------------------


async def test_norag_leaves_the_bucket_empty(tmp_path, replay_target):
    import json
    cfg = _config(strategy=Strategy(rounds=2, requests_per_operation=4, seed=11,
                                    coverage_depth=2, arms=("+NoBucket",)))
    report = await execute(cfg, runs_root=tmp_path, target=replay_target)
    assert report.ok
    bucket = json.loads((tmp_path / report.run_id / "artifacts" / "bucket.json").read_text())
    # With value reuse off, nothing is harvested from responses.
    objs = bucket.get("objects", bucket)
    assert not objs or all(not v for v in (objs.values() if isinstance(objs, dict) else objs))


async def test_random_arm_policy_is_recorded(tmp_path, replay_target):
    import json
    cfg = _config(strategy=Strategy(rounds=2, requests_per_operation=4, seed=11,
                                    coverage_depth=2, arms=("+RandomArm",)))
    report = await execute(cfg, runs_root=tmp_path, target=replay_target)
    assert report.ok
    bandit = json.loads((tmp_path / report.run_id / "artifacts" / "bandit.json").read_text())
    assert bandit.get("policy") == "random"      # the control, not Thompson


# --------------------------------------------------------------------------
# Self-correction and the minimal-prompt baseline: +NoFeedback removes the
# missing-argument feedback; +Base removes every mechanism (v1's BASE).
# --------------------------------------------------------------------------


class _RecordingGenerator:
    """The heuristic generator, recording the context of every call."""

    name = "recording"

    def __init__(self) -> None:
        from prediql.generation.generator import HeuristicGenerator
        self.inner = HeuristicGenerator()
        self.contexts: list[dict] = []

    async def generate(self, **kwargs):
        self.contexts.append(dict(kwargs.get("context") or {}))
        return await self.inner.generate(**kwargs)


def _missing_argument_target(replay_target):
    """Every request fails with a resolver demanding the ``code`` argument."""
    from prediql.targets.replay import ReplayTarget
    error = {"status": 200, "elapsed_ms": 3.0, "body": {"data": None, "errors": [
        {"message": "missing 1 required positional argument: 'code'"}]}}
    return ReplayTarget(replay_target._introspection, {}, default=error)


async def test_self_correction_feeds_missing_arguments_back(tmp_path, replay_target):
    gen = _RecordingGenerator()
    await execute(_config(), runs_root=tmp_path,
                  target=_missing_argument_target(replay_target), generator=gen)
    assert any("code" in c.get("required_args", []) for c in gen.contexts)


async def test_nofeedback_disables_self_correction(tmp_path, replay_target):
    gen = _RecordingGenerator()
    cfg = _config(strategy=Strategy(rounds=2, requests_per_operation=4, seed=11,
                                    coverage_depth=2, arms=("+NoFeedback",)))
    await execute(cfg, runs_root=tmp_path,
                  target=_missing_argument_target(replay_target), generator=gen)
    assert gen.contexts, "generation still ran"
    assert all(not c.get("required_args") for c in gen.contexts)
    assert not any(c.get("minimal_prompt") for c in gen.contexts)


async def test_base_is_one_fixed_arm_with_a_minimal_prompt(tmp_path, replay_target):
    import json
    gen = _RecordingGenerator()
    cfg = _config(strategy=Strategy(rounds=2, requests_per_operation=4, seed=11,
                                    coverage_depth=2, arms=("+Base",)))
    report = await execute(cfg, runs_root=tmp_path, target=replay_target, generator=gen)
    assert report.ok
    artifacts = tmp_path / report.run_id / "artifacts"
    bandit = json.loads((artifacts / "bandit.json").read_text())
    used = {name for name, arm in bandit["arms"].items() if arm["selections"]}
    assert used == {"base_minimal"}, "no selection policy: only the fixed arm runs"
    assert all(c.get("minimal_prompt") for c in gen.contexts)
    assert all(not c.get("required_args") for c in gen.contexts)
    bucket = json.loads((artifacts / "bucket.json").read_text())
    objs = bucket.get("objects", bucket)
    assert not objs or all(not v for v in (objs.values() if isinstance(objs, dict) else objs))
