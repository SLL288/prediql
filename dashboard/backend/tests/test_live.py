"""Live launcher: pipe draining, durability, stop, and the targets picker.

The first test is the important one: a child that writes more than a pipe buffer
must not deadlock. Before the reader thread existed, every real run hung partway.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def runs_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    import live
    live._LAUNCHES.clear()
    return tmp_path


def _fake_launch(child_code: str, **over):
    """Build a Launch around an arbitrary child process, bypassing the CLI."""
    import live
    proc = subprocess.Popen([sys.executable, "-c", child_code],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1)
    ln = live.Launch(launch_id=over.get("launch_id", "L1"), run_id=over.get("run_id", "r1"),
                     target="t", mode="coverage", cmd=["x"], process=proc)
    ln.drain()
    live._LAUNCHES[ln.launch_id] = ln
    return ln


def test_child_writing_more_than_a_pipe_buffer_does_not_deadlock():
    """A pipe holds ~64KB; an unread one blocks the child forever."""
    ln = _fake_launch("import sys\nfor _ in range(20000): print('x'*40)\n")
    deadline = time.time() + 15
    while ln.alive() and time.time() < deadline:
        time.sleep(0.05)
    assert not ln.alive(), "child deadlocked on a full stdout pipe"
    assert ln.exit_code == 0


def test_drained_output_is_kept_as_a_bounded_log():
    import live
    ln = _fake_launch("for i in range(50): print('line', i)")
    deadline = time.time() + 10
    while ln.alive() and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.2)
    assert any("line 49" in l for l in ln.log), "the tail of the child's output is kept"
    assert len(ln.log) <= live.LOG_LINES, "the log is bounded"


def test_log_ring_buffer_caps_memory():
    import live
    ln = _fake_launch(f"for i in range({live.LOG_LINES * 3}): print(i)")
    deadline = time.time() + 15
    while ln.alive() and time.time() < deadline:
        time.sleep(0.05)
    time.sleep(0.2)
    assert len(ln.log) == live.LOG_LINES


def test_stop_terminates_a_running_child():
    import live
    ln = _fake_launch("import time\ntime.sleep(30)")
    assert ln.alive()
    assert live.stop(ln.launch_id)["stopped"] is True
    deadline = time.time() + 5
    while ln.alive() and time.time() < deadline:
        time.sleep(0.05)
    assert not ln.alive()


def test_stop_on_unknown_launch_is_reported_not_raised():
    import live
    assert live.stop("nope")["stopped"] is False


def test_launch_records_survive_a_restart(runs_tmp):
    """Disk-durable: a new process must still see the launch history."""
    import live
    ln = _fake_launch("print('done')", launch_id="L42", run_id="r42")
    ln.persist()
    live._LAUNCHES.clear()          # simulate a backend restart
    assert live.list_launches() == []
    result = live.recover()
    assert result["restored"] == 1
    assert any(r["launch_id"] == "L42" for r in live.list_launches())


def test_recover_is_idempotent():
    import live
    _fake_launch("print('x')", launch_id="L7").persist()
    live._LAUNCHES.clear()
    live.recover()
    second = live.recover()
    assert second["restored"] == 0, "recovering twice must not duplicate"


def _spec(**over):
    import live
    base = live._normalize({"target": "https://x.test/graphql", "rounds": 2, "requests": 5})
    base.update(over)
    return base


def test_run_id_matches_what_the_cli_would_create():
    """The launcher finds the journal only if it predicts the run dir exactly."""
    import live
    sys.path.insert(0, str(live.REPO_ROOT))
    from prediql.cli import _build_parser, _config_from_args

    predicted = live._predql_run_id(_spec(), 1, "heuristic")
    args = _build_parser().parse_args(
        ["run", "--target", "https://x.test/graphql", "--rounds", "2", "--requests", "5"])
    actual = _config_from_args(args).run_id()
    assert predicted == actual


def test_run_id_carries_the_code_version():
    """Results from different engine code must never share a run directory."""
    import live
    sys.path.insert(0, str(live.REPO_ROOT))
    from prediql.engine.config import RunConfig

    base = RunConfig(target_url="https://x.test/graphql")
    assert base.with_(code_version="aaa").run_id() != base.with_(code_version="bbb").run_id()
    # unset keeps the pre-provenance identity, so replays and tests are unchanged
    assert base.run_id() == base.with_(code_version="").run_id()


def test_sys_path_is_not_grown_on_every_call():
    import live
    before = len(sys.path)
    for _ in range(5):
        live._predql_run_id(_spec(), 1, "heuristic")
    assert len(sys.path) <= before + 1


# --------------------------------------------------------------------------
# Alias, trials, and custom-model pricing
# --------------------------------------------------------------------------


def test_each_trial_gets_its_own_run_id():
    """Three replicates must not overwrite each other."""
    import live
    spec = _spec(alias="dvga")
    ids = {live._predql_run_id(spec, t, "heuristic") for t in (1, 2, 3)}
    assert len(ids) == 3
    assert all("dvga__t" in i for i in ids), ids


def test_alias_names_the_run_directory():
    import live
    run_id = live._predql_run_id(_spec(alias="My DVGA Box"), 1, "heuristic")
    assert run_id.startswith("my_dvga_box__t1__"), run_id


def test_command_carries_alias_trial_and_custom_price():
    import live
    spec = live._normalize({
        "target": "https://x.test/graphql", "alias": "dvga", "trials": 3,
        "generator": "custom:my-model",
        "model_prices": {"custom:my-model": [1.5, 6.0]},
        "max_operations": 25, "judge_samples": 3,
    })
    cmd = live._build_cmd(spec, 2, "custom:my-model")
    assert "--alias" in cmd and "dvga" in cmd
    assert cmd[cmd.index("--trial") + 1] == "2"
    assert "--provider" in cmd and "generator=custom:my-model" in cmd
    assert "custom:my-model=1.5,6.0" in cmd, "a custom model's price must reach the CLI"
    assert cmd[cmd.index("--max-operations") + 1] == "25"
    assert cmd[cmd.index("--judge-samples") + 1] == "3"


def test_normalize_rejects_a_missing_target():
    import live
    with pytest.raises(ValueError, match="target is required"):
        live._normalize({})


def test_heuristic_selection_configures_no_provider():
    import live
    spec = live._normalize({"target": "https://x.test/graphql", "generator": "heuristic"})
    assert live._providers_for(spec, "heuristic") == {}, \
        "heuristic means no LLM, not a provider named heuristic"


def test_options_expose_the_model_catalog_with_prices():
    import live
    opts = live.options()
    assert opts["models"], "the launcher must offer the catalogued models"
    refs = {m["ref"] for m in opts["models"]}
    assert "zai:glm-5.3-flash" in refs
    assert any(m["price_in"] > 0 for m in opts["models"]), "prices must be exposed"
    assert "anthropic" in opts["vendors"]


async def test_stream_reports_a_run_that_never_wrote_a_journal():
    """A plan error exits without a journal; the UI must get the reason."""
    import live
    ln = _fake_launch("import sys; print('boom: bad plan'); sys.exit(2)")
    frames = [f async for f in live.stream(ln.launch_id)]
    assert any("event: failed" in f for f in frames)
    assert any("boom: bad plan" in f for f in frames), "the drained log explains the failure"


async def test_stream_on_unknown_launch_yields_failed_not_error_event():
    """`error` is reserved by EventSource for transport errors, so we use `failed`."""
    import live
    frames = [f async for f in live.stream("nope")]
    assert frames and "event: failed" in frames[0]
    assert "event: error" not in frames[0]


# --------------------------------------------------------------------------
# Multi-model sweep (models x trials)
# --------------------------------------------------------------------------


def test_sweep_across_vendors_gives_every_point_its_own_run_dir():
    import live
    spec = live._normalize({
        "target": "https://x.test/graphql", "alias": "dvga", "trials": 2,
        "generators": ["zai:glm-5.3-flash", "anthropic:claude-haiku-4-5-20251001", "heuristic"],
    })
    ids = {live._predql_run_id(spec, t, g) for g in spec["generators"] for t in (1, 2)}
    assert len(ids) == 6, "3 models x 2 trials must not collide"


def test_single_generator_shorthand_still_works():
    import live
    spec = live._normalize({"target": "https://x.test/graphql", "generator": "zai:glm-5.3-flash"})
    assert spec["generators"] == ["zai:glm-5.3-flash"]


def test_heuristic_is_a_valid_sweep_member_and_configures_no_provider():
    """The zero-cost baseline belongs in the sweep, not outside it."""
    import live
    spec = live._normalize({"target": "https://x.test/graphql",
                            "generators": ["heuristic", "zai:glm-5.3-flash"]})
    assert live._providers_for(spec, "heuristic") == {}
    assert live._providers_for(spec, "zai:glm-5.3-flash") == {"generator": "zai:glm-5.3-flash"}


def test_fixed_roles_apply_across_every_sweep_point():
    import live
    spec = live._normalize({
        "target": "https://x.test/graphql", "judge": "zai:glm-5.3-flash",
        "generators": ["heuristic", "anthropic:claude-haiku-4-5-20251001"],
    })
    for generator in spec["generators"]:
        assert live._providers_for(spec, generator)["judge"] == "zai:glm-5.3-flash"


def test_sweep_deduplicates_repeated_models():
    import live
    spec = live._normalize({"target": "https://x.test/graphql",
                            "generators": ["zai:glm-5.3-flash", "zai:glm-5.3-flash", ""]})
    assert spec["generators"] == ["zai:glm-5.3-flash"]


def test_custom_model_price_survives_into_each_sweep_command():
    import live
    spec = live._normalize({
        "target": "https://x.test/graphql",
        "generators": ["custom:mine"], "model_prices": {"custom:mine": [3.0, 9.0]},
    })
    cmd = live._build_cmd(spec, 1, "custom:mine")
    assert "custom:mine=3.0,9.0" in cmd
    assert "generator=custom:mine" in cmd


def test_credentials_endpoint_names_missing_variables(monkeypatch, tmp_path):
    """The dashboard tells you what to add to .env; it never carries the secret."""
    import live
    monkeypatch.setattr("prediql.providers.env.dotenv_path", lambda: tmp_path / "none.env")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("ACME_API_KEY", raising=False)
    monkeypatch.delenv("ACME_BASE_URL", raising=False)

    result = live.credentials_for("acme:my-model")
    assert result["ready"] is False
    assert set(result["missing"]) == {"ACME_API_KEY", "ACME_BASE_URL"}


def test_credentials_for_heuristic_needs_nothing():
    import live
    assert live.credentials_for("heuristic")["ready"] is True


def test_launch_payload_carries_no_api_key():
    """A key in argv would be readable via `ps`; keys must come from .env only."""
    import live
    spec = live._normalize({
        "target": "https://x.test/graphql", "generators": ["zai:glm-5.3-flash"],
        "api_key": "sk-should-be-ignored", "model_prices": {"zai:glm-5.3-flash": [1, 2]},
    })
    cmd = live._build_cmd(spec, 1, "zai:glm-5.3-flash")
    assert not any("sk-should-be-ignored" in part for part in cmd)
    assert "--api-key" not in cmd


def test_launch_response_reports_the_first_point_as_running(monkeypatch):
    """The response must not say 'queued' for a point it just spawned."""
    import live
    monkeypatch.setattr(live, "_spawn", _fake_spawn)
    res = live.launch({"target": "https://x.test/graphql", "trials": 2,
                       "mode": "coverage"})
    first, second = res["launches"]
    assert first["queued"] is False, "trial 1 was spawned, not queued"
    assert second["queued"] is True, "trial 2 is genuinely still queued"


def _fake_spawn(spec, trial, generator, launch_id):
    """Spawn a trivial child instead of a real pipeline run."""
    import live, subprocess, sys
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ln = live.Launch(launch_id=launch_id, run_id="r", target=spec["target"],
                     mode=spec["mode"], cmd=["x"], process=proc,
                     trial=trial, trials=spec["trials"], model=generator)
    ln.drain()
    live._LAUNCHES[launch_id] = ln
    return ln


# --------------------------------------------------------------------------
# Deleting launches from the queue
# --------------------------------------------------------------------------


def test_delete_launch_removes_a_finished_record(runs_tmp):
    import live
    ln = _fake_launch("print('done')", launch_id="Ldel", run_id="rdel")
    deadline = time.time() + 5
    while ln.alive() and time.time() < deadline:
        time.sleep(0.05)
    ln.persist()
    assert (live._launch_dir() / "Ldel.json").exists()
    res = live.delete_launch("Ldel")
    assert res["deleted"] is True
    assert "Ldel" not in live._LAUNCHES
    assert not (live._launch_dir() / "Ldel.json").exists()


def test_delete_launch_refuses_a_running_one(runs_tmp):
    import live
    ln = _fake_launch("import time; time.sleep(30)", launch_id="Lrun")
    assert ln.alive()
    res = live.delete_launch("Lrun")
    assert res["deleted"] is False and "running" in res["reason"]
    live.stop("Lrun")  # cleanup the child


def test_delete_launch_tolerates_an_unknown_id(runs_tmp):
    import live
    assert live.delete_launch("nope")["deleted"] is True
