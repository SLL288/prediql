"""Backend read layer + overlap, over a synthetic runs/ tree (no live process)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _write_run(root: Path, run_id: str, *, target: str, mode: str, model: str,
               confirmed: list[tuple[str, str]], status: str = "completed") -> None:
    run = root / run_id
    (run / "artifacts").mkdir(parents=True)
    (run / "findings").mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "started_at": "2026-01-01T00:00:00Z",
        "config": {"target": target, "mode": mode,
                   "providers": {"generator": model} if model else {}},
        "plan": ["introspect", "cover", "probe", "adjudicate"],
    }))
    events = [
        {"seq": 1, "ts": "2026-01-01T00:00:00Z", "event": "run_start"},
        {"seq": 2, "ts": "2026-01-01T00:00:01Z", "event": "step_start", "step": "cover"},
        {"seq": 3, "ts": "2026-01-01T00:00:02Z", "event": "step_finish", "step": "cover",
         "outcome": "ok", "seconds": 1.0, "note": "covered", "metrics": {}},
    ]
    if status == "completed":
        events.append({"seq": 4, "ts": "2026-01-01T00:00:03Z", "event": "run_finish",
                       "reason": "completed",
                       "budget": {"total_tokens": 100, "usd": 0.01}})
    (run / "journal.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n")
    findings = [{"id": f"f_{op}_{cls}", "class": cls, "operation": op, "state": "confirmed",
                 "severity": "high", "witness": {}} for cls, op in confirmed]
    (run / "artifacts" / "findings.json").write_text(json.dumps({
        "findings": findings, "confirmed": len(findings), "potential": 0, "by_class": {}}))
    (run / "artifacts" / "coverage.json").write_text(json.dumps({
        "operation_coverage": 1.0, "element_coverage": 0.7, "operations_covered": 5,
        "operations_total": 5, "elements_covered": 7, "elements_total": 10}))
    for f in findings:
        (run / "findings" / f"{f['id']}.json").write_text(json.dumps(f))


@pytest.fixture
def runs_tree(tmp_path, monkeypatch):
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    # config caches nothing; import fresh each test via the env var.
    _write_run(tmp_path, "dvga__aaa", target="http://dvga/graphql", mode="security",
               model="zai:glm", confirmed=[("sql_injection", "search"), ("path_traversal", "readFile")])
    _write_run(tmp_path, "dvga__bbb", target="http://dvga/graphql", mode="security",
               model="anthropic:haiku", confirmed=[("sql_injection", "search")])
    _write_run(tmp_path, "ctry__ccc", target="http://ctry/graphql", mode="coverage",
               model="", confirmed=[])
    return tmp_path


def test_list_runs_summarizes_and_sorts(runs_tree):
    import runs
    summaries = runs.list_runs()
    assert len(summaries) == 3
    assert {s["run_id"] for s in summaries} == {"dvga__aaa", "dvga__bbb", "ctry__ccc"}
    dvga = next(s for s in summaries if s["run_id"] == "dvga__aaa")
    assert dvga["confirmed"] == 2 and dvga["status"] == "completed"


def test_get_run_builds_the_step_rail(runs_tree):
    import runs
    detail = runs.get_run("dvga__aaa")
    assert detail is not None
    rail = {s["name"]: s["status"] for s in detail["steps"]}
    assert rail["cover"] == "pass"
    assert rail["probe"] == "pending", "unstarted steps show pending"


def test_get_run_404_for_unknown(runs_tree):
    import runs
    assert runs.get_run("nope") is None


def test_stats_aggregate(runs_tree):
    import runs
    s = runs.stats()
    assert s["runs"] == 3 and s["confirmed_findings"] == 3 and s["targets"] == 2


def test_report_path_rejects_traversal(runs_tree):
    import runs
    assert runs.report_path("dvga__aaa", "../manifest.json") is None
    assert runs.report_path("dvga__aaa", "index.html") is None  # no report dir here


def test_overlap_requires_two_models(runs_tree):
    import overlap
    # ctry has a single (heuristic) run -> not ready.
    result = overlap.overlap_for_target("http://ctry/graphql")
    assert result["ready"] is False


def test_overlap_computes_jaccard_over_confirmed(runs_tree):
    import overlap
    result = overlap.overlap_for_target("http://dvga/graphql")
    assert result["ready"] is True
    assert set(result["models"]) == {"zai:glm", "anthropic:haiku"}
    # zai found {sqli, path}; haiku found {sqli}. Jaccard = 1/2.
    assert result["matrix"]["zai:glm"]["anthropic:haiku"] == 0.5
    assert "sql_injection::search" in result["consensus"]
    assert result["found_by"]["sql_injection::search"] == 2
    assert result["found_by"]["path_traversal::readFile"] == 1  # singleton


def test_overlap_consensus_vs_singletons(runs_tree):
    import overlap
    result = overlap.overlap_for_target("http://dvga/graphql")
    # The consensus core is reliable; the singleton is the likely hallucination.
    assert result["consensus"] == ["sql_injection::search"]


# --------------------------------------------------------------------------
# Live progress merge (coverage round tracker + security jobs bar)
# --------------------------------------------------------------------------


def test_latest_progress_merges_disjoint_phase_fields():
    """Coverage and security emit disjoint progress fields; folding them keeps
    both bars, so a completed full run shows the round tracker AND the probe
    jobs bar — and a late tick never blanks an earlier phase's numbers."""
    import runs
    events = [
        {"event": "run_start"},
        {"event": "step_progress", "step": "cover", "phase": "coverage",
         "round": 1, "total_rounds": 2, "covered": 3, "total": 6, "requests": 9},
        {"event": "step_progress", "step": "cover", "phase": "coverage",
         "round": 2, "total_rounds": 2, "covered": 6, "total": 6, "requests": 18},
        {"event": "step_progress", "step": "probe", "phase": "security",
         "jobs_done": 4, "jobs_total": 12, "confirmed": 0, "signals": 1,
         "requests": 30, "error": "should not leak"},
        {"event": "step_progress", "step": "probe", "phase": "security",
         "jobs_done": 12, "jobs_total": 12, "confirmed": 2, "signals": 3, "requests": 44},
        {"event": "run_finish", "reason": "completed"},
    ]
    p = runs._latest_progress(events, {"budgets": {"max_tokens": 1000, "max_usd": None}})
    assert p["round"] == 2 and p["total_rounds"] == 2          # coverage survived
    assert p["covered"] == 6 and p["total"] == 6
    assert p["jobs_done"] == 12 and p["jobs_total"] == 12       # security present
    assert p["confirmed"] == 2 and p["signals"] == 3
    assert p["requests"] == 44                                 # last value wins
    assert p["budget_tokens"] == 1000                          # cap from the manifest
    assert "error" not in p, "diagnostics must not leak into the progress bar"


def test_latest_progress_is_none_without_ticks():
    import runs
    p = runs._latest_progress(
        [{"event": "run_start"}, {"event": "run_finish"}], {})
    assert p is None


# --------------------------------------------------------------------------
# A killed/interrupted run must not read as "running" forever (so it can be
# stopped/deleted). It never wrote run_finish; liveness decides the status.
# --------------------------------------------------------------------------


def _unfinished_run(root, run_id):
    run = root / run_id
    run.mkdir()
    (run / "manifest.json").write_text(json.dumps({"config": {}}))
    (run / "journal.jsonl").write_text(
        json.dumps({"seq": 1, "event": "step_start", "step": "cover"}) + "\n")
    return run


def test_unfinished_run_with_a_stale_journal_reports_stopped(tmp_path, monkeypatch):
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    import os, time, runs
    run = _unfinished_run(tmp_path, "x__killed")
    old = time.time() - 10_000                      # no live process, no fresh writes
    os.utime(run / "journal.jsonl", (old, old))
    status, active = runs._effective_status("x__killed", run, runs._journal(run))
    assert status == "stopped" and active is False


def test_unfinished_run_with_a_fresh_journal_reports_running(tmp_path, monkeypatch):
    """Post-restart heuristic: no handle, but a very recent write => still going."""
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    import runs
    run = _unfinished_run(tmp_path, "y__going")     # journal just written => fresh
    status, active = runs._effective_status("y__going", run, runs._journal(run))
    assert status == "running" and active is True


def test_list_runs_marks_a_stale_unfinished_run_stopped(tmp_path, monkeypatch):
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    import os, time, runs
    run = _unfinished_run(tmp_path, "z__killed")
    (run / "artifacts").mkdir()
    old = time.time() - 10_000
    os.utime(run / "journal.jsonl", (old, old))
    summary = next(r for r in runs.list_runs() if r["run_id"] == "z__killed")
    assert summary["status"] == "stopped"
    assert summary["active"] is False               # UI shows delete, not stop


# --------------------------------------------------------------------------
# Ablation facet: imported runs alias as <api>-<ablation>; the summary exposes
# both the ablation tag and the API it strips to, so the UI can group/compare.
# --------------------------------------------------------------------------


def test_api_of_strips_the_ablation_tag():
    import runs
    assert runs._api_of("countries-base", "base") == "countries"
    assert runs._api_of("countries-full", "full") == "countries"
    assert runs._api_of("userwallet", "") == "userwallet"          # no tag
    assert runs._api_of("my-api-scl", "aqg") == "my-api-scl"        # tag mismatch: leave alias


def test_summary_exposes_api_and_ablation(tmp_path, monkeypatch):
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    import runs
    run = tmp_path / "countries-base__t1__abc"
    (run / "artifacts").mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "run_id": run.name, "started_at": "2026-01-01T00:00:00Z",
        "config": {"target": "http://c/graphql", "alias": "countries-base",
                   "ablation": "base", "mode": "coverage",
                   "providers": {"generator": "openrouter:openai/gpt-5.4-nano"}},
        "plan": ["introspect", "cover"],
    }))
    (run / "journal.jsonl").write_text(
        json.dumps({"seq": 1, "event": "run_finish", "reason": "completed"}) + "\n")
    (run / "artifacts" / "coverage.json").write_text(json.dumps(
        {"operation_coverage": 1.0, "element_coverage": 0.9}))
    s = next(r for r in runs.list_runs() if r["run_id"] == run.name)
    assert s["ablation"] == "base"
    assert s["api"] == "countries"


# --------------------------------------------------------------------------
# Reliability facet: the cross-model overlap can be scoped to one ablation.
# --------------------------------------------------------------------------


def _write_sec_run(root, run_id, *, target, model, ablation, confirmed):
    run = root / run_id
    (run / "artifacts").mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "started_at": "2026-01-01T00:00:00Z",
        "config": {"target": target, "alias": f"dvga-{ablation}", "ablation": ablation,
                   "mode": "security", "providers": {"generator": model}},
        "plan": ["introspect", "cover", "probe", "adjudicate"],
    }))
    (run / "journal.jsonl").write_text(
        json.dumps({"seq": 1, "event": "run_finish", "reason": "completed"}) + "\n")
    findings = [{"id": f"f_{op}_{cls}", "class": cls, "operation": op, "state": "confirmed"}
                for cls, op in confirmed]
    (run / "artifacts" / "findings.json").write_text(json.dumps(
        {"findings": findings, "confirmed": len(findings), "potential": 0}))


def test_overlap_scopes_to_one_ablation(tmp_path, monkeypatch):
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    import overlap
    T = "http://dvga/graphql"
    # full mode: two models with findings -> ready. base mode: only one model.
    _write_sec_run(tmp_path, "dvga-full__a", target=T, model="m:1", ablation="full",
                   confirmed=[("sqli", "search")])
    _write_sec_run(tmp_path, "dvga-full__b", target=T, model="m:2", ablation="full",
                   confirmed=[("sqli", "search")])
    _write_sec_run(tmp_path, "dvga-base__a", target=T, model="m:1", ablation="base",
                   confirmed=[("sqli", "search")])

    tgt = next(t for t in overlap.targets_with_runs() if t["target"] == T)
    assert set(tgt["ablations"]) == {"full", "base"}

    full = overlap.overlap_for_target(T, "full")
    assert full["ready"] and full["n_models"] == 2

    base = overlap.overlap_for_target(T, "base")
    assert base["ready"] is False            # only one model in base mode

    allmodes = overlap.overlap_for_target(T, "all")
    assert allmodes["ready"] and allmodes["n_models"] == 2
