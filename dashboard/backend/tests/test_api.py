"""HTTP surface: routes, status codes, and the SPA fallback."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _write_run(root: Path, run_id: str, *, target: str, mode: str, model: str,
               confirmed: list[tuple[str, str]]) -> None:
    run = root / run_id
    (run / "artifacts").mkdir(parents=True)
    (run / "report").mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "started_at": "2026-01-01T00:00:00Z",
        "config": {"target": target, "mode": mode,
                   "providers": {"generator": model} if model else {}},
        "plan": ["introspect", "cover"]}))
    (run / "journal.jsonl").write_text("\n".join(json.dumps(e) for e in [
        {"seq": 1, "ts": "t", "event": "run_start"},
        {"seq": 2, "ts": "t", "event": "step_finish", "step": "cover",
         "outcome": "ok", "seconds": 1.0, "note": "n", "metrics": {}},
        {"seq": 3, "ts": "t", "event": "run_finish", "reason": "completed",
         "budget": {"total_tokens": 10, "usd": 0.0}},
    ]) + "\n")
    (run / "artifacts" / "findings.json").write_text(json.dumps({
        "findings": [{"id": f"f_{op}_{c}", "class": c, "operation": op,
                      "state": "confirmed", "severity": "high", "witness": {}}
                     for c, op in confirmed],
        "confirmed": len(confirmed), "potential": 0, "by_class": {}}))
    (run / "report" / "index.html").write_text("<!doctype html><title>r</title>")


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    _write_run(tmp_path, "t__a", target="http://t/graphql", mode="security",
               model="zai:glm", confirmed=[("sql_injection", "search")])
    _write_run(tmp_path, "t__b", target="http://t/graphql", mode="security",
               model="anthropic:haiku", confirmed=[("sql_injection", "search")])
    import app
    with TestClient(app.app) as c:
        yield c


def test_core_read_routes(client):
    assert client.get("/api/health").json() == {"ok": True}
    assert client.get("/api/stats").json()["runs"] == 2
    assert len(client.get("/api/runs").json()) == 2
    assert client.get("/api/runs/t__a").json()["run_id"] == "t__a"


def test_unknown_run_is_404(client):
    assert client.get("/api/runs/nope").status_code == 404


def test_report_file_is_served_and_traversal_is_refused(client):
    assert client.get("/api/runs/t__a/report/index.html").status_code == 200
    assert client.get("/api/runs/t__a/report/nope.html").status_code == 404
    # `..` escaping the report dir must not return the manifest.
    body = client.get("/api/runs/t__a/report/..%2fmanifest.json").text
    assert '"config"' not in body or "<div id=" in body


def test_targets_lists_only_completed_security_runs(client):
    targets = client.get("/api/analysis/targets").json()
    assert len(targets) == 1
    assert targets[0]["target"] == "http://t/graphql"
    assert targets[0]["ready"] is True
    assert set(targets[0]["models"]) == {"zai:glm", "anthropic:haiku"}


def test_overlap_is_computed_when_the_sweep_is_complete(client):
    res = client.get("/api/analysis/overlap?target=http://t/graphql")
    assert res.status_code == 200
    body = res.json()
    assert body["ready"] is True
    assert body["mean_pairwise_jaccard"] == 1.0, "both models found the same finding"
    assert body["consensus"] == ["sql_injection::search"]


def test_overlap_409s_until_the_sweep_is_complete(client):
    res = client.get("/api/analysis/overlap?target=http://nothing/graphql")
    assert res.status_code == 409, "an incomplete sweep must be refused, not guessed at"
    assert "need >=2 models" in res.json()["reason"]


def test_live_options_and_launches(client):
    opts = client.get("/api/live/options").json()
    assert "coverage" in opts["modes"] and opts["families"]
    assert client.get("/api/live/launches").json() == []


def test_launch_requires_a_target(client):
    assert client.post("/api/live/launch", json={}).status_code == 400


def test_stop_unknown_launch_reports_rather_than_raises(client):
    assert client.post("/api/live/nope/stop").json()["stopped"] is False


def test_llm_calls_endpoint(client, tmp_path):
    import json
    run = tmp_path / "t__a"
    (run / "llm_calls.jsonl").write_text(
        json.dumps({"step": "cover", "role": "generator", "model": "zai:glm",
                    "prompt": "p", "response": "r", "prompt_tokens": 5,
                    "completion_tokens": 9, "usd": 0.001, "cached": False}) + "\n")
    calls = client.get("/api/runs/t__a/llm-calls").json()
    assert len(calls) == 1 and calls[0]["step"] == "cover"


def test_llm_calls_empty_when_no_log(client):
    assert client.get("/api/runs/t__b/llm-calls").json() == []


def test_delete_run_removes_the_directory(client, tmp_path):
    assert (tmp_path / "t__a").exists()
    assert client.delete("/api/runs/t__a").json()["deleted"] is True
    assert not (tmp_path / "t__a").exists()


def test_delete_unknown_run_is_404(client):
    assert client.delete("/api/runs/nope").status_code == 404


def test_delete_refuses_a_path_traversal(client, tmp_path):
    # `..%2f..` would escape the runs root; must be refused, not honoured.
    r = client.delete("/api/runs/..%2f..%2fetc")
    assert r.status_code in (404, 405, 409), "traversal must not delete anything"
    assert (tmp_path / "t__a").exists(), "no unrelated directory was touched"


def test_run_summary_carries_grouping_fields(client):
    runs = client.get("/api/runs").json()
    for r in runs:
        assert "alias" in r and "trial" in r and "calls" in r


def test_stop_run_without_a_launch_is_reported(client):
    assert client.post("/api/runs/t__a/stop").json()["stopped"] is False


def test_delete_run_guard_rejects_traversal_at_the_function_level(client, tmp_path):
    import runs
    outside = tmp_path.parent / "should_survive"
    outside.mkdir(exist_ok=True)
    result = runs.delete_run("../should_survive")
    assert result["deleted"] is False
    assert outside.exists(), "delete_run must never touch anything outside the runs root"


def test_http_calls_endpoint(client, tmp_path):
    import json
    run = tmp_path / "t__a"
    (run / "http_calls.jsonl").write_text("\n".join([
        json.dumps({"operation": "search", "source": "llm", "document": "query{search}",
                    "status": 200, "success": True, "new_coverage": 2, "elapsed_ms": 12.0,
                    "data": '{"search":{"id":"1"}}', "errors": "", "error": None,
                    "round": 1, "arm": "a", "identity": "anon"}),
        json.dumps({"operation": "search", "source": "llm", "document": "query{search bad}",
                    "status": 200, "success": False, "new_coverage": 0, "elapsed_ms": 5.0,
                    "data": "", "errors": '[{"message":"boom"}]', "error": None,
                    "round": 1, "arm": "a", "identity": "anon"}),
    ]) + "\n")
    calls = client.get("/api/runs/t__a/http-calls").json()
    assert len(calls) == 2
    assert calls[0]["operation"] == "search" and calls[0]["success"] is True
    assert calls[0]["new_coverage"] == 2
    assert calls[1]["success"] is False and "boom" in calls[1]["errors"]


def test_http_calls_empty_when_no_log(client):
    assert client.get("/api/runs/t__b/http-calls").json() == []
