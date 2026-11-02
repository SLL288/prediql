"""Security-results aggregate (RQ3 page), over a synthetic runs/ tree."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _score(tp, fp, fn, tn, **extra):
    p = tp / (tp + fp) if (tp + fp) else None
    r = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * p * r / (p + r)) if (p and r) else None
    m = {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r,
         "f1": f1, "coverage_conditioned_recall": r, "fp_cells": [], "fn_cells": [],
         "fn_uncovered_cells": []}
    return {"confirmed": m, "with_potential": m, "certification": "certified",
            "by_class": {}, "unlabelled_confirmed_cells": [], **extra}


def _write(root, run_id, *, app, model, mode, score):
    run = root / run_id
    (run / "artifacts").mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "started_at": "2026-01-01T00:00:00Z",
        "config": {"target": f"http://{app}/graphql", "alias": app, "mode": mode,
                   "providers": {"generator": model}, "trial": 1, "code_version": "abc123"},
        "plan": ["probe", "adjudicate", "score"]}))
    (run / "journal.jsonl").write_text(json.dumps({
        "seq": 1, "event": "run_finish", "reason": "completed",
        "budget": {"total_tokens": 1, "usd": 0.0}}) + "\n")
    (run / "artifacts" / "findings.json").write_text(json.dumps(
        {"findings": [], "confirmed": score["confirmed"]["tp"], "potential": 0}))
    (run / "artifacts" / "score.json").write_text(json.dumps(score))


@pytest.fixture
def tree(tmp_path, monkeypatch):
    monkeypatch.setenv("PREDIQL_RUNS_ROOT", str(tmp_path))
    _write(tmp_path, "injection__t1__a", app="injection", model="zai:glm", mode="full",
           score=_score(4, 0, 0, 0))
    _write(tmp_path, "idor__t1__b", app="idor", model="zai:glm", mode="full",
           score=_score(5, 0, 0, 2))
    _write(tmp_path, "dvga__t1__c", app="dvga", model="zai:glm", mode="full",
           score=_score(4, 0, 6, 1, post_hoc_labels=["importPaste::os_command_injection"],
                        without_post_hoc={"confirmed": _score(2, 1, 5, 1)["confirmed"]}))
    # a coverage-only run must be ignored
    _write(tmp_path, "ctry__t1__d", app="ctry", model="zai:glm", mode="coverage",
           score=_score(0, 0, 0, 0))
    (tmp_path / "ctry__t1__d" / "artifacts" / "score.json").unlink()
    return tmp_path


def test_summary_groups_by_model_and_pools(tree):
    import security
    s = security.summary()
    assert s["run_count"] == 3  # the coverage run without a score is excluded
    model = next(m for m in s["models"] if m["model"] == "glm")
    assert {r["app"] for r in model["rows"]} == {"injection", "idor", "dvga"}
    agg = model["aggregate"]
    assert agg["tp"] == 13 and agg["fn"] == 6 and agg["fp"] == 0
    assert agg["recall"] == pytest.approx(13 / 19)


def test_post_hoc_row_carries_the_before_metrics(tree):
    import security
    s = security.summary()
    assert s["any_post_hoc"] is True
    dvga = next(r for m in s["models"] for r in m["rows"] if r["app"] == "dvga")
    assert dvga["post_hoc_labels"] == ["importPaste::os_command_injection"]
    assert dvga["confirmed"]["tp"] == 4
    assert dvga["without_post_hoc"]["tp"] == 2 and dvga["without_post_hoc"]["fp"] == 1


def test_endpoint_serves_the_summary(tree):
    from fastapi.testclient import TestClient
    import app as app_module
    client = TestClient(app_module.app)
    r = client.get("/api/security/summary")
    assert r.status_code == 200
    assert r.json()["run_count"] == 3
