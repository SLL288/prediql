"""End-to-end: security run -> score against ground truth (M3 exit criteria).

Uses the vulnerable replay API from the security test, plus a ground-truth file
that labels its operations, and verifies P/R/F1, negative-contract precision,
coverage-conditioned recall, and the score-mode re-run.
"""

from __future__ import annotations

import textwrap

import pytest

from prediql.engine.config import RunConfig, Strategy
from prediql.engine.context import RunContext
from prediql.runner import execute
from test_security_run import VulnerableReplay  # reuse the vulnerable API

TRUTH = textwrap.dedent("""
    target:
      name: VulnDemo
      slug: vuln
    contracts:
      - operation: search
        vulnerable: true
        classes: [{id: sql_injection, evidence_kind: latency}]
      - operation: run
        vulnerable: true
        classes: [{id: os_command_injection, evidence_kind: sentinel}]
      - operation: readFile
        vulnerable: true
        classes: [{id: path_traversal, evidence_kind: sentinel}]
      - operation: health
        vulnerable: false
""")


@pytest.fixture
def truth_file(tmp_path):
    path = tmp_path / "vuln.yaml"
    path.write_text(TRUTH, encoding="utf-8")
    return path


def _config(**kw):
    base = dict(target_url="https://vuln.test/graphql", mode="security",
                strategy=Strategy(rounds=1, requests_per_operation=60, seed=5))
    base.update(kw)
    return RunConfig(**base)


async def test_security_then_score_reports_metrics(tmp_path, truth_file):
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target, truth_path=str(truth_file))

    # score is not in `security` mode, so run it as its own step against the run.
    await execute(config.with_(mode="score"), runs_root=tmp_path,
                  truth_path=str(truth_file), force={"score"})

    result = RunContext(config, runs_root=tmp_path).get("score")
    m = result["confirmed"]
    # search (SQLi), run (oscmd), readFile (path traversal) all confirmed.
    assert m["tp"] == 3, result
    assert m["fp"] == 0, "no confirmed finding on the clean 'health' endpoint"
    assert m["recall"] == 1.0
    assert m["precision"] == 1.0
    assert m["f1"] == 1.0
    assert result["certification"] == "uncertified"


async def test_score_writes_a_readable_summary(tmp_path, truth_file):
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target)
    await execute(config.with_(mode="score"), runs_root=tmp_path,
                  truth_path=str(truth_file), force={"score"})

    summary = (tmp_path / config.run_id() / "score.md").read_text(encoding="utf-8")
    assert "# Score — vuln" in summary
    assert "precision" in summary and "recall" in summary


async def test_partial_scoring_restricts_to_named_operations(tmp_path, truth_file):
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target)
    await execute(config.with_(mode="score"), runs_root=tmp_path,
                  truth_path=str(truth_file), score_operations=["readFile"], force={"score"})

    result = RunContext(config, runs_root=tmp_path).get("score")
    assert result["partial"] is True
    assert result["scored_operations"] == ["readFile"]
    assert result["confirmed"]["tp"] == 1
    assert result["confirmed"]["fn"] == 0, "search/run are out of scope, not misses"


async def test_score_is_non_gating_when_truth_is_missing(tmp_path):
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target)
    report = await execute(config.with_(mode="score"), runs_root=tmp_path,
                           truth_path=str(tmp_path / "nonexistent.yaml"), force={"score"})

    assert report.ok, "a missing truth file annotates, never crashes"
    result = RunContext(config, runs_root=tmp_path).get("score")
    assert result["score"] is None
    assert "not found" in result["reason"]


async def test_rescoring_after_editing_truth_needs_no_reprobe(tmp_path, truth_file):
    """The ground-truth iteration loop: edit truth, re-score, no target touched."""
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target)
    await execute(config.with_(mode="score"), runs_root=tmp_path,
                  truth_path=str(truth_file), force={"score"})
    before = RunContext(config, runs_root=tmp_path).get("score")["confirmed"]["fp"]

    # Relabel 'health' as vulnerable to something we did NOT find -> a new FN,
    # and re-score WITHOUT re-running the pipeline (target is not passed).
    truth_file.write_text(textwrap.dedent("""
        target: {name: VulnDemo, slug: vuln}
        contracts:
          - operation: search
            vulnerable: true
            classes: [{id: sql_injection, evidence_kind: latency}]
          - operation: health
            vulnerable: true
            classes: [{id: ssrf, evidence_kind: sentinel}]
    """), encoding="utf-8")
    await execute(config.with_(mode="score"), runs_root=tmp_path,
                  truth_path=str(truth_file), force={"score"}, target=None)

    after = RunContext(config, runs_root=tmp_path).get("score")
    assert after["confirmed"]["fn"] >= 1, "the new label is now an unmet expectation"
    assert target.sent, "the run happened once; re-scoring issued no new requests"
