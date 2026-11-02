"""End-to-end: security run -> report in four formats (M5 exit criteria)."""

from __future__ import annotations

import json

import pytest
from graphql import parse  # noqa: F401 (proves graphql is importable in this env)

from prediql.engine.config import RunConfig, Strategy
from prediql.engine.context import RunContext
from prediql.runner import execute
from test_security_run import VulnerableReplay


def _config(**kw):
    base = dict(target_url="https://vuln.test/graphql", mode="security",
                strategy=Strategy(rounds=1, requests_per_operation=60, seed=5))
    base.update(kw)
    return RunConfig(**base)


async def test_report_writes_all_four_formats(tmp_path):
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target)
    await execute(config.with_(mode="report"), runs_root=tmp_path, force={"report"})

    report_dir = tmp_path / config.run_id() / "report"
    for name in ("index.html", "findings.sarif", "findings.csv", "summary.md"):
        assert (report_dir / name).exists(), f"missing {name}"


async def test_html_is_self_contained_and_shows_findings(tmp_path):
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target)
    await execute(config.with_(mode="report"), runs_root=tmp_path, force={"report"})

    htmltext = (tmp_path / config.run_id() / "report" / "index.html").read_text()
    assert htmltext.startswith("<!doctype html>")
    # Self-contained: no external resource loads (src=, href=, <link>, @import,
    # url(http...)). A target URL appearing as displayed text is fine.
    import re
    loaders = re.findall(r'(?:src|href)\s*=\s*["\']https?://|<link\b|@import|url\(\s*["\']?https?://',
                         htmltext, re.I)
    assert not loaders, f"report must load no external resources: {loaders[:2]}"
    assert "SQL Injection" in htmltext or "Command Injection" in htmltext


async def test_sarif_is_valid_2_1_0(tmp_path):
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target)
    await execute(config.with_(mode="report"), runs_root=tmp_path, force={"report"})

    doc = json.loads((tmp_path / config.run_id() / "report" / "findings.sarif").read_text())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "PrediQL"
    results = doc["runs"][0]["results"]
    assert results, "confirmed findings should appear as SARIF results"
    assert all("ruleId" in r and "level" in r for r in results)


async def test_csv_has_one_row_per_finding(tmp_path):
    target = VulnerableReplay()
    config = _config()
    await execute(config, runs_root=tmp_path, target=target)
    await execute(config.with_(mode="report"), runs_root=tmp_path, force={"report"})

    csv_text = (tmp_path / config.run_id() / "report" / "findings.csv").read_text()
    lines = [l for l in csv_text.splitlines() if l.strip()]
    findings = RunContext(config, runs_root=tmp_path).get("findings")
    assert len(lines) == 1 + len(findings["findings"]), "header + one row per finding"


async def test_full_mode_runs_cover_to_report(tmp_path):
    """`full` mode: introspect -> ... -> adjudicate -> score -> report, one shot."""
    import textwrap
    truth = tmp_path / "vuln.yaml"
    truth.write_text(textwrap.dedent("""
        target: {name: Vuln, slug: vuln}
        contracts:
          - operation: search
            vulnerable: true
            classes: [{id: sql_injection, evidence_kind: latency}]
          - operation: health
            vulnerable: false
    """), encoding="utf-8")

    target = VulnerableReplay()
    config = _config(mode="full")
    report = await execute(config, runs_root=tmp_path, target=target, truth_path=str(truth))
    assert report.ok, [s.error for s in report.steps if s.error]
    names = [s.name for s in report.steps]
    assert names[-1] == "report" and "score" in names and "plan_chains" in names

    run_dir = tmp_path / config.run_id()
    assert (run_dir / "report" / "index.html").exists()
    assert (run_dir / "report" / "summary.md").exists()
    summary = (run_dir / "report" / "summary.md").read_text()
    assert "Score vs ground truth" in summary


async def test_report_surfaces_judge_verdicts(tmp_path):
    """A judged potential shows the LLM second opinion in HTML and SARIF."""
    from prediql.reporting import html, sarif
    import json as _json

    findings = {"confirmed": 0, "potential": 1, "by_class": {}, "findings": [{
        "id": "p_echo_xss_reflected", "class": "xss_reflected", "title": "Reflected XSS",
        "severity": "medium", "state": "potential", "operation": "echo", "identity": "anon",
        "evidence_kind": "reflection", "oracle_verdict": "signal",
        "witness": {"matched": "payload reflected", "requests": [{"document": "q", "identity": "anon"}]},
        "judge_verdict": {"agrees": False, "confidence": 0.95,
                          "rationale": "Reflection in a JSON body is not executable XSS.",
                          "model": "glm-5.3-flash"},
    }]}
    h = html.render(target="t", run_id="r", coverage=None, findings=findings,
                    score=None, budget=None)
    assert "LLM judge" in h and "disagrees" in h and "not executable XSS" in h

    doc = _json.loads(sarif.render(findings["findings"], target="t"))
    assert doc["runs"][0]["results"][0]["properties"]["judge_verdict"]["agrees"] is False
