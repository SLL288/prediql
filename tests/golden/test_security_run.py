"""End-to-end security run against a recorded vulnerable API (M2 exit criteria).

Encodes docs/08 M2: DVGA-style injections confirmed with witnesses, and — the
anti-'2,130 findings' invariant — zero confirmations on read-only operations.
Deterministic and offline via the replay target.
"""

from __future__ import annotations

import pytest

from prediql.engine.config import RunConfig, Strategy
from prediql.engine.context import RunContext
from prediql.runner import execute

# A small vulnerable API: `search` is SQLi-able, `run` is command-injectable,
# `readFile` leaks files, `echo` merely reflects, `health` is clean.
INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "search", "type": {"kind": "OBJECT", "name": "Post"},
             "args": [{"name": "q", "type": {"kind": "NON_NULL",
                                             "ofType": {"kind": "SCALAR", "name": "String"}}}]},
            {"name": "run", "type": {"kind": "SCALAR", "name": "String"},
             "args": [{"name": "cmd", "type": {"kind": "SCALAR", "name": "String"}}]},
            {"name": "readFile", "type": {"kind": "SCALAR", "name": "String"},
             "args": [{"name": "path", "type": {"kind": "SCALAR", "name": "String"}}]},
            {"name": "echo", "type": {"kind": "SCALAR", "name": "String"},
             "args": [{"name": "text", "type": {"kind": "SCALAR", "name": "String"}}]},
            {"name": "health", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
        ]},
        {"name": "Post", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []},
            {"name": "title", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
    ]}}}

_PRODUCT = str(91_273 * 7)  # the oscmd sentinel


class VulnerableReplay:
    """A hand-written vulnerable server: reacts to payload *content*, like a real one."""

    def __init__(self):
        self.introspection = INTROSPECTION
        self.sent: list[str] = []

    async def introspect(self, identity):
        return self.introspection

    async def send(self, document, identity, *, variables=None):
        from prediql.targets.base import HttpResult
        self.sent.append(document)
        norm = " ".join(document.split())

        def result(body, elapsed=10.0, status=200):
            return HttpResult(document=document, identity=identity.name, status=status,
                              body=body, elapsed_ms=elapsed, variables=variables or {})

        # health: always clean.
        if "health" in norm:
            return result({"data": {"health": "ok"}})
        # search: SQL-injectable. A SQL breaker (single quote / boolean) provokes
        # an engine error; a time-based payload actually sleeps. A benign
        # double-quoted GraphQL value is NOT a breaker, so valid requests succeed.
        if norm.startswith("query { search"):
            if "sleep" in norm.lower() or "pg_sleep" in norm.lower():
                return result({"data": {"search": None}}, elapsed=5300.0)
            if "'" in norm or "1=1" in norm:
                return result({"errors": [{"message": "sqlite3.OperationalError: unrecognized"}]})
            return result({"data": {"search": {"id": "1", "title": "hello"}}})
        # run: command-injectable. If the payload contains a shell-math breakout,
        # the "shell" evaluates it and the product appears in the output.
        if norm.startswith("query { run"):
            if _PRODUCT_TRIGGER(norm):
                return result({"data": {"run": f"output {_PRODUCT}\n"}})
            return result({"data": {"run": "output"}})
        # readFile: path-traversable. A passwd traversal returns file content.
        if norm.startswith("query { readFile"):
            if "passwd" in norm:
                return result({"data": {"readFile": "root:x:0:0:root:/root:/bin/bash\n"}})
            return result({"data": {"readFile": "not found"}})
        # echo: reflects its input verbatim but executes nothing.
        if norm.startswith("query { echo"):
            import re
            m = re.search(r'text:\s*"((?:[^"\\]|\\.)*)"', norm)
            reflected = m.group(1) if m else ""
            return result({"data": {"echo": reflected}})
        # introspection.
        if "__schema" in norm:
            return result({"data": {"__schema": {"queryType": {"name": "Query"}}}})
        if "__thisFieldDoesNotExist" in norm:
            return result({"errors": [{"message": "Cannot query field '__thisFieldDoesNotExist'. "
                                                  "Did you mean '__schema'?"}]})
        return result({"data": {"__typename": "Query"}})

    async def aclose(self):
        pass


def _PRODUCT_TRIGGER(norm: str) -> bool:
    """The 'shell' evaluates arithmetic only when a breakout metachar is present."""
    return any(tok in norm for tok in ("$((", "expr ", "`expr", "$(expr")) and "91273" in norm


def _config(**kw) -> RunConfig:
    base = dict(target_url="https://vuln.test/graphql", mode="security",
                strategy=Strategy(rounds=1, requests_per_operation=60, seed=5))
    base.update(kw)
    return RunConfig(**base)


@pytest.fixture
def vuln_target():
    return VulnerableReplay()


async def test_security_run_completes_all_steps(tmp_path, vuln_target):
    report = await execute(_config(), runs_root=tmp_path, target=vuln_target)
    assert report.ok, [s.error for s in report.steps if s.error]
    assert [s.name for s in report.steps] == [
        "introspect", "compile", "seed_identities", "cover", "validate",
        "probe", "adjudicate",
    ]


async def test_confirms_the_real_injections_with_witnesses(tmp_path, vuln_target):
    config = _config()
    await execute(config, runs_root=tmp_path, target=vuln_target)
    findings = RunContext(config, runs_root=tmp_path).get("findings")

    confirmed = {f["operation"]: f for f in findings["findings"] if f["state"] == "confirmed"}
    # SQLi on search (via time-based refinement), oscmd on run, path traversal on readFile.
    assert "search" in confirmed
    assert confirmed["search"]["class"] == "sql_injection"
    assert "run" in confirmed and confirmed["run"]["class"] == "os_command_injection"
    assert "readFile" in confirmed and confirmed["readFile"]["class"] == "path_traversal"

    for finding in confirmed.values():
        assert finding["witness"]["requests"], "a confirmed finding must carry its request"
        assert finding["witness"]["matched"], "and the concrete evidence it matched"
        assert finding["repro"].startswith("predql repro")


async def test_read_only_operations_manufacture_no_confirmation(tmp_path, vuln_target):
    """The anti-'2,130 findings' invariant, end to end."""
    config = _config()
    await execute(config, runs_root=tmp_path, target=vuln_target)
    findings = RunContext(config, runs_root=tmp_path).get("findings")

    for finding in findings["findings"]:
        if finding["state"] == "confirmed":
            assert finding["operation"] != "health", "a clean endpoint cannot be confirmed"
    # `echo` reflects but never executes -> at most a potential, never confirmed.
    echo = [f for f in findings["findings"] if f["operation"] == "echo"]
    assert all(f["state"] == "potential" for f in echo), "reflection is not confirmation"


async def test_path_traversal_confirmed_by_content_not_reflection(tmp_path, vuln_target):
    """Directly exercises GraphQLer's documented gap."""
    config = _config()
    await execute(config, runs_root=tmp_path, target=vuln_target)
    findings = RunContext(config, runs_root=tmp_path).get("findings")
    pt = next(f for f in findings["findings"]
              if f["operation"] == "readFile" and f["state"] == "confirmed")
    assert pt["evidence_kind"] == "sentinel"
    assert "root:x:0:0" in pt["witness"]["matched"]


async def test_finding_files_are_written_per_issue(tmp_path, vuln_target):
    config = _config()
    await execute(config, runs_root=tmp_path, target=vuln_target)
    run_dir = tmp_path / config.run_id()
    files = list((run_dir / "findings").glob("*.json"))
    assert files, "adjudicate must write one file per finding"


async def test_family_isolation_limits_findings_to_that_class(tmp_path, vuln_target):
    """`--families` is both the isolated run and the RQ3 ablation."""
    config = _config(families=("path_traversal",))
    await execute(config, runs_root=tmp_path, target=vuln_target)
    findings = RunContext(config, runs_root=tmp_path).get("findings")
    classes = {f["class"] for f in findings["findings"]}
    assert classes <= {"path_traversal"}, classes
    assert any(f["state"] == "confirmed" for f in findings["findings"])


async def test_probe_trace_is_recorded_for_the_dashboard(tmp_path, vuln_target):
    config = _config()
    await execute(config, runs_root=tmp_path, target=vuln_target)
    probe = RunContext(config, runs_root=tmp_path).get("probe_results")
    assert probe["results"], "the full payload trace must be persisted"
    stages = {r["stage"] for r in probe["results"]}
    assert "time-based" in stages, "refinement stages appear in the trace"
    # Every result carries what the dashboard shows: input, verdict, reasoning.
    for r in probe["results"]:
        assert r["document"] and r["verdict"] and "detail" in r
