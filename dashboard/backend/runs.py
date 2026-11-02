"""Read-only view over run artifacts.

Every function here reads the JSON the pipeline already writes — ``manifest.json``,
``journal.jsonl``, ``artifacts/*.json``, ``findings/*.json`` — and never mutates a
run. That read-only contract is what lets the dashboard run safely alongside a
live pipeline writing the same directories.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from config import runs_root


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _run_dirs() -> list[Path]:
    root = runs_root()
    if not root.exists():
        return []
    return [p for p in root.iterdir() if p.is_dir() and (p / "manifest.json").exists()]


def _artifact(run_dir: Path, key: str, default: Any = None) -> Any:
    return _read_json(run_dir / "artifacts" / f"{key}.json", default)


def _journal(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "journal.jsonl"
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


#: Journal events that mean a run has begun doing work. A baseline run
#: (run_fuzz4all) emits ``run_start``/``step_progress`` but no ``step_start``, so
#: matching only ``step_start`` would leave it stuck at "created" for its whole
#: life — which is why in-flight Fuzz4All runs never showed as running.
_ACTIVE_EVENTS = {"step_start", "step_progress", "run_start"}


def _status(events: list[dict[str, Any]]) -> str:
    """Terminal status of a run, from its journal."""
    finish = [e for e in events if e.get("event") == "run_finish"]
    if finish:
        reason = finish[-1].get("reason", "completed")
        return "completed" if reason == "completed" else reason
    if any(e.get("event") in _ACTIVE_EVENTS for e in events):
        return "running"
    return "created"


def list_runs() -> list[dict[str, Any]]:
    """Summaries for every run, newest first."""
    summaries = []
    for run_dir in _run_dirs():
        manifest = _read_json(run_dir / "manifest.json", {})
        events = _journal(run_dir)
        coverage = _artifact(run_dir, "coverage", {})
        findings = _artifact(run_dir, "findings", {})
        score = _artifact(run_dir, "score", {})
        budget = _budget(events)
        config = manifest.get("config", {})
        status, active = _effective_status(run_dir.name, run_dir, events)
        alias = config.get("alias", "")
        ablation = _ablation_label(config)
        generator = (config.get("providers") or {}).get("generator", "")
        summaries.append({
            "run_id": run_dir.name,
            "target": config.get("target", ""),
            "alias": alias,
            "api": _api_of(alias, ablation),
            "ablation": ablation,
            "kind": "baseline" if generator.startswith("baseline:") else "system",
            "arms": (config.get("strategy") or {}).get("arms", []),
            "fuzz4all_model": config.get("fuzz4all_model", ""),
            "trial": config.get("trial", 1),
            "mode": config.get("mode", ""),
            "providers": config.get("providers", {}),
            "started_at": manifest.get("started_at") or _first_ts(events),
            "status": status,
            "active": active,
            "operation_coverage": coverage.get("operation_coverage"),
            "element_coverage": coverage.get("element_coverage"),
            "field_path_coverage": coverage.get("field_path_coverage"),
            "confirmed": findings.get("confirmed", 0),
            "potential": findings.get("potential", 0),
            "precision": (score.get("confirmed") or {}).get("precision") if score else None,
            "recall": (score.get("confirmed") or {}).get("recall") if score else None,
            "tokens": budget.get("total_tokens", 0),
            "usd": budget.get("usd", 0.0),
            "calls": budget.get("calls", 0),
        })
    summaries.sort(key=lambda s: s.get("started_at") or "", reverse=True)
    return summaries


#: A run with no ``run_finish`` and no tracked process counts as "running" only
#: if its journal was written this recently — the fallback for a backend restart,
#: or for a run launched outside the dashboard (e.g. the campaign driver), where
#: the live process handle is gone but the run may still be progressing. Sized
#: generously: a single slow public-API introspection or LLM call can leave the
#: journal untouched for a couple of minutes without the run being dead.
_LIVENESS_WINDOW = 240.0


def _is_live(run_id: str, run_dir: Path) -> bool:
    """Best-effort: is this run actually still executing right now?"""
    try:
        import live
        launch = live.launch_for_run(run_id)
    except Exception:
        launch = None
    if launch is not None:
        if launch.process is not None:   # we hold the handle (no restart)
            return launch.alive()
        if launch.exit_code is not None:  # recorded as finished
            return False
    # No process handle (restart, or launched outside the dashboard): a very
    # recent journal write is evidence the run is still going.
    try:
        mtime = (run_dir / "journal.jsonl").stat().st_mtime
    except OSError:
        return False
    return (time.time() - mtime) < _LIVENESS_WINDOW


def _effective_status(run_id: str, run_dir: Path,
                      events: list[dict[str, Any]]) -> tuple[str, bool]:
    """Status + liveness. A killed run never writes ``run_finish``, so the journal
    alone would call it "running" forever; a run that is not actually executing is
    reported ``stopped`` instead — which is also what makes it deletable."""
    status = _status(events)
    if status != "running":
        return status, False
    if _is_live(run_id, run_dir):
        return "running", True
    return "stopped", False


def _ablation_label(config: dict[str, Any]) -> str:
    """The ablation a run belongs to, for the dashboard facet.

    v1-imported runs carry an ``ablation`` tag (base/aqg/scl/full). The current
    engine instead encodes an ablation in ``strategy.arms`` (``+RandomArm`` =
    no bandit, ``+NoBucket`` = no value reuse); without translating those here,
    the new ablation runs look like ordinary full-config runs and never appear as
    a distinct ablation on the Overview/Compare/Reliability facets.
    """
    tag = config.get("ablation", "")
    if tag:
        return tag
    arms = set((config.get("strategy") or {}).get("arms") or [])
    labels = []
    if "+RandomArm" in arms:
        labels.append("no-bandit")
    if "+NoBucket" in arms:
        labels.append("no-bucket")
    return "+".join(labels)


def _api_of(alias: str, ablation: str) -> str:
    """The API an alias names, independent of its ablation tag.

    Imported runs alias as ``<api>-<ablation>`` (e.g. ``countries-base``) so the
    four ablation variants stay distinct runs; the facet groups them back by API.
    """
    if ablation and alias.endswith(f"-{ablation}"):
        return alias[: -(len(ablation) + 1)]
    return alias


def _first_ts(events: list[dict[str, Any]]) -> str:
    return events[0].get("ts", "") if events else ""


def _budget(events: list[dict[str, Any]]) -> dict[str, Any]:
    finish = [e for e in events if e.get("event") == "run_finish"]
    return (finish[-1].get("budget") or {}) if finish else {}


def get_run(run_id: str) -> dict[str, Any] | None:
    """Full detail for one run."""
    run_dir = runs_root() / run_id
    if not (run_dir / "manifest.json").exists():
        return None
    manifest = _read_json(run_dir / "manifest.json", {})
    events = _journal(run_dir)
    return {
        "run_id": run_id,
        "manifest": manifest,
        "status": _effective_status(run_id, run_dir, events)[0],
        "progress": _latest_progress(events, manifest),
        "steps": _steps(events, manifest),
        "coverage": _artifact(run_dir, "coverage"),
        "known_good": _artifact(run_dir, "known_good", {}),
        "probe_results": _artifact(run_dir, "probe_results", {}),
        "findings": _artifact(run_dir, "findings", {"findings": []}),
        "score": _artifact(run_dir, "score"),
        "bandit": _artifact(run_dir, "bandit"),
        "chains": _artifact(run_dir, "chains"),
        "budget": _budget(events),
        "reports": _reports(run_dir),
    }


def _latest_progress(events: list[dict[str, Any]], manifest: dict[str, Any]) -> dict[str, Any] | None:
    """The most recent step_progress event, enriched with the run's budget caps.

    This is what the progress bar reads: which round, how many operations
    covered, how many requests sent, and how much of the token/USD budget spent.
    """
    prog = [e for e in events if e.get("event") == "step_progress"]
    if not prog:
        return None
    # Fold the metric fields across every tick. Coverage and security emit
    # disjoint keys (round/covered vs jobs_done/jobs_total), so a completed run
    # shows both bars, and a later phase never blanks an earlier phase's numbers.
    metrics = {
        "phase", "round", "total_rounds", "covered", "total", "requests",
        "tokens", "usd", "budget_tokens", "budget_usd", "consumed",
        "jobs_done", "jobs_total", "confirmed", "signals",
    }
    latest: dict[str, Any] = {"step": prog[-1].get("step")}
    for event in prog:
        for key in metrics:
            if key in event:
                latest[key] = event[key]
    budgets = manifest.get("budgets", {})
    latest.setdefault("budget_tokens", budgets.get("max_tokens"))
    latest.setdefault("budget_usd", budgets.get("max_usd"))
    return latest


def _steps(events: list[dict[str, Any]], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """The step rail: one entry per planned step, with status and metrics."""
    plan = manifest.get("plan", [])
    finished = {e["step"]: e for e in events
                if e.get("event") == "step_finish" and e.get("step")}
    skipped = {e["step"] for e in events if e.get("event") == "step_skip"}
    started = {e["step"] for e in events if e.get("event") == "step_start"}
    rail = []
    for name in plan:
        fin = finished.get(name)
        if fin:
            status = "pass" if fin.get("outcome") == "ok" else "fail"
        elif name in skipped:
            status = "skipped"
        elif name in started:
            status = "running"
        else:
            status = "pending"
        rail.append({
            "name": name,
            "status": status,
            "seconds": (fin or {}).get("seconds"),
            "note": (fin or {}).get("note", ""),
            "metrics": (fin or {}).get("metrics", {}),
            "error": (fin or {}).get("error"),
        })
    return rail


def _reports(run_dir: Path) -> list[str]:
    report_dir = run_dir / "report"
    return sorted(p.name for p in report_dir.iterdir()) if report_dir.exists() else []


def get_finding(run_id: str, finding_id: str) -> dict[str, Any] | None:
    run_dir = runs_root() / run_id
    return _read_json(run_dir / "findings" / f"{finding_id}.json")


def report_path(run_id: str, name: str) -> Path | None:
    """Path to a report file, validated to stay inside the run's *report* dir.

    Resolving before comparing is what closes ``report/../manifest.json``: that
    escapes the report directory even though it stays inside the run directory,
    so the check must be against the report dir, not the run dir.
    """
    report_dir = (runs_root() / run_id / "report").resolve()
    candidate = (report_dir / name).resolve()
    try:
        candidate.relative_to(report_dir)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def stats() -> dict[str, Any]:
    """Aggregate KPIs across all runs."""
    runs = list_runs()
    completed = [r for r in runs if r["status"] == "completed"]
    total_confirmed = sum(r["confirmed"] for r in runs)
    total_tokens = sum(r["tokens"] for r in runs)
    by_target: dict[str, int] = {}
    for r in runs:
        by_target[r["target"]] = by_target.get(r["target"], 0) + 1
    return {
        "runs": len(runs),
        "completed": len(completed),
        "confirmed_findings": total_confirmed,
        "total_tokens": total_tokens,
        "total_usd": round(sum(r["usd"] for r in runs), 4),
        "targets": len(by_target),
    }


def http_calls(run_id: str, limit: int = 1000) -> list[dict[str, Any]]:
    """Query->server exchanges for a run — the request each generated query made,
    and the response it got back. Empty when the coverage step has not run."""
    return _read_jsonl(runs_root() / run_id / "http_calls.jsonl", limit)


def llm_calls(run_id: str, limit: int = 500) -> list[dict[str, Any]]:
    """The run's LLM call log — what each step asked, and what it cost.

    Read from ``llm_calls.jsonl``, which the provider router appends to as calls
    happen. A run with no LLM configured simply has no file.
    """
    return _read_jsonl(runs_root() / run_id / "llm_calls.jsonl", limit)


def _read_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]


def delete_run(run_id: str) -> dict[str, Any]:
    """Delete a run directory. Path-validated to stay inside the runs root."""
    import shutil

    root = runs_root().resolve()
    target = (root / run_id).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return {"deleted": False, "reason": "invalid run id"}
    if not target.is_dir() or not (target / "manifest.json").exists():
        return {"deleted": False, "reason": "no such run"}
    shutil.rmtree(target, ignore_errors=True)
    return {"deleted": True, "run_id": run_id}
