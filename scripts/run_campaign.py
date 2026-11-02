#!/usr/bin/env python3
"""Coverage campaign runner: 3x-trial coverage + Fuzz4All + ablation, in parallel.

Enumerates the full matrix (APIs x models x trials), skips any job already
complete (resumable — "use old runs"), and runs the rest through a bounded
worker pool. Coverage-level only: every PrediQL job runs ``--mode coverage`` so
no security probing or spend beyond generation happens.

Three job kinds:
  * coverage  — PrediQL default config (the full system), all models.
  * fuzz4all  — the Fuzz4All-style baseline (scripts/run_fuzz4all.py), all models.
  * ablation  — the 2x2x2 factorial over +RandomArm (no bandit), +NoBucket (no
                value reuse), and +NoFeedback (no self-correction), plus +Base
                (minimal-prompt LLM), on one representative model.

Usage:
    python scripts/run_campaign.py [--jobs 4] [--trials 3] [--only coverage,fuzz4all,ablation]
    python scripts/run_campaign.py --report        # best-model summary, no runs
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PY = str(REPO / ".venv" / "bin" / "python")
RUNS = REPO / "runs"

# 7 coverage APIs (alias -> endpoint). Public APIs + the local userwallet.
APIS = {
    "countries": "https://countries.trevorblades.com/graphql",
    "ehri": "https://portal.ehri-project.eu/api/graphql",
    "graphqlzero": "https://graphqlzero.almansi.me/api",
    "pokeapi": "https://beta.pokeapi.co/graphql/v1beta",
    "rickandmorty": "https://rickandmortyapi.com/graphql",
    "tcgdex": "https://api.tcgdex.net/v2/graphql",
    "userwallet": "http://127.0.0.1:4001/graphql",
    # Extensions toward GraphQLer's public set (GraphQLer's own Food Delivery
    # target, a json-graphql-server instance, and the live AniList API).
    "fooddelivery": "http://127.0.0.1:4007/graphql",
    "jsongraphql": "http://127.0.0.1:4006/",
    "anilist": "https://graphql.anilist.co",
}

MODELS = [
    "openrouter:z-ai/glm-5.3-flash",
    "openrouter:deepseek/deepseek-v4.1-flash",
    "openrouter:google/gemini-3.1-flash-lite",
    "openrouter:openai/gpt-6-luna",
    "openrouter:meta-llama/llama-3.1-8b-instruct",
    "openrouter:qwen/qwen3-32b",
]
# Representative model for the ablation (the two reviewer configs).
ABLATION_MODEL = "openrouter:z-ai/glm-5.3-flash"
# Each entry is the arm tuple for one ablation cell. Together with the full
# config they form the 2x2x2 factorial over bandit x value reuse x
# self-correction, plus +Base, the minimal-prompt LLM with none of them.
ABLATION_ARMS = [
    ("+RandomArm",), ("+NoBucket",), ("+RandomArm", "+NoBucket"),
    ("+NoFeedback",), ("+RandomArm", "+NoFeedback"), ("+NoBucket", "+NoFeedback"),
    ("+RandomArm", "+NoBucket", "+NoFeedback"),
    ("+Base",),
]
# Invalid runs are moved here (out of the runs/*/manifest.json glob) before a
# retry, so the engine starts fresh instead of resuming the broken attempt.
INVALID = RUNS / "_invalid"
# A run whose LLM calls failed at the provider this often is not a measurement.
MAX_LLM_FAILURE_RATE = 0.2

# Pacing, overridable per-launch (gentler for a rate-limited giant like pokeapi).
MAX_HTTP = 4
DELAY_MS = 50


def _run_is_valid(d: Path) -> bool:
    """A PrediQL coverage run counts only if it reached the API and its LLM worked.

    A network outage can end a run as "completed" with zero requests and 0%
    coverage; counting it would record an infrastructure failure as a result.
    """
    if not (d / "artifacts" / "coverage.json").exists():
        return False
    calls = d / "http_calls.jsonl"
    if not calls.exists() or calls.stat().st_size == 0:
        return False
    llm = d / "llm_calls.jsonl"
    n_llm = sum(1 for _ in open(llm)) if llm.exists() else 0
    journal = d / "journal.jsonl"
    failed = 0
    if journal.exists():
        for line in open(journal):
            if "llm error" in line.lower() or "failed after 3 attempts" in line:
                failed += 1
    return not n_llm or failed / n_llm < MAX_LLM_FAILURE_RATE


def _completed() -> set[tuple]:
    """Keys (alias, model_slug, trial, arms_tuple|'fuzz4all') with a valid result."""
    done = set()
    for m in glob.glob(str(RUNS / "*" / "manifest.json")):
        d = Path(m).parent
        if not (d / "artifacts" / "coverage.json").exists():
            continue
        try:
            c = json.load(open(m)).get("config", {})
        except Exception:
            continue
        model = (c.get("providers") or {}).get("generator", "")
        key_model = model.split("openrouter:")[-1]
        trial = c.get("trial")
        if c.get("baseline_source") == "fuzz4all" or (c.get("providers") or {}).get("generator") == "baseline:fuzz4all":
            done.add((c.get("alias"), c.get("fuzz4all_model", "").split("openrouter:")[-1], trial, "fuzz4all"))
        elif _run_is_valid(d):
            arms = tuple((c.get("strategy") or {}).get("arms") or [])
            done.add((c.get("alias"), key_model, trial, arms))
    return done


def _find_run(job: dict) -> Path | None:
    """The newest run directory whose config matches ``job``."""
    best, best_mtime = None, -1.0
    for m in glob.glob(str(RUNS / "*" / "manifest.json")):
        try:
            c = json.load(open(m)).get("config", {})
        except Exception:
            continue
        if (c.get("alias") == job["alias"] and c.get("trial") == job["trial"]
                and (c.get("providers") or {}).get("generator") == job["model"]
                and tuple((c.get("strategy") or {}).get("arms") or []) == tuple(job.get("arms") or ())):
            mtime = os.path.getmtime(m)
            if mtime > best_mtime:
                best, best_mtime = Path(m).parent, mtime
    return best


def _set_aside(d: Path) -> None:
    INVALID.mkdir(parents=True, exist_ok=True)
    d.rename(INVALID / f"{d.name}.{int(time.time())}")


def _jobs(trials: int, only: set[str]) -> list[dict]:
    jobs = []
    for trial in range(1, trials + 1):
        for alias, target in APIS.items():
            for model in MODELS:
                slug = model.split("openrouter:")[-1]
                if "coverage" in only:
                    jobs.append({"kind": "coverage", "alias": alias, "target": target,
                                 "model": model, "trial": trial, "arms": (),
                                 "key": (alias, slug, trial, ())})
                if "fuzz4all" in only:
                    jobs.append({"kind": "fuzz4all", "alias": alias, "target": target,
                                 "model": model, "trial": trial,
                                 "key": (alias, slug, trial, "fuzz4all")})
            if "ablation" in only:
                slug = ABLATION_MODEL.split("openrouter:")[-1]
                for arms in ABLATION_ARMS:
                    jobs.append({"kind": "ablation", "alias": alias, "target": target,
                                 "model": ABLATION_MODEL, "trial": trial, "arms": arms,
                                 "key": (alias, slug, trial, arms)})
    return jobs


def _cmd(job: dict) -> list[str]:
    if job["kind"] == "fuzz4all":
        # The run-id MUST include the model: without it, every model's fuzz4all
        # run for one (alias, trial) wrote the same directory and overwrote each
        # other, collapsing 6 models into 1 random survivor. Slashes/colons in
        # the slug are not filesystem-safe, so flatten them.
        slug = job["model"].split("openrouter:")[-1].replace("/", "-").replace(":", "-")
        rid = f"{job['alias']}__fuzz4all__{slug}__r{job['trial']}"
        return [PY, str(REPO / "scripts" / "run_fuzz4all.py"),
                "--target", job["target"], "--alias", job["alias"],
                "--model", job["model"], "--run-id", rid,
                "--trial", str(job["trial"]),
                "--budget", "15", "--batch", "5"]
    cmd = [PY, "-m", "prediql.cli", "run", "--target", job["target"],
           "--alias", job["alias"], "--trial", str(job["trial"]),
           "--mode", "coverage", "--provider", f"generator={job['model']}",
           # Gentler on public endpoints: fewer in-flight requests and a small
           # inter-request delay keep us under rate limits; the target also now
           # backs off on 429/503. Tunable per-launch for rate-limited giants.
           "--max-http", str(MAX_HTTP), "--delay-ms", str(DELAY_MS)]
    if job.get("arms"):
        cmd += ["--arms", ",".join(job["arms"])]
    return cmd


def _run_one(job: dict, logdir: Path, attempts: int = 3) -> tuple[dict, int, str]:
    tag = f"{job['kind']}.{job['alias']}.{job['model'].split('/')[-1]}.t{job['trial']}"
    if job.get("arms"):
        tag += "." + "".join(a.strip("+") for a in job["arms"])
    log = logdir / f"{tag}.log"
    rc = 1
    # Public APIs throttle introspection under parallel load, which the engine
    # reports as a step failure. Such failures are transient, so retry a few
    # times with backoff before giving up; the engine resumes, so a retry only
    # re-does the step that failed.
    for attempt in range(1, attempts + 1):
        with open(log, "w") as fh:
            if attempt > 1:
                fh.write(f"# retry attempt {attempt}\n")
                fh.flush()
            p = subprocess.run(_cmd(job), cwd=str(REPO), stdout=fh, stderr=subprocess.STDOUT)
        rc = p.returncode
        if rc == 0 and job["kind"] != "fuzz4all":
            # Exit code 0 is not enough: an outage can "complete" a run that
            # never reached the API. Set such a run aside and retry it fresh.
            d = _find_run(job)
            if d is None or not _run_is_valid(d):
                if d is not None:
                    _set_aside(d)
                with open(log, "a") as fh:
                    fh.write("\n# invalid run (no requests reached the API, or LLM provider failures); retrying\n")
                rc = 2
        if rc == 0:
            break
        time.sleep(30 * attempt)
    return job, rc, tag


def report() -> None:
    """Best-model summary: mean element coverage per model over the default (full) config."""
    per_model = defaultdict(list)
    for m in glob.glob(str(RUNS / "*" / "manifest.json")):
        d = Path(m).parent
        cov = d / "artifacts" / "coverage.json"
        if not cov.exists():
            continue
        try:
            c = json.load(open(m)).get("config", {})
            cj = json.load(open(cov))
        except Exception:
            continue
        gen = (c.get("providers") or {}).get("generator", "")
        if not gen.startswith("openrouter:"):
            continue  # skip baselines/imports
        if (c.get("strategy") or {}).get("arms"):
            continue  # default config only
        if c.get("alias") not in APIS:
            continue
        per_model[gen.split("openrouter:")[-1]].append(
            (c["alias"], c.get("trial"), cj.get("element_coverage"), cj.get("operation_coverage")))
    print(f"{'model':30} {'runs':>4} {'mean elem':>10} {'mean op':>8}")
    ranked = []
    for model, rows in per_model.items():
        els = [r[2] for r in rows if r[2] is not None]
        ops = [r[3] for r in rows if r[3] is not None]
        me = sum(els) / len(els) if els else 0
        mo = sum(ops) / len(ops) if ops else 0
        ranked.append((me, mo, model, len(rows)))
    for me, mo, model, n in sorted(ranked, reverse=True):
        print(f"{model:30} {n:>4} {me:>10.3f} {mo:>8.3f}")
    if ranked:
        best = max(ranked)
        print(f"\nBEST by mean element coverage: {best[2]} ({best[0]:.3f})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=4, help="concurrent runs")
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--only", default="coverage,fuzz4all,ablation")
    ap.add_argument("--apis", default="", help="restrict to these comma-separated aliases "
                    "(lets a scoped run avoid colliding with another driver)")
    ap.add_argument("--max-http", type=int, default=4, help="per-run HTTP concurrency")
    ap.add_argument("--delay-ms", type=int, default=50, help="per-run inter-request delay")
    ap.add_argument("--report", action="store_true", help="print best-model summary and exit")
    args = ap.parse_args()
    global MAX_HTTP, DELAY_MS
    MAX_HTTP, DELAY_MS = args.max_http, args.delay_ms
    if args.report:
        report()
        return 0

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    api_filter = {s.strip() for s in args.apis.split(",") if s.strip()}
    logdir = REPO / "runs" / "_campaign_logs"
    logdir.mkdir(parents=True, exist_ok=True)

    done = _completed()
    all_jobs = _jobs(args.trials, only)
    if api_filter:
        all_jobs = [j for j in all_jobs if j["alias"] in api_filter]
    todo = [j for j in all_jobs if j["key"] not in done]
    print(f"matrix: {len(all_jobs)} jobs | already complete: {len(all_jobs) - len(todo)} | to run: {len(todo)}")
    print(f"concurrency: {args.jobs}  kinds: {sorted(only)}  logs: {logdir}")
    sys.stdout.flush()

    ok = fail = 0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(_run_one, j, logdir): j for j in todo}
        for i, fut in enumerate(as_completed(futs), 1):
            job, rc, tag = fut.result()
            ok += rc == 0
            fail += rc != 0
            mins = (time.time() - t0) / 60
            print(f"[{i}/{len(todo)}] {'ok ' if rc == 0 else 'FAIL'} {tag}  "
                  f"(ok={ok} fail={fail}, {mins:.0f}m)")
            sys.stdout.flush()
    print(f"\ncampaign done: {ok} ok, {fail} failed, {(time.time()-t0)/60:.0f}m")
    report()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
