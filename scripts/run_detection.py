#!/usr/bin/env python3
"""Detection campaign: the security benchmark across all backbones.

Runs `--mode full` detection for every (app, model), skipping any that already
has a score.json (resumable). Detection mutates shared stateful apps (creates,
deletes, cross-user replay), so runs are issued SEQUENTIALLY — two runs against
the same app at once would race and corrupt the ground-truth comparison.

Per-app flags mirror scripts/run_security_benchmark.sh: idor/vvsm need their
identities, every app gets the OOB collaborator, and DVGA is run both
unauthenticated and with the authenticated-scan credentials.
"""
from __future__ import annotations

import argparse, glob, json, os, subprocess, sys, time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PY = str(REPO / ".venv" / "bin" / "python")
OOB = "host.docker.internal"

MODELS = [
    "openrouter:z-ai/glm-5.3-flash",
    "openrouter:deepseek/deepseek-v4.1-flash",
    "openrouter:google/gemini-3.1-flash-lite",
    "openrouter:openai/gpt-6-luna",
    "openrouter:meta-llama/llama-3.1-8b-instruct",
    "openrouter:qwen/qwen3-32b",
]

T = "security_benchmark/truth"
# (alias, truth, url, extra-flags)
APPS = [
    ("injection", f"{T}/injection.yaml", "http://127.0.0.1:4002/graphql", []),
    ("idor", f"{T}/idor.yaml", "http://127.0.0.1:8010/graphql",
     ["--identity", "alice:user=Authorization: Bearer alice_token_abc123",
      "--identity", "bob:user=Authorization: Bearer bob_token_xyz789"]),
    ("vvsm", f"{T}/vvsm.yaml", "http://127.0.0.1:8001/graphql",
     ["--identity", "alice:user=Authorization: Bearer alice_social_token"]),
    ("api-security", f"{T}/api-security.yaml", "http://127.0.0.1:4004/graphql", []),
    ("injection-patched", f"{T}/injection-patched.yaml", "http://127.0.0.1:4102/graphql", []),
    ("dvga-heldout", "templates/ground_truth/examples/dvga/dvga.yaml",
     "http://127.0.0.1:5013/graphql", []),
    ("dvga-heldout-auth", "templates/ground_truth/examples/dvga/dvga.yaml",
     "http://127.0.0.1:5013/graphql",
     ["--auth-arg", "username=admin", "--auth-arg", "password=changeme"]),
]


def _completed() -> set[tuple]:
    """(alias, model_slug) pairs that already have a scored run."""
    done = set()
    for m in glob.glob(str(REPO / "runs" / "*" / "manifest.json")):
        d = Path(m).parent
        if not (d / "artifacts" / "score.json").exists():
            continue
        try:
            c = json.load(open(m)).get("config", {})
        except Exception:
            continue
        model = (c.get("providers") or {}).get("generator", "").split("openrouter:")[-1]
        done.add((c.get("alias"), model))
    return done


def _cmd(alias, truth, url, extra, model, trial):
    return ([PY, "-m", "prediql.cli", "run", "--target", url, "--alias", alias,
             "--trial", str(trial), "--mode", "full", "--allow-destructive",
             "--provider", f"generator={model}", "--truth", truth,
             "--oob-host", OOB, "--max-http", "4", "--delay-ms", "50"] + extra)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trial", type=int, default=1)
    args = ap.parse_args()
    done = _completed()
    logdir = REPO / "runs" / "_campaign_logs"; logdir.mkdir(parents=True, exist_ok=True)

    jobs = []
    for model in MODELS:
        slug = model.split("openrouter:")[-1]
        for alias, truth, url, extra in APPS:
            if (alias, slug) in done:
                continue
            jobs.append((alias, truth, url, extra, model, slug))
    print(f"detection matrix: {len(MODELS)*len(APPS)} | complete: {len(MODELS)*len(APPS)-len(jobs)} | to run: {len(jobs)}", flush=True)

    ok = fail = 0
    t0 = time.time()
    for i, (alias, truth, url, extra, model, slug) in enumerate(jobs, 1):
        tag = f"detect.{alias}.{slug.split('/')[-1]}"
        log = logdir / f"{tag}.log"
        rc = 1
        for attempt in range(1, 3):  # one retry (apps can be transiently busy)
            with open(log, "w") as fh:
                p = subprocess.run(_cmd(alias, truth, url, extra, model, args.trial),
                                   cwd=str(REPO), stdout=fh, stderr=subprocess.STDOUT)
            rc = p.returncode
            if rc == 0:
                break
            time.sleep(5)
        ok += rc == 0; fail += rc != 0
        print(f"[{i}/{len(jobs)}] {'ok ' if rc==0 else 'FAIL'} {tag}  (ok={ok} fail={fail}, {(time.time()-t0)/60:.0f}m)", flush=True)
    print(f"\ndetection done: {ok} ok, {fail} failed, {(time.time()-t0)/60:.0f}m", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
