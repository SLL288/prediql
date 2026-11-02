"""Live launcher: spawn a pipeline run and stream its progress (doc 05 §3).

Spawns ``python -m prediql.cli run`` as a subprocess. Because a run's directory
name is deterministic (`RunConfig.run_id()`), the launcher locates the
``journal.jsonl`` the run creates and tails it to produce Server-Sent-Events —
the same "deterministic run dir + journal tail" approach autosec uses, with no
handshake between launcher and run.

Two properties this module is careful about:

* **The child's stdout is drained continuously.** A pipe holds ~64 KB; a child
  that fills it blocks forever on its next write. Every real run prints more than
  that, so an unread pipe would hang the run partway through. A reader thread
  drains stdout into a bounded ring buffer, which doubles as the log the UI shows.
* **Launch records are disk-durable.** They are written under
  ``<runs_root>/.launches/`` and reloaded by :func:`recover` at startup, so a
  backend restart does not lose the launch history (autosec's ``live.recover()``).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

from config import REPO_ROOT, runs_root

# Selectable options for the launcher UI.
MODES = ["coverage", "security", "chains", "full"]
FAMILIES = ["sql_injection", "os_command_injection", "path_traversal",
            "xss_reflected", "introspection_enabled", "denial_of_service"]
#: Lines of child stdout kept per launch. Bounded so a long run cannot grow
#: memory without limit; the journal is the durable record, not this.
LOG_LINES = 400


def _launch_dir() -> Path:
    path = runs_root() / ".launches"
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class Launch:
    launch_id: str
    run_id: str
    target: str
    mode: str
    cmd: list[str]
    trial: int = 1
    trials: int = 1
    model: str = "heuristic"
    started_at: float = field(default_factory=time.time)
    process: subprocess.Popen | None = None
    log: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_LINES))
    exit_code: int | None = None
    cancelled: bool = False
    _reader: threading.Thread | None = None

    # -- lifecycle --------------------------------------------------------

    def drain(self) -> None:
        """Continuously read the child's stdout so it can never block on a full pipe."""
        if self.process is None or self.process.stdout is None:
            return

        def _pump() -> None:
            assert self.process is not None and self.process.stdout is not None
            try:
                for line in self.process.stdout:
                    self.log.append(line.rstrip("\n"))
            except (ValueError, OSError):
                pass  # pipe closed on terminate
            finally:
                self.exit_code = self.process.wait()
                self.persist()

        self._reader = threading.Thread(target=_pump, daemon=True)
        self._reader.start()

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def signal_stop(self) -> bool:
        if not self.alive():
            return False
        assert self.process is not None
        self.process.terminate()
        return True

    # -- persistence ------------------------------------------------------

    def record(self) -> dict[str, Any]:
        return {
            "launch_id": self.launch_id,
            "run_id": self.run_id,
            "target": self.target,
            "mode": self.mode,
            "trial": self.trial,
            "trials": self.trials,
            "model": self.model,
            "started_at": self.started_at,
            "alive": self.alive(),
            "queued": self.process is None and self.exit_code is None,
            "exit_code": self.exit_code,
            "log_tail": list(self.log)[-20:],
        }

    def persist(self) -> None:
        payload = {k: v for k, v in self.record().items() if k != "log_tail"}
        payload["cmd"] = self.cmd
        payload["pid"] = self.process.pid if self.process else None
        try:
            (_launch_dir() / f"{self.launch_id}.json").write_text(
                json.dumps(payload, default=str), encoding="utf-8"
            )
        except OSError:
            pass  # a launch record is a convenience, never load-bearing

    @classmethod
    def from_record(cls, data: dict[str, Any]) -> "Launch":
        launch = cls(
            launch_id=data["launch_id"], run_id=data.get("run_id", ""),
            target=data.get("target", ""), mode=data.get("mode", ""),
            cmd=data.get("cmd", []), started_at=float(data.get("started_at", 0.0)),
            trial=int(data.get("trial", 1)), trials=int(data.get("trials", 1)),
            model=data.get("model", "heuristic"),
        )
        launch.exit_code = data.get("exit_code")
        return launch


_LAUNCHES: dict[str, Launch] = {}


def options() -> dict[str, Any]:
    """Selectable options for the launcher, including the model catalog."""
    root = str(REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from prediql.providers.catalog import all_models
    from prediql.providers.env import configured_vendors
    from prediql.providers.registry import PROVIDERS, supported

    hosted = tuple(v for v, spec in PROVIDERS.items() if spec.hosted)
    return {
        "modes": MODES,
        "families": FAMILIES,
        "vendors": supported(),
        "models": [m.to_dict() for m in all_models()],
        # Which vendors can authenticate, and from which variable — so a
        # cross-vendor sweep is warned about before it fails halfway through.
        "keys": configured_vendors(hosted),
    }


def credentials_for(model_ref: str) -> dict[str, Any]:
    """Environment requirements for one ``vendor:model``, and whether they are met."""
    root = str(REPO_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    from prediql.providers.env import key_requirements

    vendor = (model_ref or "").partition(":")[0].strip().lower()
    if not vendor or vendor == "heuristic":
        return {"vendor": vendor, "ready": True, "requirements": {}}
    requirements = key_requirements(vendor)
    return {
        "vendor": vendor,
        "ready": all(requirements.values()),
        "requirements": requirements,
        "missing": [k for k, ok in requirements.items() if not ok],
    }


def launch_for_run(run_id: str) -> "Launch | None":
    """The most recent launch that produced (or is producing) ``run_id``."""
    matches = [ln for ln in _LAUNCHES.values() if ln.run_id == run_id]
    return max(matches, key=lambda l: l.started_at) if matches else None


def is_run_active(run_id: str) -> bool:
    ln = launch_for_run(run_id)
    return bool(ln and ln.alive())


def stop_run(run_id: str) -> dict[str, Any]:
    ln = launch_for_run(run_id)
    if ln is None:
        return {"stopped": False, "reason": "no launch for this run"}
    return stop(ln.launch_id)


def recover() -> dict[str, Any]:
    """Reload launch records from disk. Safe to call repeatedly."""
    restored = 0
    for path in sorted(_launch_dir().glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if data.get("launch_id") in _LAUNCHES:
            continue
        _LAUNCHES[data["launch_id"]] = Launch.from_record(data)
        restored += 1
    return {"restored": restored, "total": len(_LAUNCHES)}


def _providers_for(spec: dict[str, Any], generator: str) -> dict[str, str]:
    """Provider map for one point in the sweep."""
    providers = dict(spec["fixed_providers"])
    if generator and generator != "heuristic":
        providers["generator"] = generator
    return providers


def _seed_for(spec: dict[str, Any], trial: int) -> int:
    """Per-trial seed: replicates must differ, or repeated trials collapse to one
    sample (temperature 0 + a fixed Thompson seed is otherwise deterministic).
    Trial 1 keeps the base seed, so single runs are unchanged."""
    return int(spec["seed"]) + trial - 1


def _predql_run_id(spec: dict[str, Any], trial: int, generator: str) -> str:
    """Recompute the deterministic run id the CLI will produce, to find its dir."""
    root = str(REPO_ROOT)
    if root not in sys.path:  # insert once, not per call
        sys.path.insert(0, root)
    from prediql.engine import provenance
    from prediql.engine.config import RunConfig, Strategy

    config = RunConfig(
        target_url=spec["target"], alias=spec["alias"], trial=trial,
        mode=spec["mode"], providers=_providers_for(spec, generator),
        code_version=provenance.code_version(),
        model_prices=spec["prices"], families=tuple(spec["families"]),
        strategy=Strategy(rounds=spec["rounds"], requests_per_operation=spec["requests"],
                          seed=_seed_for(spec, trial), max_operations=spec["max_operations"],
                          judge_samples=spec["judge_samples"]),
    )
    return config.run_id()


def _normalize(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate and default a launch payload into one canonical spec."""
    target = (payload.get("target") or "").strip()
    if not target:
        raise ValueError("target is required")

    prices: dict[str, tuple[float, float]] = {}

    def _price(ref: str) -> None:
        # A custom model carries its own price, since the catalog has no entry.
        rate = (payload.get("model_prices") or {}).get(ref)
        if rate and len(rate) == 2:
            prices[ref] = (float(rate[0]), float(rate[1]))

    # The sweep axis: one or more generator models, possibly across vendors.
    # `generators` (list) is the sweep; `generator` (string) is the single-model
    # shorthand. "heuristic" means no LLM generator, and is a valid sweep member —
    # it is the zero-cost baseline every LLM arm should be measured against.
    raw_generators = payload.get("generators")
    if not raw_generators:
        raw_generators = [payload.get("generator") or "heuristic"]
    generators: list[str] = []
    for ref in raw_generators:
        ref = (ref or "").strip()
        if ref and ref not in generators:
            generators.append(ref)
            if ref != "heuristic":
                _price(ref)
    if not generators:
        generators = ["heuristic"]

    # Non-swept roles are fixed across the whole sweep.
    fixed: dict[str, str] = {}
    for role in ("judge", "resolver"):
        value = (payload.get(role) or "").strip()
        if value and value != "heuristic":
            fixed[role] = value
            _price(value)

    return {
        "generators": generators,
        "fixed_providers": fixed,
        "target": target,
        "alias": (payload.get("alias") or "").strip(),
        "mode": payload.get("mode", "coverage"),
        "rounds": int(payload.get("rounds", 2)),
        "requests": int(payload.get("requests", 5)),
        "seed": int(payload.get("seed", 42)),
        "families": payload.get("families") or [],
        "max_operations": payload.get("max_operations") or None,
        "judge_samples": int(payload.get("judge_samples", 1)),
        "prices": prices,
        "truth": payload.get("truth"),
        "trials": max(1, int(payload.get("trials", 1))),
    }


def _build_cmd(spec: dict[str, Any], trial: int, generator: str) -> list[str]:
    cmd = [sys.executable, "-m", "prediql.cli", "run",
           "--target", spec["target"], "--mode", spec["mode"],
           "--trial", str(trial),
           "--rounds", str(spec["rounds"]), "--requests", str(spec["requests"]),
           "--seed", str(_seed_for(spec, trial)), "--runs-root", str(runs_root())]
    if spec["alias"]:
        cmd += ["--alias", spec["alias"]]
    for role, model in _providers_for(spec, generator).items():
        cmd += ["--provider", f"{role}={model}"]
    for model, (pin, pout) in spec["prices"].items():
        cmd += ["--model-price", f"{model}={pin},{pout}"]
    if spec["families"]:
        cmd += ["--families", ",".join(spec["families"])]
    if spec["max_operations"]:
        cmd += ["--max-operations", str(spec["max_operations"])]
    if spec["judge_samples"] > 1:
        cmd += ["--judge-samples", str(spec["judge_samples"])]
    if spec["truth"]:
        cmd += ["--truth", spec["truth"]]
    return cmd


def _spawn(spec: dict[str, Any], trial: int, generator: str, launch_id: str) -> Launch:
    cmd = _build_cmd(spec, trial, generator)
    proc = subprocess.Popen(
        cmd, cwd=str(REPO_ROOT), env=dict(os.environ),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    ln = Launch(launch_id=launch_id, run_id=_predql_run_id(spec, trial, generator),
                target=spec["target"], mode=spec["mode"], cmd=cmd, process=proc,
                trial=trial, trials=spec["trials"], model=generator)
    ln.drain()  # start reading immediately — an unread pipe deadlocks the run
    _LAUNCHES[launch_id] = ln
    ln.persist()
    return ln


def launch(payload: dict[str, Any]) -> dict[str, Any]:
    """Start a run, or a sequential batch of ``trials`` replicates.

    Trials run **one at a time**: concurrent runs against the same target contend
    for it and distort the per-operation latency baselines the timing oracles
    depend on, which is exactly how a false DoS confirmation was produced during
    development.
    """
    spec = _normalize(payload)
    base = int(time.time() * 1000)

    # The full sweep: every generator model x every trial. Each point gets its own
    # run directory, because the provider map is part of a run's identity.
    matrix = [(g, t) for g in spec["generators"] for t in range(1, spec["trials"] + 1)]
    launches = [
        Launch(launch_id=f"L{base}-{i}", run_id=_predql_run_id(spec, trial, generator),
               target=spec["target"], mode=spec["mode"],
               cmd=_build_cmd(spec, trial, generator),
               trial=trial, trials=spec["trials"], model=generator)
        for i, (generator, trial) in enumerate(matrix)
    ]
    for ln in launches:
        _LAUNCHES[ln.launch_id] = ln
        ln.persist()

    first = _spawn(spec, matrix[0][1], matrix[0][0], launches[0].launch_id)

    if len(matrix) > 1:
        def _run_remaining() -> None:
            """Run the rest of the sweep one at a time.

            Sequential by design: concurrent runs contend for the same target and
            distort the per-operation latency baselines the timing oracles rely on.
            """
            for index in range(1, len(matrix)):
                previous = _LAUNCHES.get(f"L{base}-{index - 1}")
                while previous is not None and previous.alive():
                    time.sleep(0.5)
                pending = _LAUNCHES.get(f"L{base}-{index}")
                if pending is None or pending.cancelled:
                    continue  # deleted from the queue before it could start
                generator, trial = matrix[index]
                _spawn(spec, trial, generator, f"L{base}-{index}")

        threading.Thread(target=_run_remaining, daemon=True).start()

    # Read the records back out of the registry: _spawn replaces the placeholder
    # for the first point, so returning the originals would report it as queued
    # when it is already running.
    return {
        "launches": [_LAUNCHES[ln.launch_id].record() for ln in launches],
        "primary": first.record(),
        "sweep": {"models": spec["generators"], "trials": spec["trials"],
                  "runs": len(matrix)},
    }


def get(launch_id: str) -> Launch | None:
    return _LAUNCHES.get(launch_id)


def list_launches(limit: int = 50) -> list[dict[str, Any]]:
    ordered = sorted(_LAUNCHES.values(), key=lambda x: x.started_at, reverse=True)
    return [ln.record() for ln in ordered[:limit]]


def stop(launch_id: str) -> dict[str, Any]:
    ln = _LAUNCHES.get(launch_id)
    if ln is None:
        return {"stopped": False, "reason": "unknown launch"}
    stopped = ln.signal_stop()
    ln.persist()
    return {"stopped": stopped, "reason": "" if stopped else "not running"}


def delete_launch(launch_id: str) -> dict[str, Any]:
    """Remove a launch from the queue. Refuses one that is still running."""
    ln = _LAUNCHES.get(launch_id)
    if ln is not None and ln.alive():
        return {"deleted": False, "reason": "launch is running; stop it first"}
    if ln is not None:
        ln.cancelled = True  # a queued point must not be spawned after removal
        _LAUNCHES.pop(launch_id, None)
    try:
        (_launch_dir() / f"{launch_id}.json").unlink(missing_ok=True)
    except OSError:
        pass
    return {"deleted": True, "launch_id": launch_id}


def launch_fuzz4all(payload: dict[str, Any]) -> dict[str, Any]:
    """Launch the Fuzz4All-style GraphQL baseline as a subprocess.

    It writes the same run-dir + journal as any run, so the existing ``stream``
    and run views work unchanged; results land as a ``baseline:fuzz4all`` run.
    """
    target = payload["target"]
    alias = payload["alias"]
    model = payload["model"]
    trial = int(payload.get("trial", 1))
    budget = int(payload.get("budget", 20))
    run_id = f"{alias}__fuzz4all__r{trial}"
    cmd = [sys.executable, "scripts/run_fuzz4all.py",
           "--target", target, "--alias", alias, "--model", model,
           "--run-id", run_id, "--trial", str(trial), "--budget", str(budget),
           "--runs-root", str(runs_root())]
    proc = subprocess.Popen(
        cmd, cwd=str(REPO_ROOT), env=dict(os.environ),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )
    launch_id = f"F{int(time.time())}"
    ln = Launch(launch_id=launch_id, run_id=run_id, target=target, mode="fuzz4all",
                cmd=cmd, process=proc, model=model)
    ln.drain()
    _LAUNCHES[launch_id] = ln
    ln.persist()
    return {"launch_id": launch_id, "run_id": run_id}


async def stream(launch_id: str) -> AsyncIterator[str]:
    """Yield SSE frames by tailing the run's journal until it terminates."""
    ln = _LAUNCHES.get(launch_id)
    if ln is None:
        yield _sse("failed", {"message": "unknown launch"})
        return

    journal = runs_root() / ln.run_id / "journal.jsonl"
    yield _sse("launched", ln.record())
    offset = 0
    saw_finish = False
    # Once the process exits, make one final pass so a fast run's tail is not lost.
    grace_passes = 0

    while True:
        if journal.exists():
            with journal.open("r", encoding="utf-8") as handle:
                handle.seek(offset)
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    yield _sse("journal", event)
                    if event.get("event") == "run_finish":
                        saw_finish = True
                offset = handle.tell()

        if saw_finish:
            break
        if not ln.alive():
            grace_passes += 1
            if grace_passes > 2:
                # The process ended without a run_finish: a plan error or a crash.
                # The drained log is the only explanation available, so send it.
                yield _sse("failed", {
                    "message": f"run exited (code {ln.exit_code}) without finishing",
                    "log": list(ln.log)[-25:],
                })
                return
        await asyncio.sleep(0.35)

    yield _sse("done", {"run_id": ln.run_id, "exit_code": ln.exit_code})


def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"
