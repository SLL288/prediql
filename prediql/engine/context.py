"""Per-run state: the artifact store, journal, and budget ledger.

``RunContext`` is the explicit replacement for v1's module-level ``Config``
singleton. Steps receive it as a parameter and never reach for globals, so
several runs coexist in one process and every step's inputs are visible in its
signature rather than hidden in import-time state.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from prediql.engine import provenance
from prediql.engine.budget import BudgetLedger
from prediql.engine.config import RunConfig
from prediql.engine.fingerprint import fingerprint
from prediql.engine.journal import Event, Journal


class ArtifactStore:
    """Typed, on-disk key/value store for one run.

    Artifacts are JSON documents under ``artifacts/``; ``state.json`` indexes
    them with the fingerprint each was written under. The index is a cache —
    it can always be rebuilt by re-reading the directory — but keeping it means
    resume does not have to parse every artifact to decide what to skip.
    """

    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.dir = self.run_dir / "artifacts"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.run_dir / "state.json"
        self._lock = threading.RLock()
        self._cache: dict[str, Any] = {}
        self._index: dict[str, dict[str, Any]] = self._load_index()

    def _load_index(self) -> dict[str, dict[str, Any]]:
        if not self.index_path.exists():
            return {}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
            return dict(data.get("artifacts", {}))
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_index(self) -> None:
        payload = {"artifacts": self._index}
        tmp = self.index_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        tmp.replace(self.index_path)  # atomic: never leave a half-written index

    @staticmethod
    def _safe(key: str) -> str:
        """Artifact keys become filenames, so keep them to a safe charset."""
        return "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in key)

    def path_for(self, key: str) -> Path:
        return self.dir / f"{self._safe(key)}.json"

    def put(self, key: str, value: Any, *, step: str) -> str:
        """Write an artifact and return its fingerprint."""
        with self._lock:
            fp = fingerprint(value)
            self.path_for(key).write_text(
                json.dumps(value, indent=2, default=str), encoding="utf-8"
            )
            self._cache[key] = value
            self._index[key] = {"fingerprint": fp, "step": step, "file": self.path_for(key).name}
            self._save_index()
            return fp

    def get(self, key: str, default: Any = None) -> Any:
        """Read an artifact, loading from disk on first access."""
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            path = self.path_for(key)
            if not path.exists():
                return default
            value = json.loads(path.read_text(encoding="utf-8"))
            self._cache[key] = value
            return value

    def has(self, key: str) -> bool:
        with self._lock:
            return key in self._cache or self.path_for(key).exists()

    def fingerprint_of(self, key: str) -> str:
        """Fingerprint an artifact was stored under, or ``""`` if absent."""
        with self._lock:
            return str(self._index.get(key, {}).get("fingerprint", ""))

    def keys(self) -> set[str]:
        with self._lock:
            on_disk = {p.stem for p in self.dir.glob("*.json")}
            return on_disk | set(self._cache)

    def drop(self, key: str) -> None:
        """Remove an artifact — used when a step is invalidated."""
        with self._lock:
            self._cache.pop(key, None)
            self._index.pop(key, None)
            self.path_for(key).unlink(missing_ok=True)
            self._save_index()


class RunContext:
    """Everything a step needs, passed explicitly."""

    def __init__(
        self, config: RunConfig, runs_root: Path | str = "runs", *, run_id: str | None = None
    ) -> None:
        """``run_id`` attaches to an existing run (re-score, re-report) instead of
        deriving one from ``config``, whose identity it would not reproduce."""
        self.config = config
        self.attached = run_id is not None
        self.run_id = run_id or config.run_id()
        self.run_dir = Path(runs_root) / self.run_id
        if self.attached and not self.run_dir.is_dir():
            raise FileNotFoundError(f"no such run: {self.run_dir}")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.journal = Journal(self.run_dir)
        self.ledger = BudgetLedger(
            max_tokens=config.budgets.max_tokens,
            max_usd=config.budgets.max_usd,
        )
        self.store = ArtifactStore(self.run_dir)
        self._http_lock = threading.Lock()
        self.limiter: Any = None
        """Concurrency limiter, attached by the orchestrator once an event loop
        is running (semaphores must bind to the active loop)."""

        self.services: dict[str, Any] = {}
        """Runtime collaborators (provider router, target adapter) injected by
        the orchestrator. Kept out of :class:`RunConfig` because they are live
        objects, not configuration, and must not reach fingerprints."""

    # -- artifacts --------------------------------------------------------

    def put(self, key: str, value: Any, *, step: str) -> str:
        return self.store.put(key, value, step=step)

    def get(self, key: str, default: Any = None) -> Any:
        return self.store.get(key, default)

    def has(self, key: str) -> bool:
        return self.store.has(key)

    def artifact_fingerprint(self, key: str) -> str:
        return self.store.fingerprint_of(key)

    def available(self) -> set[str]:
        """Artifact keys already present — what plan resolution may assume."""
        return self.store.keys()

    # -- filesystem -------------------------------------------------------

    def step_dir(self, step: str) -> Path:
        """Per-step scratch directory. Step-owned, so fan-out needs no locking."""
        path = self.run_dir / "steps" / step
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def findings_dir(self) -> Path:
        path = self.run_dir / "findings"
        path.mkdir(parents=True, exist_ok=True)
        return path

    # -- journal ----------------------------------------------------------

    def log_exchange(self, record: dict[str, Any]) -> None:
        """Append one query→server exchange to ``http_calls.jsonl``.

        Every generated query that is actually sent — the request text and the
        server's response — is recorded here, so the dashboard can show what each
        candidate did against the API, not just whether it counted as coverage.
        The write is a single line under a lock, so parallel per-operation fan-out
        cannot interleave records.
        """
        line = json.dumps(record, default=str) + "\n"
        path = self.run_dir / "http_calls.jsonl"
        with self._http_lock:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line)

    def progress(self, step: str, **fields: Any) -> None:
        """Emit a progress event (drives the dashboard's live step rail)."""
        self.journal.append(Event.STEP_PROGRESS, step=step, **fields)

    def write_manifest(self, extra: dict[str, Any] | None = None) -> None:
        """Write ``manifest.json`` — the run's secret-free description.

        An attached run keeps the manifest of the run that produced it; the
        re-score/re-report is recorded beside it, with its own provenance."""
        path = self.run_dir / "manifest.json"
        if self.attached and path.exists():
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest.setdefault("reprocessed", []).append(
                {**(extra or {}), "provenance": provenance.collect()})
            path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
            return
        payload = {
            "run_id": self.run_id,
            "config": self.config.signature(),
            "provenance": provenance.collect(),
            "budgets": {
                "max_tokens": self.config.budgets.max_tokens,
                "max_usd": self.config.budgets.max_usd,
            },
            **(extra or {}),
        }
        (self.run_dir / "manifest.json").write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
