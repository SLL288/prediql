"""Content-addressed response cache.

Keyed by ``(provider, model, request)``, so an identical prompt is never paid
for twice — within a run (a retried step, two arms that build the same prompt)
or across runs (a re-run after an unrelated fix). Persistent by design: the
cache outliving a run is the point.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from prediql.engine.fingerprint import fingerprint


class ResponseCache:
    """Simple on-disk JSON cache with an in-memory front."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._memory: dict[str, dict[str, Any]] = {}
        self.hits = 0
        self.misses = 0

    @staticmethod
    def key(provider: str, model: str, parts: tuple[Any, ...]) -> str:
        return fingerprint(provider, model, parts).split(":", 1)[1]

    def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            if key in self._memory:
                self.hits += 1
                return self._memory[key]
            path = self.root / f"{key}.json"
            if not path.exists():
                self.misses += 1
                return None
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.misses += 1
                return None
            self._memory[key] = value
            self.hits += 1
            return value

    def put(self, key: str, value: dict[str, Any]) -> None:
        with self._lock:
            self._memory[key] = value
            path = self.root / f"{key}.json"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(value, default=str), encoding="utf-8")
            tmp.replace(path)

    def stats(self) -> dict[str, Any]:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 4) if total else 0.0,
        }
