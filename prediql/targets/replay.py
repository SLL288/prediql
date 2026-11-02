"""Replay adapter: serves recorded exchanges instead of touching a live API.

This is what makes the security logic regression-testable. v1 has almost no
tests because its behaviour is entangled with live HTTP and a live LLM; a
recorded corpus lets ``cover``/``probe``/``adjudicate`` run deterministically in
CI with no network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from prediql.engine.config import Identity
from prediql.targets.base import HttpResult, TargetAdapter


class ReplayTarget(TargetAdapter):
    """Serves responses from an in-memory or on-disk recording.

    Lookup is by exact document text; unmatched documents return a recorded
    ``default`` (or an explicit miss), so a test can assert on what the engine
    asked for as well as what it did with the answer.
    """

    def __init__(
        self,
        introspection: dict[str, Any],
        responses: dict[str, dict[str, Any]] | None = None,
        *,
        default: dict[str, Any] | None = None,
    ) -> None:
        self._introspection = introspection
        self._responses = responses or {}
        self._default = default
        self.sent: list[str] = []
        """Every document the engine executed, in order — assertable in tests."""

    @classmethod
    def from_dir(cls, path: Path | str) -> ReplayTarget:
        """Load ``introspection.json`` and ``responses.json`` from a directory."""
        root = Path(path)
        introspection = json.loads((root / "introspection.json").read_text(encoding="utf-8"))
        responses_path = root / "responses.json"
        responses = (
            json.loads(responses_path.read_text(encoding="utf-8"))
            if responses_path.exists()
            else {}
        )
        return cls(introspection, responses)

    async def introspect(self, identity: Identity) -> dict[str, Any]:
        return self._introspection

    async def send(
        self,
        document: str,
        identity: Identity,
        *,
        variables: dict[str, Any] | None = None,
    ) -> HttpResult:
        self.sent.append(document)
        key = " ".join(document.split())  # whitespace-insensitive lookup
        recorded = self._responses.get(key, self._default)
        if recorded is None:
            return HttpResult(
                document=document,
                identity=identity.name,
                status=200,
                body={"errors": [{"message": "no recording for this document"}]},
                elapsed_ms=1.0,
                variables=variables or {},
            )
        return HttpResult(
            document=document,
            identity=identity.name,
            status=int(recorded.get("status", 200)),
            body=recorded.get("body"),
            elapsed_ms=float(recorded.get("elapsed_ms", 1.0)),
            error=recorded.get("error"),
            variables=variables or {},
        )
