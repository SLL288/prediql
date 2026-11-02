"""Witness: the reproducible evidence behind a finding (doc 07 §3).

A finding is only as trustworthy as the artifact that proves it. Every confirmed
or potential finding carries a witness — the exact request(s), the identity, the
matched evidence, and a bounded response excerpt — so a human, or ``predql
repro``, can re-derive the verdict rather than trust it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MAX_EXCERPT = 2000


def _excerpt(text: str, limit: int = MAX_EXCERPT) -> str:
    """Head+tail clip, so a large response is legible without bloating artifacts."""
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n… [{len(text) - limit} chars elided] …\n{text[-half:]}"


@dataclass(frozen=True, slots=True)
class RequestRecord:
    """One request that forms part of the evidence."""

    document: str
    identity: str
    variables: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"document": self.document, "identity": self.identity, "variables": self.variables}


@dataclass(frozen=True, slots=True)
class Witness:
    """Everything needed to reproduce and believe a finding."""

    requests: tuple[RequestRecord, ...]
    matched: str = ""
    """The concrete evidence: the sentinel found, the signature matched, etc."""
    response_excerpt: str = ""
    latency_ms: float | None = None
    baseline_ms: float | None = None
    differential: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": [r.to_dict() for r in self.requests],
            "matched": self.matched,
            "response_excerpt": _excerpt(self.response_excerpt),
            "latency_ms": self.latency_ms,
            "baseline_ms": self.baseline_ms,
            "differential": self.differential,
        }
