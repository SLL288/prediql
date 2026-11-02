"""Token/cost accounting and the context-compression ladder.

The governing rule (docs 04 and 10): **a budget cap must not drop data — it must
compress context so the run reaches the same result at lower cost.** Truncating
the work (fewer rounds, fewer candidates) is a last resort that is recorded as a
quality-degrade event, never the first response to pressure.

So :class:`BudgetLedger` does two jobs:

1. meter every LLM call by ``cost_class`` and step, and
2. translate remaining headroom into a :class:`CompressionLevel` that prompt
   assembly uses to shed *redundancy* before *information*.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class CompressionLevel(IntEnum):
    """How aggressively prompt context must be compressed.

    Ordered so that every level below :attr:`REDUCE_SCOPE` preserves the
    information needed to produce the same query and reach the same finding.
    Only :attr:`REDUCE_SCOPE` can change outcomes, and it is always logged.
    """

    FULL = 0
    """Full context. Static preamble sent inline."""

    CACHE_PREAMBLE = 1
    """Send the static preamble once and reference it thereafter."""

    SLICE_SCHEMA = 2
    """Replace the full schema block with the operation-local sub-schema slice."""

    SUMMARIZE_TRACES = 3
    """Retrieved traces become summarized exemplars rather than raw responses."""

    DEDUP_ERRORS = 4
    """Error pairs collapse to deduplicated, normalized signals."""

    MEMORY_ONLY = 5
    """Retrieval and error blocks reduce to compact memory facts."""

    REDUCE_SCOPE = 6
    """Last resort: fewer candidates/rounds. Degrades quality; always recorded."""


@dataclass(frozen=True)
class Usage:
    """One metered LLM call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0
    wall_seconds: float = 0.0
    usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class _Bucket:
    """Running totals for one attribution key (a step, or a cost class)."""

    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0
    wall_seconds: float = 0.0
    usd: float = 0.0

    def add(self, usage: Usage) -> None:
        self.calls += 1
        self.prompt_tokens += usage.prompt_tokens
        self.completion_tokens += usage.completion_tokens
        self.cached_tokens += usage.cached_tokens
        self.wall_seconds += usage.wall_seconds
        self.usd += usage.usd

    def as_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cached_tokens": self.cached_tokens,
            "total_tokens": self.prompt_tokens + self.completion_tokens,
            "wall_seconds": round(self.wall_seconds, 3),
            "usd": round(self.usd, 6),
        }


# Fraction of budget consumed at which each level engages. Deliberately gentle
# early (cheap, lossless wins first) and reserved at the top: REDUCE_SCOPE only
# once 98% is gone.
_LADDER: tuple[tuple[float, CompressionLevel], ...] = (
    (0.50, CompressionLevel.CACHE_PREAMBLE),
    (0.65, CompressionLevel.SLICE_SCHEMA),
    (0.78, CompressionLevel.SUMMARIZE_TRACES),
    (0.88, CompressionLevel.DEDUP_ERRORS),
    (0.94, CompressionLevel.MEMORY_ONLY),
    (0.98, CompressionLevel.REDUCE_SCOPE),
)


class BudgetLedger:
    """Thread-safe meter over a run's token and dollar spend.

    Instances are per-run and live on :class:`~prediql.engine.context.RunContext`.
    There is deliberately no module-level state: v1's ``llm_cost_tracker._STATE``
    was a module global, which is one of the two reasons concurrent runs needed
    separate processes.
    """

    def __init__(
        self,
        *,
        max_tokens: int | None = None,
        max_usd: float | None = None,
    ) -> None:
        self.max_tokens = max_tokens
        self.max_usd = max_usd
        self._lock = threading.RLock()
        self._total = _Bucket()
        self._by_step: dict[str, _Bucket] = {}
        self._by_cost_class: dict[str, _Bucket] = {}
        self._degrade_events: list[dict[str, Any]] = []

    # -- metering ---------------------------------------------------------

    def record(self, usage: Usage, *, step: str, cost_class: str) -> None:
        """Attribute one metered call to a step and a cost class."""
        with self._lock:
            self._total.add(usage)
            self._by_step.setdefault(step, _Bucket()).add(usage)
            self._by_cost_class.setdefault(cost_class, _Bucket()).add(usage)

    def note_degrade(self, *, step: str, reason: str, detail: str = "") -> None:
        """Record that scope (not just context) had to be reduced.

        Called only when :attr:`CompressionLevel.REDUCE_SCOPE` actually changes
        what work is done, so the cost/quality trade stays auditable.
        """
        with self._lock:
            self._degrade_events.append({"step": step, "reason": reason, "detail": detail})

    # -- headroom ---------------------------------------------------------

    @property
    def consumed_fraction(self) -> float:
        """Largest fraction of any configured ceiling that has been consumed.

        Returns 0.0 when no ceiling is set, so an unbudgeted run always runs at
        :attr:`CompressionLevel.FULL`.
        """
        with self._lock:
            fractions: list[float] = []
            if self.max_tokens:
                used = self._total.prompt_tokens + self._total.completion_tokens
                fractions.append(used / self.max_tokens)
            if self.max_usd:
                fractions.append(self._total.usd / self.max_usd)
            return max(fractions, default=0.0)

    def compression_level(self) -> CompressionLevel:
        """Map current headroom onto the compression ladder."""
        consumed = self.consumed_fraction
        level = CompressionLevel.FULL
        for threshold, candidate in _LADDER:
            if consumed >= threshold:
                level = candidate
        return level

    def exhausted(self) -> bool:
        """True once a ceiling is fully consumed."""
        return self.consumed_fraction >= 1.0

    def remaining_tokens(self) -> int | None:
        if self.max_tokens is None:
            return None
        with self._lock:
            used = self._total.prompt_tokens + self._total.completion_tokens
        return max(0, self.max_tokens - used)

    def remaining_usd(self) -> float | None:
        if self.max_usd is None:
            return None
        with self._lock:
            return max(0.0, self.max_usd - self._total.usd)

    # -- reporting --------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Full accounting, for ``manifest``/journal/report and the dashboard."""
        with self._lock:
            return {
                "total": self._total.as_dict(),
                "by_step": {k: v.as_dict() for k, v in sorted(self._by_step.items())},
                "by_cost_class": {k: v.as_dict() for k, v in sorted(self._by_cost_class.items())},
                "limits": {"max_tokens": self.max_tokens, "max_usd": self.max_usd},
                "consumed_fraction": round(self.consumed_fraction, 4),
                "compression_level": self.compression_level().name,
                "degrade_events": list(self._degrade_events),
            }
