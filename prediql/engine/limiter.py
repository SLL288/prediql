"""Concurrency limits for in-run fan-out.

Three independent semaphores, so a saturated resource cannot starve an unrelated
one: HTTP politeness toward the target is not the same constraint as an LLM
provider's rate limit, and neither is local CPU for embedding.
"""

from __future__ import annotations

import asyncio
from types import TracebackType

from prediql.engine.config import Limits


class _Slot:
    """Async context manager pairing a semaphore with an optional delay."""

    def __init__(self, semaphore: asyncio.Semaphore, delay_ms: int = 0) -> None:
        self._semaphore = semaphore
        self._delay = max(0, delay_ms) / 1000.0

    async def __aenter__(self) -> None:
        await self._semaphore.acquire()
        if self._delay:
            await asyncio.sleep(self._delay)

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._semaphore.release()


class Limiter:
    """Holds a run's concurrency budget.

    Created inside the running loop so the semaphores bind to the correct event
    loop; two concurrent runs each get their own instance.
    """

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self._http = asyncio.Semaphore(max(1, limits.max_http))
        self._llm = asyncio.Semaphore(max(1, limits.max_llm))
        self._cpu = asyncio.Semaphore(max(1, limits.max_cpu))

    @property
    def http(self) -> _Slot:
        """Target-facing requests: bounded and rate-delayed (politeness)."""
        return _Slot(self._http, self.limits.delay_ms)

    @property
    def llm(self) -> _Slot:
        """Provider calls: bounded by the provider's rate limit."""
        return _Slot(self._llm)

    @property
    def cpu(self) -> _Slot:
        """Local compute: embedding, parsing, analysis."""
        return _Slot(self._cpu)

    async def map(self, func, items, *, slot: str = "http"):
        """Run ``func`` over ``items`` concurrently under the named slot.

        Results come back in input order. Exceptions are returned rather than
        raised, so one failing operation cannot cancel a whole fan-out.
        """
        getter = {"http": lambda: self.http, "llm": lambda: self.llm, "cpu": lambda: self.cpu}[slot]

        async def _one(item):
            async with getter():
                return await func(item)

        return await asyncio.gather(*(_one(item) for item in items), return_exceptions=True)
