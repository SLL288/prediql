"""Step: repeatability and the control baselines every oracle needs.

Two jobs, and the second is the one v1 never did:

* **repeatability** — re-send the known-good document and require the same clean
  success, so a one-off fluke does not become a baseline;
* **controls** — record a per-operation latency distribution (median + MAD) and
  the benign *negative control* response. Time-based and differential oracles are
  meaningless without them, and their absence is why v1's detector could only
  ask a model for an opinion.
"""

from __future__ import annotations

import statistics
from typing import Any

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.targets.base import is_success

#: Samples per operation for the latency baseline. Enough for a median and a
#: median-absolute-deviation without hammering the target.
LATENCY_SAMPLES = 3


@register
class ValidateStep(Step):
    name = "validate"
    requires = frozenset({A.KNOWN_GOOD})
    produces = frozenset({A.BASELINE})
    parallelizable = True
    cost_class = "io"
    description = "Confirm repeatability and capture latency/negative controls."

    async def run(self, ctx: RunContext) -> StepResult:
        known_good: dict[str, str] = ctx.get(A.KNOWN_GOOD) or {}
        target = ctx.services["target"]
        identity = ctx.config.identities[0]
        baselines: dict[str, Any] = {}

        async def measure(item: tuple[str, str]) -> None:
            operation, document = item
            samples: list[float] = []
            successes = 0
            control: dict[str, Any] | None = None

            for _ in range(LATENCY_SAMPLES):
                result = await target.send(document, identity)
                samples.append(result.elapsed_ms)
                if is_success(result):
                    successes += 1
                    if control is None:
                        control = result.body
            baselines[operation] = self._summarize(document, samples, successes, control)

        items = list(known_good.items())
        outcomes = await ctx.limiter.map(measure, items, slot="http")
        errors = 0
        for (operation, _), outcome in zip(items, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                errors += 1
                baselines[operation] = {
                    "error": f"{type(outcome).__name__}: {outcome}",
                    "repeatable": False,
                }

        repeatable = sum(1 for b in baselines.values() if b.get("repeatable"))
        return StepResult(
            artifacts={A.BASELINE: baselines},
            metrics={"measured": len(baselines), "repeatable": repeatable, "errors": errors},
            note=f"{repeatable}/{len(baselines)} operations repeatable",
        )

    @staticmethod
    def _summarize(
        document: str, samples: list[float], successes: int, control: dict | None
    ) -> dict[str, Any]:
        median = statistics.median(samples) if samples else 0.0
        # Median absolute deviation: robust to the one slow sample a percentile
        # would let through, which matters because this threshold gates
        # time-based findings.
        mad = statistics.median([abs(s - median) for s in samples]) if samples else 0.0
        return {
            "document": document,
            "samples": [round(s, 2) for s in samples],
            "latency_median_ms": round(median, 2),
            "latency_mad_ms": round(mad, 2),
            "repeatable": successes == len(samples) and successes > 0,
            "successes": successes,
            "attempts": len(samples),
            "negative_control": control,
        }
