"""Exception hierarchy for the engine.

Every failure mode the orchestrator can distinguish gets its own type, so a step
crash is never confused with a plan that was invalid before any work started.
"""

from __future__ import annotations


class PrediQLError(Exception):
    """Base class for every error raised by PrediQL."""


class PlanError(PrediQLError):
    """A requested step list cannot be run.

    Raised by :func:`StepGraph.resolve` *before* any work happens — an unknown
    step name, or a step whose ``requires`` no upstream step ``produces``.
    """


class StepError(PrediQLError):
    """A step failed in a way that should stop its branch of the run."""

    def __init__(self, step: str, message: str) -> None:
        super().__init__(f"[{step}] {message}")
        self.step = step
        self.message = message


class BudgetExhausted(PrediQLError):
    """The run's token/USD ceiling was hit and no further compression is possible.

    This is the *last* resort: the compression ladder (see :mod:`prediql.engine.budget`)
    reduces context before scope, so reaching this means even the smallest viable
    request would exceed the remaining budget.
    """


class ProviderError(PrediQLError):
    """An LLM provider call failed after its retry policy was exhausted."""


class TargetError(PrediQLError):
    """The target API could not be reached or returned an unusable response."""
