"""Steps, the step registry, plan resolution, and cascade invalidation.

A **Step** is the atomic unit of work — the direct replacement for v1's
600-line ``process_node``. It declares typed ``requires``/``produces`` artifact
keys, so three things fall out of one mechanism:

* **plan validation** — an unsatisfiable step list fails before any work starts;
* **resume** — a step whose fingerprint and outputs are unchanged is skipped;
* **cascade invalidation** — re-running a step forces every downstream consumer
  of its artifacts to re-run too, so a fixed upstream never leaves a stale
  downstream artifact behind.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from prediql.engine.errors import PlanError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from prediql.engine.context import RunContext


@dataclass
class StepResult:
    """What a step reports back to the orchestrator."""

    artifacts: dict[str, Any] = field(default_factory=dict)
    """Artifact key -> value. Keys must match the step's ``produces``."""

    metrics: dict[str, Any] = field(default_factory=dict)
    """Free-form counters for the journal, report, and dashboard."""

    note: str = ""
    """One-line human summary, shown on the step rail."""


class Step(abc.ABC):
    """Base class for every unit of work.

    Subclasses set the class-level contract and implement :meth:`run`.
    """

    name: ClassVar[str] = ""
    requires: ClassVar[frozenset[str]] = frozenset()
    produces: ClassVar[frozenset[str]] = frozenset()
    parallelizable: ClassVar[bool] = False
    cost_class: ClassVar[str] = "io"
    description: ClassVar[str] = ""

    def fingerprint(self, ctx: RunContext) -> str:
        """Stable hash of everything that determines this step's output.

        The default covers the step's identity plus the fingerprints of the
        artifacts it consumes, which is what makes cascade invalidation work
        without each step re-implementing it. Steps whose behaviour depends on
        extra configuration should override and mix that in.
        """
        from prediql.engine.fingerprint import fingerprint

        upstream = {key: ctx.artifact_fingerprint(key) for key in sorted(self.requires)}
        return fingerprint(self.name, upstream, self.config_signature(ctx))

    def config_signature(self, ctx: RunContext) -> Any:
        """Configuration this step's output depends on. Override as needed."""
        return {}

    @abc.abstractmethod
    async def run(self, ctx: RunContext) -> StepResult:
        """Do the work. Read from ``ctx``; return artifacts and metrics."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

STEP_REGISTRY: dict[str, type[Step]] = {}


def register(step_cls: type[Step]) -> type[Step]:
    """Class decorator adding a step to the global registry.

    The registry maps *names* to classes; instances are created per run, so no
    step ever holds cross-run state.
    """
    if not step_cls.name:
        raise ValueError(f"{step_cls.__qualname__} must set a non-empty `name`")
    if step_cls.name in STEP_REGISTRY:
        raise ValueError(f"duplicate step name: {step_cls.name!r}")
    STEP_REGISTRY[step_cls.name] = step_cls
    return step_cls


def get_step(name: str) -> Step:
    """Instantiate a registered step by name."""
    try:
        return STEP_REGISTRY[name]()
    except KeyError:
        known = ", ".join(sorted(STEP_REGISTRY)) or "<none registered>"
        raise PlanError(f"unknown step {name!r}; known steps: {known}") from None


# ---------------------------------------------------------------------------
# Modes — named step lists (doc 01 §4)
# ---------------------------------------------------------------------------

#: A mode is *which steps run*. Strategy (bandit arms, RAG, judge model) is
#: configuration passed alongside — deliberately NOT welded to the mode, which
#: is the v1 ``MODE`` flag's central design flaw.
MODES: dict[str, tuple[str, ...]] = {
    "introspect": ("introspect",),
    "compile": ("introspect", "compile"),
    "coverage": ("introspect", "compile", "seed_identities", "cover", "validate"),
    "security": (
        "introspect", "compile", "seed_identities", "cover", "validate",
        "probe", "adjudicate",
    ),
    "chains": (
        "introspect", "compile", "seed_identities", "cover", "validate",
        "probe", "plan_chains", "execute_chains", "adjudicate",
    ),
    "score": ("score",),
    "report": ("report",),
    "full": (
        "introspect", "compile", "seed_identities", "cover", "validate",
        "probe", "plan_chains", "execute_chains", "adjudicate", "score", "report",
    ),
}


def mode_steps(mode: str) -> tuple[str, ...]:
    """Look up a mode's step names."""
    try:
        return MODES[mode]
    except KeyError:
        known = ", ".join(sorted(MODES))
        raise PlanError(f"unknown mode {mode!r}; known modes: {known}") from None


# ---------------------------------------------------------------------------
# Plan resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    """A validated, ordered list of steps ready to execute."""

    steps: tuple[Step, ...]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(step.name for step in self.steps)

    def index_of(self, name: str) -> int:
        return self.names.index(name)


def resolve(
    step_names: Sequence[str],
    *,
    available: Iterable[str] = (),
) -> Plan:
    """Order and validate a step list.

    ``available`` names artifact keys that already exist on disk (from a prior
    run), which is what lets ``--steps probe,adjudicate`` run against a finished
    coverage run without re-deriving the schema.

    Raises :class:`PlanError` when a step is unknown, requested twice, or has a
    requirement nothing upstream produces — always *before* any work happens.
    """
    seen: set[str] = set()
    for name in step_names:
        if name in seen:
            raise PlanError(f"step {name!r} requested more than once")
        seen.add(name)

    steps = [get_step(name) for name in step_names]
    by_name = {step.name: step for step in steps}

    # Topologically order by artifact dependencies, so `--steps validate,cover`
    # is accepted and run in the correct order rather than rejected.
    producer_of: dict[str, str] = {}
    for step in steps:
        for key in step.produces:
            producer_of.setdefault(key, step.name)

    ordered: list[Step] = []
    placed: set[str] = set()
    satisfied: set[str] = set(available)

    remaining = list(steps)
    while remaining:
        progressed = False
        for step in list(remaining):
            unmet = {
                key
                for key in step.requires
                if key not in satisfied and producer_of.get(key) not in placed
            }
            if unmet:
                continue
            ordered.append(step)
            placed.add(step.name)
            satisfied |= set(step.produces)
            remaining.remove(step)
            progressed = True
        if not progressed:
            blocked = ", ".join(sorted(s.name for s in remaining))
            missing = sorted(
                key
                for s in remaining
                for key in s.requires
                if key not in satisfied and producer_of.get(key) not in placed
            )
            raise PlanError(
                f"cannot run [{blocked}]: missing artifact(s) {missing}. "
                f"Add the step that produces them, or run against a run that has them."
            )
    del by_name
    return Plan(steps=tuple(ordered))


def dependents(plan: Plan, changed: Iterable[str]) -> set[str]:
    """Steps in ``plan`` that must re-run because ``changed`` steps re-ran.

    Propagates forward transitively: if ``compile`` re-runs, everything that
    consumes ``graph`` re-runs, and everything consuming *their* outputs too.
    This is what makes "fix an upstream step" safe — no stale downstream
    artifact can survive it.
    """
    dirty = set(changed)
    tainted_artifacts: set[str] = set()
    for step in plan.steps:
        if step.name in dirty:
            tainted_artifacts |= set(step.produces)
            continue
        if step.requires & tainted_artifacts:
            dirty.add(step.name)
            tainted_artifacts |= set(step.produces)
    return dirty - set(changed)
