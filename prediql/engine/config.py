"""Immutable run configuration.

Every knob v1 kept on the mutable ``config.Config`` singleton lives here instead,
on a frozen dataclass created once per run and threaded explicitly through
:class:`~prediql.engine.context.RunContext`. That single change is what lets two
runs share a process — v1 needed a subprocess per target because
``configure_run_artifacts`` rewrote module globals and ``os.environ``.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from prediql.engine.fingerprint import fingerprint, short

# Roles the router can address independently. Splitting generation from
# adjudication is the single largest cost lever (doc 04 §1).
ROLE_GENERATOR = "generator"
ROLE_RESOLVER = "resolver"
ROLE_JUDGE = "judge"
ROLES = (ROLE_GENERATOR, ROLE_RESOLVER, ROLE_JUDGE)


@dataclass(frozen=True, slots=True)
class Identity:
    """A named authentication profile.

    Chain strategies (IDOR, BFLA) need at least two; v1 had a single
    ``Config.AUTHORIZATION`` string, which is why it could not express them.
    """

    name: str
    headers: dict[str, str] = field(default_factory=dict)
    role: str = "user"

    def signature(self) -> dict[str, Any]:
        """Identity minus secrets — safe for fingerprints and artifacts."""
        return {"name": self.name, "role": self.role, "header_keys": sorted(self.headers)}


@dataclass(frozen=True, slots=True)
class Limits:
    """Concurrency and politeness limits.

    Three independent semaphores so one saturated resource cannot starve
    another (doc 01 §5).
    """

    max_http: int = 8
    max_llm: int = 4
    max_cpu: int = 2
    request_timeout: float = 120.0
    delay_ms: int = 1


@dataclass(frozen=True, slots=True)
class Budgets:
    """Spend ceilings. ``None`` means unbounded.

    A ceiling drives context compression, not truncation — see
    :class:`~prediql.engine.budget.BudgetLedger`.
    """

    max_tokens: int | None = None
    max_usd: float | None = None


@dataclass(frozen=True, slots=True)
class Strategy:
    """Generation strategy — deliberately separate from *which steps run*.

    v1 conflated these in one ``MODE`` flag (``discovery_only = mode !=
    "prediql"``), so you could not ask for coverage-only with the full strategy.
    """

    arms: tuple[str, ...] = ()
    """Ablation toggles from the novelty ledger, e.g. ``+SmartRAG``, ``+HierMAB``."""

    rounds: int = 3
    requests_per_operation: int = 10
    seed: int = 42
    temperature: float = 0.0
    plateau_rounds: int = 2
    """Stop an operation after this many consecutive rounds with no new coverage."""

    coverage_depth: int = 5
    """Depth bound D for the field-coverage denominator (doc 11 §1)."""

    judge_samples: int = 1
    """LLM-judge samples per potential finding. >1 = ensemble (median + agreement)."""

    max_operations: int | None = None
    """Cap on operations attempted in `cover` (large schemas); None = all."""

    def has(self, arm: str) -> bool:
        """True when an ablation arm is enabled."""
        return arm in self.arms


@dataclass(frozen=True, slots=True)
class RunConfig:
    """Everything that determines a run's behaviour."""

    target_url: str
    target_slug: str = ""
    alias: str = ""
    """Friendly name for this target, used in the run directory and reports.

    Defaults to the URL-derived slug. An alias makes a run directory readable
    (``dvga__t1__a1b2c3`` rather than a host/path mangling) and groups every
    trial for the same target under one name."""

    trial: int = 1
    """Replicate index. Part of the run identity, so repeating a configuration
    with ``--trial 1,2,3`` yields three independent run directories — the
    repeated-trials-with-variance the reviewers asked for — while modes still
    compose within a single trial."""

    mode: str = "coverage"
    steps: tuple[str, ...] = ()
    """Explicit step override; empty means "use the mode's step list"."""

    providers: dict[str, str] = field(default_factory=dict)
    model_prices: dict[str, tuple[float, float]] = field(default_factory=dict)
    """Per-model USD/1M overrides, keyed by ``vendor:slug``. Used for a custom
    model the catalog does not know — the dashboard collects the rate."""

    identities: tuple[Identity, ...] = ()
    families: tuple[str, ...] = ()
    """Probe families to run; empty means all applicable."""

    limits: Limits = field(default_factory=Limits)
    budgets: Budgets = field(default_factory=Budgets)
    strategy: Strategy = field(default_factory=Strategy)

    graph_backend: str = "native"
    allow_destructive: bool = False
    truth_path: str | None = None
    oob_host: str | None = None
    auth_args: dict[str, str] = field(default_factory=dict)
    """Argument *values* an authenticated tester supplies to open a resolver gate
    (e.g. ``{"username": "admin", "password": "changeme"}``). The probe fills a
    non-injected *required* argument from here when the name matches, so a probe
    can reach a resolver behind a credential check — the authenticated-scan
    assumption. The knowledge lives here in the target's config, never in a
    detection family, so families stay app-agnostic; baselines are given the same
    values, and results disclose that the scan was authenticated. These are
    credentials: only the argument *names* enter the run signature, never the
    values (mirroring :meth:`Identity.signature`)."""
    code_version: str = ""
    """Engine code that produced the run (``engine.provenance.code_version``).

    Part of the run identity when set, so results from different code never
    share — or resume into — one run directory. Empty (tests, replays) leaves
    the identity exactly as it was before provenance existed."""
    """Host the target uses to reach the out-of-band collaborator (e.g.
    ``host.docker.internal`` for a Dockerised target). Enables the SSRF family and
    blind OS-command probes; ``None`` leaves them inert."""

    def __post_init__(self) -> None:
        if not self.target_url and self.mode not in ("score", "report"):
            raise ValueError("target_url is required except in score/report modes")
        if not self.target_slug:
            object.__setattr__(self, "target_slug", _slug_from_url(self.target_url))
        if not self.alias:
            object.__setattr__(self, "alias", self.target_slug)
        else:
            object.__setattr__(self, "alias", _safe_name(self.alias))
        if self.trial < 1:
            raise ValueError("trial must be >= 1")
        if not self.identities:
            object.__setattr__(self, "identities", (Identity(name="anon", role="anonymous"),))

    # -- derived ----------------------------------------------------------

    def signature(self) -> dict[str, Any]:
        """Secret-free description of the run, for fingerprints and manifests."""
        return {
            "target": self.target_url,
            "alias": self.alias,
            "trial": self.trial,
            "mode": self.mode,
            "steps": list(self.steps),
            "providers": dict(sorted(self.providers.items())),
            "identities": [i.signature() for i in self.identities],
            "families": list(self.families),
            "graph_backend": self.graph_backend,
            "allow_destructive": self.allow_destructive,
            "oob_host": self.oob_host,
            "auth_arg_keys": sorted(self.auth_args),
            "strategy": {
                "arms": list(self.strategy.arms),
                "rounds": self.strategy.rounds,
                "requests_per_operation": self.strategy.requests_per_operation,
                "seed": self.strategy.seed,
                "temperature": self.strategy.temperature,
                "coverage_depth": self.strategy.coverage_depth,
                "judge_samples": self.strategy.judge_samples,
                "max_operations": self.strategy.max_operations,
            },
        } | ({"code_version": self.code_version} if self.code_version else {})

    def identity_signature(self) -> dict[str, Any]:
        """What makes this run *this run*, excluding which steps are running now.

        Deliberately omits ``mode`` and ``steps``: a mode is which steps you are
        executing at the moment, not a different investigation. Running
        ``coverage`` and later ``security`` against the same target and strategy
        must land in the *same* run directory, so the second builds on the
        first's artifacts rather than starting over. Changing the strategy (arms,
        rounds, seed) or the target *is* a different experiment and does yield a
        new run.
        """
        signature = self.signature()
        signature.pop("mode", None)
        signature.pop("steps", None)
        return signature

    def run_id(self) -> str:
        """Deterministic run id: ``<alias>__t<trial>__<hash>``.

        Determinism lets the dashboard predict the run directory a launch will
        create, which is how live streaming attaches without a handshake. The
        trial index is in both the name and the hash, so repeated trials never
        collide and are readable at a glance.
        """
        return f"{self.alias}__t{self.trial}__{short(fingerprint(self.identity_signature()))}"

    def identity(self, name: str) -> Identity:
        for candidate in self.identities:
            if candidate.name == name:
                return candidate
        raise KeyError(f"no identity named {name!r}")

    def with_(self, **changes: Any) -> RunConfig:
        """Return a copy with fields replaced (config stays immutable)."""
        return replace(self, **changes)


def _safe_name(name: str) -> str:
    """Filesystem-safe alias."""
    safe = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in name.strip().lower())
    return safe.strip("._-")[:64] or "target"


def _slug_from_url(url: str) -> str:
    """Filesystem-safe slug from an endpoint URL."""
    from urllib.parse import urlparse

    parsed = urlparse((url or "").strip())
    host = (parsed.netloc or "target").replace(":", "_")
    path = (parsed.path or "").strip("/").replace("/", "_")
    raw = f"{host}_{path}" if path else host
    safe = "".join(ch if (ch.isalnum() or ch in "._-") else "_" for ch in raw.lower())
    return safe.strip("._-")[:120] or "target"
