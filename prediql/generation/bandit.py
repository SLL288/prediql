"""Thompson-sampling bandit over prompt strategies (doc 11 §2).

Arms are prompt configurations; the reward is binary and strict:

    r = 1  iff  the batch produced a *successful* response
                (HTTP 200, no ``errors[]``, non-null ``data``)
          and   Δcoverage > 0  (at least one newly **returned** field path)

Explicitly **not** "HTTP 200" — a GraphQL 200 carrying ``errors[]`` or a null
``data`` scores zero. Binary reward keeps the Beta-Bernoulli conjugacy exact, so
each arm's posterior reads directly as *P(this arm yields new valid coverage)*.

Two things here go beyond v1. A **hierarchical prior** pools evidence across
operations, because v1's per-``(operation, arm)`` ``Beta(1,1)`` means each arm is
tried roughly once before exploitation begins — on a 6-operation API the bandit
barely learns. And **γ < 1** (exponential forgetting) is offered explicitly,
since reward is non-stationary: once an operation's easy paths are covered, the
arm that *was* best stops earning.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Arm", "BASE_ARM", "DEFAULT_ARMS", "WIDE_ARMS", "ThompsonBandit", "RandomSelector"]


@dataclass(frozen=True, slots=True)
class Arm:
    """One prompt-construction strategy."""

    name: str
    include_schema: bool = True
    arg_mode: str = "known"  # "known" | "real" | "nulls"
    depth: int = 1
    top_k: int = 3
    n_candidates: int = 3
    """Candidates requested per call. v1 hardcoded 1, paying a round trip each."""

    def signature(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "include_schema": self.include_schema,
            "arg_mode": self.arg_mode,
            "depth": self.depth,
            "top_k": self.top_k,
            "n_candidates": self.n_candidates,
        }


#: Ported from v1's arm space, plus batched candidate generation.
DEFAULT_ARMS: tuple[Arm, ...] = (
    Arm("schema_min_known", True, "known", 1, 3),
    Arm("schema_min_real", True, "real", 1, 3),
    Arm("schema_mod_known", True, "known", 2, 5),
    Arm("noschema_min_known", False, "known", 1, 3),
    Arm("noschema_min_real", False, "real", 1, 0),
    Arm("schema_min_nulls", True, "nulls", 1, 3),
    Arm("schema_deep_known", True, "known", 3, 5),
    Arm("schema_deep_real", True, "real", 3, 5),
)

# Wider arm set for the +WideCover mode: the defaults plus deeper, broader
# (maximal-selection) arms that reach fields the depth-3 ceiling never names.
# n_candidates > 1 makes the generator emit a maximal selection (every scalar at
# each level), so these arms select a whole type's fields at once, down to
# depth 4-5. Paired with element-driven exploration (an operation keeps running
# until its coverage plateaus, not just until it first succeeds), they close the
# gap between operation coverage and element coverage.
WIDE_ARMS: tuple[Arm, ...] = DEFAULT_ARMS + (
    Arm("schema_wide_d3", True, "known", 3, 6),
    Arm("schema_wide_d4_known", True, "known", 4, 6),
    Arm("schema_wide_d4_real", True, "real", 4, 6),
    Arm("schema_wide_d5_real", True, "real", 5, 6),
)

# The single fixed arm of the +Base ablation: the minimal-prompt LLM baseline
# (v1's BASE). Shallow, temperature 0, no retrieval; with only one arm there is
# nothing for a selection policy to choose, so the bandit is removed as well.
BASE_ARM = Arm("base_minimal", True, "known", 1, 0)


@dataclass
class _Posterior:
    """Beta parameters for one (scope, arm) pair."""

    alpha: float = 1.0
    beta: float = 1.0

    def update(self, reward: float, gamma: float) -> None:
        self.alpha = gamma * self.alpha + reward
        self.beta = gamma * self.beta + (1.0 - reward)

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)


class ThompsonBandit:
    """Beta-Bernoulli Thompson sampler, optionally hierarchical.

    With ``hierarchical=True`` an operation's posterior is
    ``Beta(A_arm + α_op, B_arm + β_op)``: a newly-seen operation inherits what
    the arm achieved elsewhere instead of restarting from ``Beta(1,1)``.
    """

    def __init__(
        self,
        arms: tuple[Arm, ...] = DEFAULT_ARMS,
        *,
        seed: int = 42,
        gamma: float = 1.0,
        hierarchical: bool = False,
    ) -> None:
        if not arms:
            raise ValueError("bandit needs at least one arm")
        if not 0.0 < gamma <= 1.0:
            raise ValueError("gamma must be in (0, 1]")
        self.arms = arms
        self.gamma = gamma
        self.hierarchical = hierarchical
        self._rng = random.Random(seed)
        self._local: dict[tuple[str, str], _Posterior] = {}
        self._global: dict[str, _Posterior] = {arm.name: _Posterior() for arm in arms}
        self._selections: dict[str, int] = {arm.name: 0 for arm in arms}
        self._rewards: dict[str, float] = {arm.name: 0.0 for arm in arms}
        self._pulls = 0

    # -- posteriors -------------------------------------------------------

    def _local_posterior(self, operation: str, arm: str) -> _Posterior:
        return self._local.setdefault((operation, arm), _Posterior())

    def _effective(self, operation: str, arm: str) -> tuple[float, float]:
        """Parameters actually sampled from, after pooling if enabled."""
        local = self._local_posterior(operation, arm)
        if not self.hierarchical:
            return local.alpha, local.beta
        shared = self._global[arm]
        # Pool by adding the shared counts to the local ones. The local Beta(1,1)
        # is the uniform prior, so subtract it to avoid double-counting.
        return shared.alpha + local.alpha - 1.0, shared.beta + local.beta - 1.0

    # -- interface --------------------------------------------------------

    def select(self, operation: str) -> Arm:
        """Sample each arm's posterior and return the argmax draw."""
        best: Arm | None = None
        best_theta = -1.0
        for arm in self.arms:
            alpha, beta = self._effective(operation, arm.name)
            theta = self._rng.betavariate(max(alpha, 1e-6), max(beta, 1e-6))
            if theta > best_theta:
                best_theta, best = theta, arm
        assert best is not None
        self._selections[best.name] += 1
        self._pulls += 1
        return best

    def update(self, operation: str, arm_name: str, reward: float) -> None:
        """Fold one binary outcome into the local (and shared) posterior."""
        if arm_name not in self._global:
            raise KeyError(f"unknown arm {arm_name!r}")
        reward = 1.0 if reward >= 1.0 else 0.0
        self._local_posterior(operation, arm_name).update(reward, self.gamma)
        if self.hierarchical:
            self._global[arm_name].update(reward, self.gamma)
        self._rewards[arm_name] += reward

    # -- evaluation -------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Selection distribution and empirical arm value.

        Feeds the RQ2/RQ3 bandit evaluation: does selection concentrate on
        high-reward arms, and what is the regret against uniform selection?
        """
        total_reward = sum(self._rewards.values())
        per_arm = {
            arm.name: {
                "selections": self._selections[arm.name],
                "reward": round(self._rewards[arm.name], 3),
                "empirical_rate": round(
                    self._rewards[arm.name] / self._selections[arm.name], 4
                ) if self._selections[arm.name] else None,
                "posterior_mean": round(self._global[arm.name].mean, 4),
            }
            for arm in self.arms
        }
        best_rate = max(
            (v["empirical_rate"] or 0.0 for v in per_arm.values()), default=0.0
        )
        return {
            "pulls": self._pulls,
            "total_reward": round(total_reward, 3),
            "mean_reward": round(total_reward / self._pulls, 4) if self._pulls else 0.0,
            "hierarchical": self.hierarchical,
            "gamma": self.gamma,
            "arms": per_arm,
            # Regret against always having played the empirically best arm.
            "regret_vs_best_arm": round(best_rate * self._pulls - total_reward, 3),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "gamma": self.gamma,
            "hierarchical": self.hierarchical,
            "global": {k: [v.alpha, v.beta] for k, v in self._global.items()},
            "local": {f"{op}|{arm}": [p.alpha, p.beta] for (op, arm), p in self._local.items()},
            "selections": dict(self._selections),
            "rewards": dict(self._rewards),
        }


class RandomSelector:
    """Non-adaptive arm selection — the ablation control for the bandit.

    Same ``select`` / ``update`` / ``stats`` surface as :class:`ThompsonBandit`,
    but ``select`` samples uniformly and ``update`` does not steer future choices.
    Comparing it against the bandit isolates the bandit's contribution (a random-arm
    control); the arm *space* is unchanged, so
    only the selection policy differs.
    """

    def __init__(self, arms: tuple[Arm, ...] = DEFAULT_ARMS, *, seed: int = 42) -> None:
        if not arms:
            raise ValueError("selector needs at least one arm")
        self.arms = arms
        self.hierarchical = False
        self.gamma = 1.0
        self._rng = random.Random(seed)
        self._selections: dict[str, int] = {arm.name: 0 for arm in arms}
        self._rewards: dict[str, float] = {arm.name: 0.0 for arm in arms}
        self._pulls = 0

    def select(self, operation: str) -> Arm:
        arm = self._rng.choice(self.arms)
        self._selections[arm.name] += 1
        self._pulls += 1
        return arm

    def update(self, operation: str, arm_name: str, reward: float) -> None:
        if arm_name not in self._rewards:
            raise KeyError(f"unknown arm {arm_name!r}")
        self._rewards[arm_name] += 1.0 if reward >= 1.0 else 0.0

    def stats(self) -> dict[str, Any]:
        total_reward = sum(self._rewards.values())
        per_arm = {
            arm.name: {
                "selections": self._selections[arm.name],
                "reward": round(self._rewards[arm.name], 3),
                "empirical_rate": round(
                    self._rewards[arm.name] / self._selections[arm.name], 4
                ) if self._selections[arm.name] else None,
                "posterior_mean": None,
            }
            for arm in self.arms
        }
        return {
            "policy": "random",
            "pulls": self._pulls,
            "total_reward": round(total_reward, 3),
            "mean_reward": round(total_reward / self._pulls, 4) if self._pulls else 0.0,
            "hierarchical": False,
            "gamma": self.gamma,
            "arms": per_arm,
        }
