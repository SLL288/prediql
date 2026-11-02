"""Bandit tests: conjugacy, reward semantics, hierarchical pooling, determinism."""

from __future__ import annotations

from prediql.generation.bandit import DEFAULT_ARMS, Arm, ThompsonBandit

ARMS = (Arm("good"), Arm("bad"))


def test_selection_is_deterministic_under_a_fixed_seed():
    a = ThompsonBandit(ARMS, seed=7)
    b = ThompsonBandit(ARMS, seed=7)
    assert [a.select("op").name for _ in range(20)] == [b.select("op").name for _ in range(20)]


def test_different_seeds_diverge():
    a = ThompsonBandit(ARMS, seed=1)
    b = ThompsonBandit(ARMS, seed=2)
    assert [a.select("op").name for _ in range(30)] != [b.select("op").name for _ in range(30)]


def test_posterior_update_follows_the_beta_bernoulli_rule():
    bandit = ThompsonBandit(ARMS, seed=1, gamma=1.0)
    bandit.update("op", "good", 1.0)
    bandit.update("op", "good", 1.0)
    bandit.update("op", "good", 0.0)
    alpha, beta = bandit._effective("op", "good")
    assert (alpha, beta) == (3.0, 2.0), "alpha counts successes, beta failures, from Beta(1,1)"


def test_gamma_discounts_older_evidence():
    stationary = ThompsonBandit(ARMS, seed=1, gamma=1.0)
    forgetting = ThompsonBandit(ARMS, seed=1, gamma=0.5)
    for _ in range(6):
        stationary.update("op", "good", 1.0)
        forgetting.update("op", "good", 1.0)
    assert forgetting._effective("op", "good")[0] < stationary._effective("op", "good")[0]


def test_bandit_concentrates_on_the_rewarding_arm():
    """The learning property the ablation claims: selection should shift."""
    bandit = ThompsonBandit(ARMS, seed=3)
    for _ in range(300):
        arm = bandit.select("op")
        bandit.update("op", arm.name, 1.0 if arm.name == "good" else 0.0)
    stats = bandit.stats()
    assert stats["arms"]["good"]["selections"] > stats["arms"]["bad"]["selections"] * 5


def test_hierarchical_prior_warm_starts_an_unseen_operation():
    """The fix for v1's per-operation cold start on small APIs."""
    flat = ThompsonBandit(ARMS, seed=5, hierarchical=False)
    pooled = ThompsonBandit(ARMS, seed=5, hierarchical=True)
    for _ in range(20):
        flat.update("op_a", "good", 1.0)
        pooled.update("op_a", "good", 1.0)

    # A brand-new operation: flat restarts at Beta(1,1); pooled inherits.
    assert flat._effective("op_b", "good") == (1.0, 1.0)
    alpha, beta = pooled._effective("op_b", "good")
    assert alpha > 1.0, "pooled prior should carry evidence to a new operation"
    assert alpha / (alpha + beta) > 0.8


def test_hierarchical_does_not_leak_across_arms():
    bandit = ThompsonBandit(ARMS, seed=5, hierarchical=True)
    for _ in range(10):
        bandit.update("op_a", "good", 1.0)
    assert bandit._effective("op_b", "bad") == (1.0, 1.0)


def test_stats_expose_regret_and_selection_distribution():
    bandit = ThompsonBandit(ARMS, seed=3)
    for _ in range(50):
        arm = bandit.select("op")
        bandit.update("op", arm.name, 1.0 if arm.name == "good" else 0.0)
    stats = bandit.stats()
    assert stats["pulls"] == 50
    assert 0.0 <= stats["mean_reward"] <= 1.0
    assert stats["regret_vs_best_arm"] >= 0.0
    assert set(stats["arms"]) == {"good", "bad"}


def test_default_arm_space_batches_candidates():
    """v1 hardcoded n_variants=1 — one round trip per candidate."""
    assert len(DEFAULT_ARMS) == 8
    assert all(arm.n_candidates > 1 for arm in DEFAULT_ARMS)


def test_rejects_invalid_configuration():
    import pytest

    with pytest.raises(ValueError):
        ThompsonBandit((), seed=1)
    with pytest.raises(ValueError):
        ThompsonBandit(ARMS, gamma=0.0)
    with pytest.raises(KeyError):
        ThompsonBandit(ARMS).update("op", "nonexistent", 1.0)
