"""CLI surface: the flags and commands the README documents actually work."""

from __future__ import annotations

from prediql.cli import _build_parser, _config_from_args


def _run_args(argv):
    return _build_parser().parse_args(["run", "--target", "https://x.test/graphql", *argv])


def test_alias_and_trial_reach_the_config():
    cfg = _config_from_args(_run_args(["--alias", "My Box", "--trial", "3"]))
    assert cfg.alias == "my_box" and cfg.trial == 3
    assert cfg.run_id().startswith("my_box__t3__")


def test_allow_destructive_flag():
    assert _config_from_args(_run_args([])).allow_destructive is False
    assert _config_from_args(_run_args(["--allow-destructive"])).allow_destructive is True


def test_custom_model_price_is_parsed():
    cfg = _config_from_args(_run_args([
        "--provider", "generator=openrouter/new-model",
        "--model-price", "openrouter/new-model=0.25,0.90"]))
    assert cfg.providers["generator"] == "openrouter/new-model"
    assert cfg.model_prices["openrouter/new-model"] == (0.25, 0.90)


def test_provider_per_role():
    cfg = _config_from_args(_run_args([
        "--provider", "generator=zai:glm-5.3-flash", "--provider", "judge=anthropic:claude-haiku-4-5-20251001"]))
    assert cfg.providers == {"generator": "zai:glm-5.3-flash",
                             "judge": "anthropic:claude-haiku-4-5-20251001"}


def test_report_and_score_commands_parse():
    p = _build_parser()
    assert p.parse_args(["report", "r1"]).command == "report"
    assert p.parse_args(["score", "r1", "--truth", "t.yaml"]).command == "score"
    assert p.parse_args(["truth", "certify", "--truth", "t.yaml"]).command == "truth"


def test_judge_samples_and_max_operations():
    cfg = _config_from_args(_run_args(["--judge-samples", "3", "--max-operations", "25"]))
    assert cfg.strategy.judge_samples == 3
    assert cfg.strategy.max_operations == 25
