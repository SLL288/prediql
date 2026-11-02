"""Provider gateway: role routing, metering, caching, structured output."""

from __future__ import annotations

import pytest

from prediql.engine.budget import BudgetLedger, CompressionLevel
from prediql.engine.errors import ProviderError
from prediql.providers.base import LLMRequest
from prediql.providers.cache import ResponseCache
from prediql.providers.echo import EchoProvider
from prediql.providers.openai_compatible import extract_json
from prediql.providers.router import Router, build_router


def _request(role: str = "generator", prompt: str = "hello", **kw) -> LLMRequest:
    return LLMRequest(role=role, prompt=prompt, **kw)


# --------------------------------------------------------------------------
# Role routing — the cost lever v1 discarded
# --------------------------------------------------------------------------


async def test_each_role_reaches_its_own_provider():
    cheap, strong = EchoProvider(model="cheap"), EchoProvider(model="strong")
    router = Router({"generator": cheap, "judge": strong})

    assert (await router.complete(_request("generator"))).model == "cheap"
    assert (await router.complete(_request("judge"))).model == "strong"
    assert len(cheap.calls) == 1 and len(strong.calls) == 1


async def test_unconfigured_role_falls_back_to_the_generator():
    """A missing judge should degrade, not crash a run mid-flight."""
    router = Router({"generator": EchoProvider(model="only")})
    assert (await router.complete(_request("judge"))).model == "only"


def test_router_rejects_unknown_roles_at_construction():
    with pytest.raises(ValueError, match="unknown role"):
        Router({"nonsense": EchoProvider()})
    with pytest.raises(ValueError):
        Router({})


async def test_router_without_a_generator_raises_for_an_unknown_role():
    router = Router({"judge": EchoProvider()})
    with pytest.raises(ProviderError):
        await router.complete(_request("resolver"))


# --------------------------------------------------------------------------
# Metering — every call lands in the ledger by construction
# --------------------------------------------------------------------------


async def test_calls_are_metered_into_the_ledger():
    ledger = BudgetLedger(max_tokens=10_000)
    router = Router({"generator": EchoProvider()}, ledger=ledger)
    await router.complete(_request(prompt="x" * 400), step="cover", cost_class="llm-cheap")

    snapshot = ledger.snapshot()
    assert snapshot["total"]["calls"] == 1
    assert snapshot["total"]["prompt_tokens"] >= 100
    assert "cover" in snapshot["by_step"]
    assert "llm-cheap" in snapshot["by_cost_class"]


async def test_budget_pressure_raises_the_compression_level():
    ledger = BudgetLedger(max_tokens=500)
    router = Router({"generator": EchoProvider()}, ledger=ledger)
    assert router.compression_level() is CompressionLevel.FULL
    await router.complete(_request(prompt="x" * 2000), step="cover")
    assert router.compression_level() > CompressionLevel.FULL


# --------------------------------------------------------------------------
# Caching — an identical prompt is never paid for twice
# --------------------------------------------------------------------------


async def test_identical_request_is_served_from_cache_and_not_re_metered(tmp_path):
    provider = EchoProvider(responder=lambda r: "result")
    ledger = BudgetLedger()
    router = Router({"generator": provider}, ledger=ledger, cache=tmp_path)

    first = await router.complete(_request(prompt="same"))
    second = await router.complete(_request(prompt="same"))

    assert first.cached is False and second.cached is True
    assert len(provider.calls) == 1, "second call must not reach the provider"
    assert ledger.snapshot()["total"]["calls"] == 1, "a cache hit costs nothing"


async def test_cache_persists_across_router_instances(tmp_path):
    provider_a = EchoProvider(responder=lambda r: "v")
    await Router({"generator": provider_a}, cache=tmp_path).complete(_request(prompt="p"))

    provider_b = EchoProvider(responder=lambda r: "v")
    response = await Router({"generator": provider_b}, cache=tmp_path).complete(
        _request(prompt="p")
    )
    assert response.cached is True
    assert provider_b.calls == [], "a later run reuses the earlier run's answer"


async def test_different_prompts_do_not_collide(tmp_path):
    provider = EchoProvider(responder=lambda r: r.prompt)
    router = Router({"generator": provider}, cache=tmp_path)
    assert (await router.complete(_request(prompt="a"))).text == "a"
    assert (await router.complete(_request(prompt="b"))).text == "b"
    assert len(provider.calls) == 2


def test_cache_reports_hit_rate(tmp_path):
    cache = ResponseCache(tmp_path)
    cache.put("k", {"text": "v"})
    cache.get("k")
    cache.get("missing")
    assert cache.stats() == {"hits": 1, "misses": 1, "hit_rate": 0.5}


# --------------------------------------------------------------------------
# Structured output — replaces v1's regex extraction
# --------------------------------------------------------------------------


async def test_structured_response_is_parsed_into_data():
    provider = EchoProvider(responder=lambda r: {"operations": [{"document": "{ a }"}]})
    router = Router({"generator": provider})
    response = await router.complete(_request(json_schema={"type": "object"}))
    assert response.data == {"operations": [{"document": "{ a }"}]}


def test_extract_json_survives_prose_and_fences():
    assert extract_json('{"a": 1}') == {"a": 1}
    assert extract_json('Here you go:\n```json\n{"a": 2}\n```\nhope that helps') == {"a": 2}
    assert extract_json('prelude {"a": 3} postlude') == {"a": 3}
    assert extract_json("no json here") is None
    assert extract_json("") is None
    assert extract_json("[1,2,3]") is None, "a bare array is not an object result"


# --------------------------------------------------------------------------
# Construction from specs
# --------------------------------------------------------------------------


def test_build_router_from_specs_shares_identical_endpoints():
    router = build_router({"generator": "echo:a", "judge": "echo:a", "resolver": "echo:b"})
    assert router.for_role("generator") is router.for_role("judge")
    assert router.for_role("resolver") is not router.for_role("generator")


def test_build_router_rejects_an_unknown_vendor():
    with pytest.raises(ValueError, match="unknown provider vendor"):
        build_router({"generator": "nosuchvendor:model"})


def test_router_stats_expose_the_role_map():
    router = build_router({"generator": "echo:cheap", "judge": "echo:strong"})
    assert router.stats()["roles"] == {"generator": "echo/cheap", "judge": "echo/strong"}


# --------------------------------------------------------------------------
# Per-vendor API keys — a cross-vendor sweep needs a key each
# --------------------------------------------------------------------------


def test_vendor_key_takes_precedence_over_the_shared_one(monkeypatch, tmp_path):
    from prediql.providers.env import api_key

    # Isolate from the developer's own .env, which legitimately sets real keys.
    monkeypatch.setattr("prediql.providers.env.dotenv_path", lambda: tmp_path / "none.env")
    monkeypatch.setenv("LLM_API_KEY", "shared")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-only")
    monkeypatch.delenv("ZAI_API_KEY", raising=False)
    assert api_key(vendor="anthropic") == "anthropic-only"
    assert api_key(vendor="zai") == "shared", "vendors without their own key fall back"


def test_explicit_key_beats_everything(monkeypatch):
    from prediql.providers.env import api_key

    monkeypatch.setenv("ANTHROPIC_API_KEY", "env")
    assert api_key("explicit", vendor="anthropic") == "explicit"


def test_configured_vendors_reports_the_source_variable(monkeypatch, tmp_path):
    from prediql.providers.env import configured_vendors

    # The .env is repo-anchored, so point the loader at an empty one: this test
    # is about "no shared key configured", not about the developer's own file.
    monkeypatch.setattr("prediql.providers.env.dotenv_path", lambda: tmp_path / "none.env")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("ZAI_API_KEY", "z")
    result = configured_vendors(("anthropic", "zai"))
    assert result["zai"] == "ZAI_API_KEY"
    assert result["anthropic"] == "", "an unconfigured vendor is reported, not guessed"


def test_hosted_provider_without_any_key_fails_with_a_useful_message(monkeypatch, tmp_path):
    from prediql.providers.registry import build_provider

    monkeypatch.setattr("prediql.providers.env.dotenv_path", lambda: tmp_path / "none.env")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        build_provider("anthropic:claude-haiku-4-5-20251001")


def test_provider_uses_its_own_vendor_key(monkeypatch, tmp_path):
    from prediql.providers.registry import build_provider

    monkeypatch.setattr("prediql.providers.env.dotenv_path", lambda: tmp_path / "none.env")
    monkeypatch.setenv("LLM_API_KEY", "shared")
    monkeypatch.setenv("ZAI_API_KEY", "zai-key")
    provider = build_provider("zai:glm-5.3-flash")
    assert provider._api_key == "zai-key"


def test_catalog_price_is_applied_to_a_built_provider(monkeypatch):
    from prediql.engine.budget import Usage
    from prediql.providers.registry import build_provider

    monkeypatch.setenv("LLM_API_KEY", "k")
    provider = build_provider("anthropic:claude-haiku-4-5-20251001")
    # 1M in @ $1.00 + 1M out @ $5.00
    assert provider.price(Usage(prompt_tokens=1_000_000, completion_tokens=1_000_000)) == 6.0


def test_custom_price_overrides_the_catalog(monkeypatch):
    from prediql.engine.budget import Usage
    from prediql.providers.registry import build_provider

    monkeypatch.setenv("LLM_API_KEY", "k")
    provider = build_provider("zai:glm-5.3-flash", price=(2.0, 8.0))
    assert provider.price(Usage(prompt_tokens=1_000_000)) == 2.0


def test_dotenv_is_found_regardless_of_working_directory(tmp_path, monkeypatch):
    """The dashboard backend runs from dashboard/backend/, not the repo root."""
    from prediql.providers.env import dotenv_path

    monkeypatch.chdir(tmp_path)
    assert dotenv_path().is_absolute() or not (tmp_path / ".env").exists()


# --------------------------------------------------------------------------
# Custom vendors (a model at a provider not in the built-in registry)
# --------------------------------------------------------------------------


def test_custom_vendor_needs_a_base_url(monkeypatch, tmp_path):
    from prediql.providers.registry import build_provider

    monkeypatch.setattr("prediql.providers.env.dotenv_path", lambda: tmp_path / "none.env")
    monkeypatch.delenv("ACME_BASE_URL", raising=False)
    with pytest.raises(ValueError, match="ACME_BASE_URL"):
        build_provider("acme:some-model")


def test_custom_vendor_builds_from_environment(monkeypatch):
    from prediql.providers.registry import build_provider

    monkeypatch.setenv("ACME_BASE_URL", "https://api.acme.test/v1/")
    monkeypatch.setenv("ACME_API_KEY", "acme-key")
    provider = build_provider("acme:some-model", price=(2.0, 6.0))
    assert provider.name == "acme" and provider.model == "some-model"
    assert provider.base_url == "https://api.acme.test/v1", "trailing slash trimmed"
    assert provider._api_key == "acme-key"


def test_custom_vendor_price_override_is_applied(monkeypatch):
    from prediql.engine.budget import Usage
    from prediql.providers.registry import build_provider

    monkeypatch.setenv("ACME_BASE_URL", "https://api.acme.test/v1")
    monkeypatch.setenv("ACME_API_KEY", "k")
    provider = build_provider("acme:m", price=(3.0, 12.0))
    assert provider.price(Usage(prompt_tokens=1_000_000, completion_tokens=1_000_000)) == 15.0


def test_key_requirements_name_exactly_what_is_missing(monkeypatch, tmp_path):
    from prediql.providers.env import key_requirements

    monkeypatch.setattr("prediql.providers.env.dotenv_path", lambda: tmp_path / "none.env")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("ACME_API_KEY", raising=False)
    monkeypatch.delenv("ACME_BASE_URL", raising=False)
    needs = key_requirements("acme")
    assert needs == {"ACME_API_KEY": False, "ACME_BASE_URL": False}


def test_known_vendor_needs_only_a_key(monkeypatch):
    from prediql.providers.env import key_requirements

    monkeypatch.setenv("ZAI_API_KEY", "z")
    assert key_requirements("zai") == {"ZAI_API_KEY": True}, "no base URL needed for a known vendor"


# --------------------------------------------------------------------------
# LLM call log — the human-readable trail of what actually ran
# --------------------------------------------------------------------------


async def test_every_call_is_logged_with_cost_and_text(tmp_path):
    from prediql.providers.base import LLMRequest
    from prediql.providers.echo import EchoProvider
    from prediql.providers.router import Router
    import json

    log = tmp_path / "llm_calls.jsonl"
    router = Router({"generator": EchoProvider(responder=lambda r: "answer")}, log_path=log)
    await router.complete(
        LLMRequest(role="generator", system="sys", prefix="schema", prompt="ask"),
        step="cover", cost_class="llm-cheap")

    rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert len(rows) == 1
    row = rows[0]
    assert row["step"] == "cover" and row["role"] == "generator"
    assert row["prompt"] == "ask" and row["response"] == "answer"
    assert row["prefix"] == "schema"
    assert row["completion_tokens"] > 0
    assert row["cached"] is False


async def test_cache_hits_are_logged_and_marked(tmp_path):
    from prediql.providers.base import LLMRequest
    from prediql.providers.echo import EchoProvider
    from prediql.providers.router import Router
    import json

    log = tmp_path / "calls.jsonl"
    router = Router({"generator": EchoProvider(responder=lambda r: "v")},
                    cache=tmp_path / "cache", log_path=log)
    req = lambda: LLMRequest(role="generator", prompt="same")
    await router.complete(req(), step="cover")
    await router.complete(req(), step="cover")

    rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert [r["cached"] for r in rows] == [False, True], "a reused answer is visible as a hit"


async def test_long_prompts_are_clipped_in_the_log(tmp_path):
    from prediql.providers.base import LLMRequest
    from prediql.providers.echo import EchoProvider
    from prediql.providers.router import Router
    import json

    log = tmp_path / "calls.jsonl"
    router = Router({"generator": EchoProvider(responder=lambda r: "ok")}, log_path=log)
    # A normal-sized prompt is kept whole (the dashboard shows it in full)…
    await router.complete(LLMRequest(role="generator", prompt="x" * 5_000), step="cover")
    assert "elided" not in json.loads(log.read_text().splitlines()[0])["prompt"]
    # …only a pathological one is bounded by the safety cap.
    await router.complete(LLMRequest(role="generator", prompt="y" * 200_000), step="cover")
    row = json.loads(log.read_text().splitlines()[1])
    assert len(row["prompt"]) < 50_000 and "elided" in row["prompt"]


async def test_no_log_path_means_no_log(tmp_path):
    from prediql.providers.base import LLMRequest
    from prediql.providers.echo import EchoProvider
    from prediql.providers.router import Router

    router = Router({"generator": EchoProvider(responder=lambda r: "ok")})
    await router.complete(LLMRequest(role="generator", prompt="p"), step="cover")
    assert not list(tmp_path.iterdir()), "logging is opt-in"
