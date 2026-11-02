"""Role-based routing, caching, metering, and structured-output handling.

The single largest cost lever in the design (doc 04 §1): generation runs on a
cheap model while adjudication and ambiguous-label resolution run on a strong
one. v1 used one model for every job, which is why its coverage stage dominated
spend.

The router is also the only place LLM tokens are counted, so the budget ledger
sees every call by construction rather than by discipline.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from prediql.engine.budget import BudgetLedger, CompressionLevel, Usage
from prediql.engine.config import ROLE_GENERATOR, ROLES
from prediql.engine.errors import ProviderError
from prediql.providers.base import LLMRequest, LLMResponse, Provider
from prediql.providers.cache import ResponseCache


class Router:
    """Dispatches a request for a *role* to the provider configured for it."""

    def __init__(
        self,
        providers: dict[str, Provider],
        *,
        ledger: BudgetLedger | None = None,
        cache: ResponseCache | Path | str | None = None,
        log_path: Path | str | None = None,
    ) -> None:
        if not providers:
            raise ValueError("router needs at least one provider")
        unknown = set(providers) - set(ROLES)
        if unknown:
            raise ValueError(f"unknown role(s): {sorted(unknown)}; valid roles are {list(ROLES)}")
        self._providers = providers
        self._ledger = ledger
        self._cache = (
            cache if isinstance(cache, ResponseCache) or cache is None else ResponseCache(cache)
        )
        # An append-only record of every LLM call: which step and role made it,
        # what it cost, and clipped prompt/response text. The cache stores answers
        # keyed by hash; this is the human-readable trail of what actually ran.
        self._log_path = Path(log_path) if log_path else None

    def for_role(self, role: str) -> Provider:
        """Provider for ``role``, falling back to the generator.

        A missing judge should degrade to *some* model rather than crash a run;
        which model answered is recorded on the response.
        """
        provider = self._providers.get(role) or self._providers.get(ROLE_GENERATOR)
        if provider is None:
            raise ProviderError(f"no provider configured for role {role!r}")
        return provider

    async def complete(
        self, request: LLMRequest, *, step: str = "unknown", cost_class: str = "llm-cheap"
    ) -> LLMResponse:
        """Run one request: cache lookup, dispatch, meter."""
        provider = self.for_role(request.role)

        key = None
        if self._cache is not None:
            key = ResponseCache.key(provider.name, provider.model, request.cache_key_parts())
            hit = self._cache.get(key)
            if hit is not None:
                # A cache hit costs nothing, so it is deliberately not metered.
                cached = LLMResponse(
                    text=hit.get("text", ""),
                    usage=Usage(),
                    data=hit.get("data"),
                    model=provider.model,
                    cached=True,
                )
                self._log(request, cached, provider, step, cost_class)
                return cached

        response = await provider.complete(request)
        usage = Usage(
            prompt_tokens=response.usage.prompt_tokens,
            completion_tokens=response.usage.completion_tokens,
            cached_tokens=response.usage.cached_tokens,
            wall_seconds=response.usage.wall_seconds,
            usd=provider.price(response.usage),
        )
        if self._ledger is not None:
            self._ledger.record(usage, step=step, cost_class=cost_class)
        if self._cache is not None and key is not None:
            self._cache.put(key, {"text": response.text, "data": response.data})
        final = LLMResponse(
            text=response.text, usage=usage, data=response.data, model=provider.model
        )
        self._log(request, final, provider, step, cost_class)
        return final

    # -- call log ---------------------------------------------------------

    #: The LLM call log keeps the FULL prompt and response — it exists to be read
    #: on the dashboard — bounded only by a high safety cap so a single runaway
    #: response cannot bloat the file without limit.
    LOG_CLIP = 40_000

    def _log(self, request, response, provider, step: str, cost_class: str) -> None:
        if self._log_path is None:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "step": step,
            "role": request.role,
            "cost_class": cost_class,
            "provider": provider.name,
            "model": provider.model,
            "cached": response.cached,
            "prompt_tokens": response.usage.prompt_tokens,
            "completion_tokens": response.usage.completion_tokens,
            "usd": round(response.usage.usd, 6),
            "wall_seconds": round(response.usage.wall_seconds, 3),
            "system": _clip(request.system, self.LOG_CLIP),
            "prefix": _clip(request.prefix, self.LOG_CLIP),
            "prompt": _clip(request.prompt, self.LOG_CLIP),
            "response": _clip(response.text, self.LOG_CLIP),
        }
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass  # the call log is diagnostics, never load-bearing

    def compression_level(self) -> CompressionLevel:
        """Current context-compression level implied by remaining budget."""
        return self._ledger.compression_level() if self._ledger else CompressionLevel.FULL

    def stats(self) -> dict[str, Any]:
        return {
            "roles": {role: f"{p.name}/{p.model}" for role, p in self._providers.items()},
            "cache": self._cache.stats() if self._cache else None,
        }

    async def aclose(self) -> None:
        for provider in set(self._providers.values()):
            await provider.aclose()


def build_router(
    spec: dict[str, str],
    *,
    ledger: BudgetLedger | None = None,
    cache_dir: Path | str | None = None,
    api_key: str | None = None,
) -> Router:
    """Build a router from ``{role: "vendor:model"}`` specifications.

    ``openrouter:llama-3.1-8b`` / ``openai:gpt-4.1-mini`` / ``ollama:llama3.1`` /
    ``echo:test``. Vendors sharing the OpenAI wire format share one class.
    """
    from prediql.providers.echo import EchoProvider
    from prediql.providers.openai_compatible import OpenAICompatibleProvider

    endpoints = {
        "openai": "https://api.openai.com/v1",
        "openrouter": "https://openrouter.ai/api/v1",
        "ollama": "http://localhost:11434/v1",
        "vllm": "http://localhost:8000/v1",
    }
    providers: dict[str, Provider] = {}
    built: dict[str, Provider] = {}

    for role, value in spec.items():
        vendor, _, model = value.partition(":")
        if value in built:
            providers[role] = built[value]
            continue
        if vendor == "echo":
            provider: Provider = EchoProvider(model=model or "echo-1")
        elif vendor in endpoints:
            provider = OpenAICompatibleProvider(
                model=model,
                base_url=endpoints[vendor],
                api_key=api_key,
                name=vendor,
                # Local runtimes are free; hosted pricing is supplied per run.
                price_per_million=(0.0, 0.0) if vendor in ("ollama", "vllm") else (0.0, 0.0),
            )
        else:
            raise ValueError(f"unknown provider vendor {vendor!r} in {value!r}")
        built[value] = provider
        providers[role] = provider

    return Router(providers, ledger=ledger, cache=cache_dir)


def _clip(text: str, limit: int) -> str:
    """Head+tail clip, so a long prompt stays readable without bloating the log."""
    text = text or ""
    if len(text) <= limit:
        return text
    half = limit // 2
    return f"{text[:half]}\n… [{len(text) - limit} chars elided] …\n{text[-half:]}"
