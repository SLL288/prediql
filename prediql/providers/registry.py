"""Supported providers and their endpoints (doc 04 §5).

Three vendors, one wire format. Anthropic, OpenRouter, and Z.ai all speak the
OpenAI chat-completions contract, so they share :class:`OpenAICompatibleProvider`
and differ only in base URL, model id, and (for pricing) their rate card. Adding
a fourth is a row here, never a new class.
"""

from __future__ import annotations

from dataclasses import dataclass

from prediql.providers import catalog
from prediql.providers.base import Capabilities, Provider
from prediql.providers.echo import EchoProvider
from prediql.providers.openai_compatible import OpenAICompatibleProvider


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """A supported vendor's fixed configuration."""

    name: str
    base_url: str
    structured_output: bool
    context_window: int
    hosted: bool = True
    """Hosted providers authenticate with ``LLM_API_KEY``; local ones do not."""


#: The registry of supported vendors.
PROVIDERS: dict[str, ProviderSpec] = {
    # Z.ai's coding endpoint speaks the OpenAI contract. Used as the default
    # wiring target while the pipeline's LLM path is brought up.
    "zai": ProviderSpec(
        "zai", "https://api.z.ai/api/coding/paas/v4", structured_output=True,
        context_window=128_000,
    ),
    "openrouter": ProviderSpec(
        "openrouter", "https://openrouter.ai/api/v1", structured_output=True,
        context_window=128_000,
    ),
    # Anthropic ships an OpenAI-compatible surface at /v1; same contract.
    "anthropic": ProviderSpec(
        "anthropic", "https://api.anthropic.com/v1", structured_output=True,
        context_window=200_000,
    ),
    # Local runtimes, for offline/no-cost ablation arms.
    "ollama": ProviderSpec(
        "ollama", "http://localhost:11434/v1", structured_output=False,
        context_window=32_000, hosted=False,
    ),
    "echo": ProviderSpec("echo", "", structured_output=True, context_window=32_000,
                         hosted=False),
}


def vendor_base_url_var(vendor: str) -> str:
    """Environment variable naming a custom vendor's OpenAI-compatible base URL."""
    return f"{vendor.strip().upper()}_BASE_URL"


def resolve_vendor(vendor: str) -> ProviderSpec | None:
    """Look up a vendor: the built-in registry, else one declared in the environment.

    A custom model at a *new* vendor needs a base URL and a key. Both come from
    the environment (``<VENDOR>_BASE_URL`` / ``<VENDOR>_API_KEY``) rather than
    from the launch request, deliberately: a key passed through the dashboard
    would land in the subprocess's argv, which is world-readable via ``ps``.
    Secrets stay in ``.env``; the dashboard only ever names the variable to set.
    """
    import os

    spec = PROVIDERS.get(vendor)
    if spec is not None:
        return spec
    base_url = os.environ.get(vendor_base_url_var(vendor))
    if not base_url:
        return None
    return ProviderSpec(vendor, base_url.rstrip("/"), structured_output=True,
                        context_window=128_000, hosted=True)


def build_provider(
    spec_str: str,
    *,
    api_key: str | None = None,
    price: tuple[float, float] | None = None,
) -> Provider:
    """Build one provider from a ``"vendor:model"`` string.

    ``zai:glm-5.3-flash`` / ``anthropic:claude-haiku-4-5-20251001`` /
    ``openrouter:google/gemini-3.1-flash-lite`` / ``echo:test``.

    Pricing comes from the model catalog; ``price`` overrides it, which is how a
    custom model entered in the dashboard supplies its own rate.
    """
    vendor, _, model = spec_str.partition(":")
    from prediql.providers.env import load_dotenv

    load_dotenv()  # a custom vendor's base URL may live in .env
    spec = resolve_vendor(vendor)
    if spec is None:
        known = ", ".join(sorted(PROVIDERS))
        raise ValueError(
            f"unknown provider {vendor!r}; supported: {known}. For a custom vendor, "
            f"set {vendor_base_url_var(vendor)} and {vendor.upper()}_API_KEY in .env"
        )
    if not model and vendor != "echo":
        raise ValueError(f"provider spec {spec_str!r} is missing a model (use 'vendor:model')")

    if vendor == "echo":
        return EchoProvider(model=model or "echo-1")
    if spec.hosted:
        # Prefer this vendor's own key; fall back to the shared one. A sweep
        # across vendors needs a key each — one token is not valid at another
        # vendor's endpoint.
        from prediql.providers.env import api_key as resolve_key, vendor_key_var

        api_key = resolve_key(api_key, vendor=vendor)
        if not api_key:
            raise ValueError(
                f"provider {vendor!r} needs an API key: set {vendor_key_var(vendor)} "
                f"(or the shared LLM_API_KEY) in .env, or pass --api-key"
            )
    return OpenAICompatibleProvider(
        model=model,
        base_url=spec.base_url,
        api_key=api_key,
        name=vendor,
        capabilities=Capabilities(
            structured_output=spec.structured_output,
            prefix_cache=spec.hosted,
            context_window=spec.context_window,
            max_concurrency=4,
        ),
        price_per_million=catalog.price_for(spec_str, price),
    )


def supported() -> list[str]:
    return sorted(PROVIDERS)
