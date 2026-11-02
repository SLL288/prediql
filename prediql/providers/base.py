"""Provider interface: one shape for every LLM vendor.

v1 accepted a ``provider`` argument and discarded it, hard-coding one
Ollama-shaped request. Here a provider is an object with declared
:class:`Capabilities`, so the caller can ask *whether* structured output or a
prefix cache is available instead of assuming, and a new vendor is a subclass
rather than a branch.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from prediql.engine.budget import Usage


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What a model/endpoint can actually do.

    Probed rather than assumed: the same code path must work against a hosted
    model with native JSON-schema output and a local one without it.
    """

    structured_output: bool = False
    prefix_cache: bool = False
    context_window: int = 8192
    max_concurrency: int = 4


@dataclass(frozen=True, slots=True)
class LLMRequest:
    """One completion request.

    ``system`` and ``prefix`` carry the *stable* part of the prompt and are
    always placed first, so a vendor prefix cache can hit across calls for the
    same operation. v1 rendered the schema into a variable position, which
    guaranteed a cache miss on every call.
    """

    role: str
    prompt: str
    system: str = ""
    prefix: str = ""
    json_schema: dict[str, Any] | None = None
    max_tokens: int = 2048
    temperature: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def cache_key_parts(self) -> tuple[Any, ...]:
        return (self.system, self.prefix, self.prompt, self.json_schema,
                self.max_tokens, self.temperature)


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """A completion, plus whatever structure could be recovered from it."""

    text: str
    usage: Usage
    data: dict[str, Any] | None = None
    model: str = ""
    cached: bool = False
    """True when served from the response cache rather than the vendor."""


class Provider(abc.ABC):
    """A single model endpoint."""

    name: str = "provider"
    model: str = ""

    @abc.abstractmethod
    def capabilities(self) -> Capabilities:
        """Describe what this endpoint supports."""

    @abc.abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Execute one completion."""

    async def aclose(self) -> None:
        """Release transport resources."""

    def price(self, usage: Usage) -> float:
        """USD for a metered call. Zero for local models."""
        return 0.0
