"""OpenAI-compatible chat-completions provider.

One class covers OpenAI, OpenRouter, Together, Groq, vLLM, LM Studio and
Ollama's OpenAI-compatible endpoint — they share the wire format, differing only
in base URL, model id, and whether they honour ``response_format``.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from prediql.engine.budget import Usage
from prediql.engine.errors import ProviderError
from prediql.providers.base import Capabilities, LLMRequest, LLMResponse, Provider


class OpenAICompatibleProvider(Provider):
    """Chat-completions over HTTP."""

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        name: str = "openai",
        capabilities: Capabilities | None = None,
        price_per_million: tuple[float, float] = (0.0, 0.0),
        timeout: float = 120.0,
        max_retries: int = 3,
    ) -> None:
        self.name = name
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._capabilities = capabilities or Capabilities(
            structured_output=True, prefix_cache=True, context_window=128_000
        )
        self._price = price_per_million
        self._max_retries = max_retries
        self._client = httpx.AsyncClient(timeout=timeout)

    def capabilities(self) -> Capabilities:
        return self._capabilities

    def price(self, usage: Usage) -> float:
        inp, out = self._price
        return usage.prompt_tokens / 1e6 * inp + usage.completion_tokens / 1e6 * out

    async def complete(self, request: LLMRequest) -> LLMResponse:
        messages: list[dict[str, str]] = []
        # Stable content first so a vendor prefix cache can hit across calls.
        system = "\n\n".join(part for part in (request.system, request.prefix) if part)
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": request.prompt})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.json_schema and self._capabilities.structured_output:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "result", "schema": request.json_schema, "strict": False},
            }

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        last_error = ""
        for attempt in range(self._max_retries):
            started = time.perf_counter()
            try:
                response = await self._client.post(
                    f"{self.base_url}/chat/completions", json=payload, headers=headers
                )
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                continue
            elapsed = time.perf_counter() - started

            if response.status_code == 200:
                return self._parse(response.json(), elapsed, request)
            # 4xx other than rate-limiting will not improve on retry.
            if 400 <= response.status_code < 500 and response.status_code != 429:
                raise ProviderError(
                    f"{self.name}/{self.model} HTTP {response.status_code}: {response.text[:400]}"
                )
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"

        raise ProviderError(
            f"{self.name}/{self.model} failed after {self._max_retries} attempts: {last_error}"
        )

    def _parse(self, body: dict[str, Any], elapsed: float, request: LLMRequest) -> LLMResponse:
        try:
            text = body["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"{self.name}: unexpected response shape ({exc})") from exc

        raw_usage = body.get("usage") or {}
        usage = Usage(
            prompt_tokens=int(raw_usage.get("prompt_tokens", 0)),
            completion_tokens=int(raw_usage.get("completion_tokens", 0)),
            cached_tokens=int(
                (raw_usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0)
            ),
            wall_seconds=elapsed,
        )
        data = extract_json(text) if request.json_schema else None
        return LLMResponse(text=text, usage=usage, data=data, model=self.model)

    async def aclose(self) -> None:
        await self._client.aclose()


def extract_json(text: str) -> dict[str, Any] | None:
    """Recover a JSON object from a completion.

    Tries the whole string, then a fenced block, then the outermost brace span —
    enough to survive a model that wraps its JSON in prose, without the fragile
    regex extraction v1 used on free-form GraphQL.
    """
    if not text:
        return None
    candidates = [text.strip()]
    if "```" in text:
        for chunk in text.split("```")[1::2]:
            candidates.append(chunk.removeprefix("json").strip())
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start : end + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None
