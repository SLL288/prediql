"""Deterministic in-process provider, for tests and offline ablations.

Not a mock in the pejorative sense: it is the ``Provider`` contract implemented
by a scripted responder, which is what lets the LLM-dependent steps be exercised
in CI with no network and no spend. Also the honest place to record a real
model's outputs for replay.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from prediql.engine.budget import Usage
from prediql.providers.base import Capabilities, LLMRequest, LLMResponse, Provider
from prediql.providers.openai_compatible import extract_json


class EchoProvider(Provider):
    """Returns scripted responses and meters plausible token counts."""

    name = "echo"

    def __init__(
        self,
        responder: Callable[[LLMRequest], str | dict[str, Any]] | None = None,
        *,
        model: str = "echo-1",
        structured_output: bool = True,
    ) -> None:
        self.model = model
        self._responder = responder or (lambda request: "{}")
        self._capabilities = Capabilities(
            structured_output=structured_output, prefix_cache=False, context_window=32_000
        )
        self.calls: list[LLMRequest] = []
        """Every request received, in order — assertable in tests."""

    def capabilities(self) -> Capabilities:
        return self._capabilities

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        produced = self._responder(request)
        if isinstance(produced, dict):
            import json

            text = json.dumps(produced)
            data: dict[str, Any] | None = produced
        else:
            text = produced
            data = extract_json(text) if request.json_schema else None

        # Character/4 is the standard rough token estimate; good enough to make
        # budget behaviour observable without a tokenizer dependency.
        prompt_chars = len(request.system) + len(request.prefix) + len(request.prompt)
        return LLMResponse(
            text=text,
            usage=Usage(
                prompt_tokens=max(1, prompt_chars // 4),
                completion_tokens=max(1, len(text) // 4),
                wall_seconds=0.0,
            ),
            data=data,
            model=self.model,
        )
