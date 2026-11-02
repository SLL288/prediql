"""LLM-backed candidate generation (doc 04 §1, doc 10).

The generator that makes PrediQL an *LLM* fuzzer. It builds a cache-friendly
prompt — stable operation schema first, volatile context last — asks the
``generator`` role for structured output, validates every returned document with
a real parser, and drops what does not parse. Invalid or empty output is not an
error: ``cover`` treats an empty candidate list as a missed round, so a flaky
model degrades to "no progress this round", never a crash.

Every call is metered through the router into the budget ledger by construction,
so token spend is accounted without the generator having to remember to do it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from graphql import parse

from prediql.generation.bandit import Arm
from prediql.generation.generator import Candidate, HeuristicGenerator
from prediql.generation.query_builder import build_selection
from prediql.model.bucket import ObjectsBucket
from prediql.model.schema import Operation, Schema
from prediql.providers.base import LLMRequest
from prediql.providers.router import Router

_SYSTEM = (
    "You are a GraphQL API fuzzer. Given one operation from a schema, produce "
    "diverse, syntactically valid GraphQL documents that exercise it and its "
    "return type. Prefer real argument values when provided. Respond with JSON "
    "only, matching the given schema."
)

_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "documents": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": ["query"],
            },
        }
    },
    "required": ["documents"],
}


@dataclass
class LLMGenerator:
    """A :class:`CandidateGenerator` backed by a provider router."""

    router: Router
    step: str = "cover"
    fallback: HeuristicGenerator | None = None
    """Heuristic generator used to seed a valid example into the prompt and as a
    safety net when the model returns nothing usable — the hybrid the paper's
    lessons-learned section recommends (strong seed, cheap iterate)."""

    name: str = "llm"

    def __post_init__(self) -> None:
        if self.fallback is None:
            self.fallback = HeuristicGenerator()

    async def generate(
        self,
        *,
        schema: Schema,
        operation: Operation,
        arm: Arm,
        bucket: ObjectsBucket,
        context: dict[str, Any] | None = None,
    ) -> list[Candidate]:
        # Do not ask the model for more documents than the remaining request
        # budget can send — anything extra is generated and then discarded.
        cap = (context or {}).get("max_candidates", arm.n_candidates)
        prefix = self._schema_slice(schema, operation, arm)
        prompt = self._instruction(schema, operation, arm, bucket, context or {})

        response = await self.router.complete(
            LLMRequest(
                role="generator",
                system=_SYSTEM,
                prefix=prefix,           # stable per operation -> prompt-cache friendly
                prompt=prompt,           # volatile: real values, round, arm
                json_schema=_OUTPUT_SCHEMA,
                max_tokens=1500,
                temperature=0.2 if arm.arg_mode == "real" else 0.0,
            ),
            step=self.step,
            cost_class="llm-cheap",
        )

        candidates = self._parse(response.data or _loads(response.text), operation, arm)[:cap]
        # The +Base ablation measures the LLM alone, so a dead round stays dead
        # instead of being rescued by the deterministic builder.
        if not candidates and self.fallback is not None and not (context or {}).get("minimal_prompt"):
            # A dead LLM round falls back to the deterministic builder rather
            # than wasting the round entirely.
            return await self.fallback.generate(
                schema=schema, operation=operation, arm=arm, bucket=bucket, context=context
            )
        return candidates

    # -- prompt construction ---------------------------------------------

    #: Caps that keep the schema slice compact on a huge schema (PokeAPI has
    #: ~2,000 types): list at most this many types, and this many fields each.
    SLICE_MAX_TYPES = 24
    SLICE_MAX_FIELDS = 40

    def _schema_slice(self, schema: Schema, operation: Operation, arm: Arm) -> str:
        """A compact, operation-local schema description (the stable prefix).

        Expands the return type AND the nested types reachable from it up to the
        arm's selection depth, so the model can build valid *deep* selections
        rather than guessing the fields of a nested type it was never shown.
        """
        args = ", ".join(f"{name}: {ref}" for name, ref in operation.args) or "(none)"
        lines = [
            f"operation: {operation.name} ({operation.kind})",
            f"arguments: {args}",
            f"returns: {operation.type}",
        ]

        # BFS over composite types reachable from the return type, bounded by the
        # arm's depth and the type cap, each type printed once.
        emitted: set[str] = set()
        frontier = [(operation.type.name, max(1, arm.depth))]
        while frontier and len(emitted) < self.SLICE_MAX_TYPES:
            type_name, remaining = frontier.pop(0)
            type_def = schema.type(type_name)
            if type_def is None or not type_def.is_composite or type_name in emitted:
                continue
            emitted.add(type_name)
            shown = type_def.fields[: self.SLICE_MAX_FIELDS]
            lines.append(f"type {type_name}: {{ "
                         + ", ".join(f"{f.name}: {f.type}" for f in shown) + " }")
            if remaining > 1:
                for f in shown:
                    child = schema.type(f.type.name)
                    if child is not None and child.is_composite and f.type.name not in emitted:
                        frontier.append((f.type.name, remaining - 1))

        # Input-object argument shapes, so the model can fill them correctly.
        for name, ref in operation.args:
            arg_type = schema.type(ref.name)
            if arg_type is not None and arg_type.is_input:
                members = ", ".join(f"{f.name}: {f.type}" for f in arg_type.fields[:20])
                lines.append(f"input {ref.name}: {{ {members} }}")
        return "\n".join(lines)

    def _instruction(
        self, schema: Schema, operation: Operation, arm: Arm,
        bucket: ObjectsBucket, context: dict[str, Any],
    ) -> str:
        n = max(1, min(arm.n_candidates, context.get("max_candidates", arm.n_candidates)))
        parts = [f"Generate {n} diverse valid GraphQL documents for `{operation.name}`."]
        # Minimal prompt (+Base): the instruction and the schema slice only, with
        # no observed values, syntactic seed, error feedback, or arm directives.
        if context.get("minimal_prompt"):
            return parts[0]

        # RAG-lite: real identifiers observed earlier, so the model reuses live
        # values instead of guessing (GraphQLer's scalar-materialization gap).
        hints = self._bucket_hints(schema, operation, bucket)
        if hints:
            parts.append("Real values observed on this API: " + hints + ".")

        # A concrete valid seed anchors the model to this schema's exact shape.
        if self.fallback is not None:
            seed = build_selection(schema, operation.type.name, depth=arm.depth, style="minimal") \
                if schema.type(operation.type.name) and \
                schema.type(operation.type.name).is_composite else ""
            if seed:
                parts.append(f"A minimal valid selection is: {operation.name} {seed}.")

        # Error feedback: arguments the schema calls optional but the server
        # rejected earlier attempts for omitting.
        required = context.get("required_args") or []
        if required:
            parts.append("The server rejected earlier attempts that omitted "
                         + ", ".join(required) + "; always supply them.")

        if arm.depth > 1:
            parts.append(f"Explore nested fields up to depth {arm.depth}.")
        round_index = context.get("round")
        if round_index and round_index > 1:
            parts.append(f"This is round {round_index}; try shapes not tried before.")
        return " ".join(parts)

    @staticmethod
    def _bucket_hints(schema: Schema, operation: Operation, bucket: ObjectsBucket) -> str:
        hints: list[str] = []
        for name, ref in operation.args:
            value = None
            return_type = schema.type(operation.type.name)
            if return_type is not None and return_type.field(name) is not None:
                value = bucket.field_value(operation.type.name, name)
            if value is not None:
                hints.append(f"{name}={value!r}")
        return ", ".join(hints)

    # -- parsing ----------------------------------------------------------

    def _parse(self, data: dict[str, Any] | None, operation: Operation, arm: Arm) -> list[Candidate]:
        if not isinstance(data, dict):
            return []
        documents = data.get("documents") or []
        candidates: list[Candidate] = []
        seen: set[str] = set()
        for entry in documents:
            document = entry.get("query") if isinstance(entry, dict) else None
            if not document or document in seen:
                continue
            try:
                parse(document)  # drop anything that is not valid GraphQL
            except Exception:
                continue
            seen.add(document)
            candidates.append(Candidate(
                operation=operation.name,
                document=document,
                arm=arm.name,
                source=self.name,
                rationale=(entry.get("rationale", "") if isinstance(entry, dict) else ""),
            ))
        return candidates


def _loads(text: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None
