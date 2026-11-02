"""LLM action-label resolver (doc 02 §compile, M6).

GraphQL gives mutations no explicit action semantics (unlike REST's verbs), so
PrediQL labels them CREATE/UPDATE/DELETE/READ by a name+verb heuristic. When the
name carries no recognized verb the heuristic returns UNKNOWN — and a missing or
wrong label *suppresses a chain*: a missed CREATE kills an IDOR chain, a missed
DELETE kills a UAF chain. This resolver asks the ``resolver``-role LLM to classify
exactly that ambiguous subset, from each operation's name, description, arguments,
and return type.

It is deliberately cheap: only UNKNOWN operations are sent, and they go in **one**
batched call, so the strong model touches a small fraction of the schema — the
high-value LLM use the GraphQLer paper measures.
"""

from __future__ import annotations

from typing import Any

from prediql.model.graph import Action
from prediql.model.schema import Operation, Schema
from prediql.providers.base import LLMRequest
from prediql.providers.router import Router

_SYSTEM = (
    "You label GraphQL mutations with their CRUD action. For each operation, "
    "decide whether it CREATEs, UPDATEs, or DELETEs a resource, or is a READ "
    "(no state change). Use the name, description, arguments, and return type. "
    "If genuinely ambiguous, answer UNKNOWN rather than guess. Respond with JSON only."
)

_VALID = {"CREATE", "UPDATE", "DELETE", "READ", "UNKNOWN"}

_SCHEMA = {
    "type": "object",
    "properties": {
        "labels": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "operation": {"type": "string"},
                    "action": {"type": "string",
                               "enum": ["CREATE", "UPDATE", "DELETE", "READ", "UNKNOWN"]},
                },
                "required": ["operation", "action"],
            },
        }
    },
    "required": ["labels"],
}


def _describe(operation: Operation, schema: Schema) -> str:
    args = ", ".join(f"{n}: {r}" for n, r in operation.args) or "(none)"
    line = f"- {operation.name}(args: {args}) -> {operation.type}"
    if operation.description:
        line += f" // {operation.description[:160]}"
    return line


async def resolve_actions(
    router: Router,
    operations: list[Operation],
    schema: Schema,
    *,
    step: str = "compile",
) -> dict[str, Action]:
    """Return ``{operation_name: Action}`` for the operations the LLM could label.

    Operations the model still cannot classify are omitted (they stay UNKNOWN).
    A malformed or empty response yields an empty dict — resolution is a bonus,
    never a failure that stops compilation.
    """
    if not operations:
        return {}

    prompt = "\n".join([
        "Classify each of these GraphQL mutations:",
        *[_describe(op, schema) for op in operations],
        "",
        'Return {"labels": [{"operation": "<name>", "action": "CREATE|UPDATE|DELETE|READ|UNKNOWN"}]}.',
    ])

    response = await router.complete(
        LLMRequest(role="resolver", system=_SYSTEM, prompt=prompt, json_schema=_SCHEMA,
                   max_tokens=1200, temperature=0.0),
        step=step, cost_class="llm-strong",
    )

    names = {op.name for op in operations}
    resolved: dict[str, Action] = {}
    for entry in (response.data or {}).get("labels", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("operation")
        action = str(entry.get("action", "")).upper()
        if name in names and action in _VALID and action != "UNKNOWN":
            resolved[name] = Action(action)
    return resolved
