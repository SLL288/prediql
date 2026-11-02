"""Build syntactically valid GraphQL documents from a normalized schema.

Shared by both generators: the heuristic one emits documents directly, and the
LLM one uses the same machinery to render the operation-local schema slice that
goes into a prompt. Keeping one implementation means a prompt can never describe
a shape the executor would not produce.

Two selection styles, mirroring GraphQLer's payload classes:

* **minimal** — the fewest scalar leaves that make a valid selection set;
* **maximal** — every scalar at each level, expanding objects up to a depth bound.
"""

from __future__ import annotations

import json
from typing import Any

from prediql.model.schema import Operation, Schema, TypeRef

# GraphQL requires a selection set on composite types and forbids one on scalars.
_BUILTIN_SCALARS = frozenset({"ID", "Int", "Float", "String", "Boolean"})


class SelectionError(ValueError):
    """A valid selection set could not be built (e.g. an object with no scalars)."""


def _scalar_fields(schema: Schema, type_name: str) -> list[str]:
    type_def = schema.type(type_name)
    if type_def is None:
        return []
    return [
        f.name
        for f in type_def.fields
        if not (schema.type(f.type.name) or type_def).is_composite
        or schema.type(f.type.name) is None
    ]


def _is_composite(schema: Schema, type_name: str) -> bool:
    type_def = schema.type(type_name)
    return bool(type_def and type_def.is_composite)


def build_selection(
    schema: Schema,
    type_name: str,
    *,
    depth: int = 1,
    style: str = "minimal",
    _seen: frozenset[str] = frozenset(),
) -> str:
    """Render a selection set for ``type_name``, or ``""`` for a scalar type."""
    if not _is_composite(schema, type_name):
        return ""
    type_def = schema.type(type_name)
    assert type_def is not None

    # Unions carry no fields of their own; select through their members.
    if type_def.kind == "UNION":
        parts = []
        for member in type_def.possible_types:
            inner = build_selection(schema, member, depth=depth, style=style, _seen=_seen)
            if inner:
                parts.append(f"... on {member} {inner}")
        return "{ " + " ".join(parts) + " }" if parts else ""

    scalars = [f for f in type_def.fields if not _is_composite(schema, f.type.name)]
    composites = [f for f in type_def.fields if _is_composite(schema, f.type.name)]

    chosen: list[str] = []
    if style == "minimal":
        if scalars:
            chosen.append(scalars[0].name)
    else:
        chosen.extend(f.name for f in scalars)

    if depth > 1:
        for f in composites:
            if f.type.name in _seen:
                continue  # cycle guard: never re-enter a type on the same branch
            inner = build_selection(
                schema, f.type.name, depth=depth - 1, style=style,
                _seen=_seen | {type_name},
            )
            if inner:
                chosen.append(f"{f.name} {inner}")
            if style == "minimal" and chosen:
                break

    if not chosen:
        # Last resort: an object whose only fields are composites we cannot
        # expand (depth exhausted). Reach one level deeper for a single scalar.
        for f in composites:
            if f.type.name in _seen:
                continue
            inner = build_selection(
                schema, f.type.name, depth=1, style="minimal", _seen=_seen | {type_name}
            )
            if inner:
                chosen.append(f"{f.name} {inner}")
                break
    if not chosen:
        raise SelectionError(f"no selectable field on type {type_name!r}")
    return "{ " + " ".join(chosen) + " }"


def render_literal(value: Any) -> str:
    """Render a Python value as a GraphQL literal.

    Enum values are passed through unquoted via :class:`RawLiteral`; everything
    else uses JSON, whose scalar syntax GraphQL shares.
    """
    if isinstance(value, RawLiteral):
        return str(value)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value)  # JSON string escaping is GraphQL-compatible
    if isinstance(value, list):
        return "[" + ", ".join(render_literal(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {render_literal(v)}" for k, v in value.items()) + "}"
    return json.dumps(str(value))


class RawLiteral(str):
    """A literal emitted verbatim — enum members, or a crafted injection payload."""


def build_operation(
    schema: Schema,
    operation: Operation,
    *,
    args: dict[str, Any] | None = None,
    depth: int = 1,
    style: str = "minimal",
) -> str:
    """Render a complete, executable GraphQL document for one operation."""
    args = args or {}
    rendered_args = ", ".join(f"{k}: {render_literal(v)}" for k, v in args.items())
    call = f"{operation.name}({rendered_args})" if rendered_args else operation.name
    selection = build_selection(schema, operation.type.name, depth=depth, style=style)
    body = f"{call} {selection}".strip()
    keyword = "query" if operation.kind == "query" else operation.kind
    return f"{keyword} {{ {body} }}"


def default_argument(ref: TypeRef, schema: "Schema | None" = None, _depth: int = 0) -> Any:
    """A syntactically valid placeholder for an argument of type ``ref``.

    Deliberately dumb for scalars: this is the *fallback* for when neither the
    objects bucket nor retrieval supplies a real value. GraphQLer's paper names
    random scalars as a root cause of unreachable operations, which is exactly
    the gap the LLM generator is meant to close.

    Input objects are different — a scalar placeholder in an input-object slot is
    always a type error — so when a schema is available their **required**
    members are filled recursively, producing a well-typed minimal object.
    """
    if ref.is_list:
        return [default_argument(TypeRef(name=ref.name), schema, _depth)]

    if schema is not None and _depth < 4:
        type_def = schema.type(ref.name)
        if type_def is not None and type_def.is_input:
            return {
                f.name: default_argument(f.type, schema, _depth + 1)
                for f in type_def.required_fields
            }
        if type_def is not None and type_def.kind == "ENUM" and type_def.fields:
            return RawLiteral(type_def.fields[0].name)

    name = ref.name
    if name == "Int":
        return 1
    if name == "Float":
        return 1.0
    if name == "Boolean":
        return True
    if name == "ID":
        return "1"
    return "test"
