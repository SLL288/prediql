"""Normalized GraphQL schema.

A clean projection of a GraphQL introspection result: the engine, the coverage
metric, and the dependency graph all read this rather than raw introspection
JSON, so nothing downstream depends on introspection's verbose wire shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCALAR_KINDS = frozenset({"SCALAR", "ENUM"})
WRAPPER_KINDS = frozenset({"NON_NULL", "LIST"})


@dataclass(frozen=True, slots=True)
class TypeRef:
    """A field or argument's type, with wrappers flattened into flags."""

    name: str
    is_list: bool = False
    non_null: bool = False

    def __str__(self) -> str:
        base = f"[{self.name}]" if self.is_list else self.name
        return f"{base}!" if self.non_null else base


@dataclass(frozen=True, slots=True)
class Field:
    name: str
    type: TypeRef
    args: tuple[tuple[str, TypeRef], ...] = ()
    description: str = ""


@dataclass(frozen=True, slots=True)
class TypeDef:
    name: str
    kind: str
    fields: tuple[Field, ...] = ()
    possible_types: tuple[str, ...] = ()

    @property
    def is_composite(self) -> bool:
        """True for types that can carry a selection set."""
        return self.kind in {"OBJECT", "INTERFACE", "UNION"}

    @property
    def is_input(self) -> bool:
        return self.kind == "INPUT_OBJECT"

    def field(self, name: str) -> Field | None:
        for candidate in self.fields:
            if candidate.name == name:
                return candidate
        return None

    @property
    def required_fields(self) -> tuple[Field, ...]:
        """Input members the schema makes mandatory."""
        return tuple(f for f in self.fields if f.type.non_null)


@dataclass(frozen=True, slots=True)
class Operation:
    """A field on a root type — what the metric calls an *operation*."""

    name: str
    kind: str  # "query" | "mutation" | "subscription"
    type: TypeRef
    args: tuple[tuple[str, TypeRef], ...] = ()
    description: str = ""

    @property
    def required_args(self) -> tuple[str, ...]:
        return tuple(name for name, ref in self.args if ref.non_null)


@dataclass(frozen=True, slots=True)
class Schema:
    """Normalized schema plus the root operation index."""

    types: dict[str, TypeDef] = field(default_factory=dict)
    operations: dict[str, Operation] = field(default_factory=dict)
    query_type: str = "Query"
    mutation_type: str | None = None
    subscription_type: str | None = None

    def type(self, name: str) -> TypeDef | None:
        return self.types.get(name)

    def operations_of(self, kind: str) -> tuple[Operation, ...]:
        return tuple(op for op in self.operations.values() if op.kind == kind)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form for the artifact store."""
        return {
            "query_type": self.query_type,
            "mutation_type": self.mutation_type,
            "subscription_type": self.subscription_type,
            "types": {
                name: {
                    "kind": t.kind,
                    "possible_types": list(t.possible_types),
                    "fields": [
                        {
                            "name": f.name,
                            "type": {"name": f.type.name, "is_list": f.type.is_list,
                                     "non_null": f.type.non_null},
                            "args": [
                                {"name": a, "type": {"name": r.name, "is_list": r.is_list,
                                                     "non_null": r.non_null}}
                                for a, r in f.args
                            ],
                            "description": f.description,
                        }
                        for f in t.fields
                    ],
                }
                for name, t in sorted(self.types.items())
            },
            "operations": {
                name: {
                    "kind": op.kind,
                    "type": {"name": op.type.name, "is_list": op.type.is_list,
                             "non_null": op.type.non_null},
                    "args": [
                        {"name": a, "type": {"name": r.name, "is_list": r.is_list,
                                             "non_null": r.non_null}}
                        for a, r in op.args
                    ],
                    "description": op.description,
                }
                for name, op in sorted(self.operations.items())
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Schema:
        """Inverse of :meth:`to_dict` — rehydrate from the artifact store."""

        def _ref(raw: dict[str, Any]) -> TypeRef:
            return TypeRef(raw["name"], bool(raw.get("is_list")), bool(raw.get("non_null")))

        def _args(raw: list[dict[str, Any]]) -> tuple[tuple[str, TypeRef], ...]:
            return tuple((a["name"], _ref(a["type"])) for a in raw)

        types = {
            name: TypeDef(
                name=name,
                kind=t["kind"],
                possible_types=tuple(t.get("possible_types", ())),
                fields=tuple(
                    Field(f["name"], _ref(f["type"]), _args(f.get("args", [])),
                          f.get("description", ""))
                    for f in t.get("fields", [])
                ),
            )
            for name, t in data.get("types", {}).items()
        }
        operations = {
            name: Operation(name, op["kind"], _ref(op["type"]), _args(op.get("args", [])),
                            op.get("description", ""))
            for name, op in data.get("operations", {}).items()
        }
        return cls(
            types=types,
            operations=operations,
            query_type=data.get("query_type", "Query"),
            mutation_type=data.get("mutation_type"),
            subscription_type=data.get("subscription_type"),
        )


# ---------------------------------------------------------------------------
# Introspection -> Schema
# ---------------------------------------------------------------------------


def _flatten(type_node: dict[str, Any] | None) -> TypeRef:
    """Collapse NON_NULL/LIST wrappers into a named ref with flags."""
    is_list = False
    non_null = False
    node = type_node or {}
    while node.get("kind") in WRAPPER_KINDS:
        if node["kind"] == "NON_NULL":
            non_null = True
        else:
            is_list = True
        node = node.get("ofType") or {}
    return TypeRef(name=node.get("name") or "Unknown", is_list=is_list, non_null=non_null)


def from_introspection(payload: dict[str, Any]) -> Schema:
    """Build a :class:`Schema` from a standard introspection response.

    Accepts either the full envelope (``{"data": {"__schema": ...}}``) or the
    bare ``__schema`` object, since both shapes show up in saved fixtures.
    """
    root = payload.get("data", payload)
    schema_node = root.get("__schema", root)

    query_type = (schema_node.get("queryType") or {}).get("name") or "Query"
    mutation_type = (schema_node.get("mutationType") or {}).get("name")
    subscription_type = (schema_node.get("subscriptionType") or {}).get("name")

    types: dict[str, TypeDef] = {}
    for node in schema_node.get("types", []):
        name = node.get("name") or ""
        if not name or name.startswith("__"):
            continue  # introspection meta-types are not part of the API surface
        # A type's members live under a different key per kind. Reading only
        # ``fields`` (as v1 effectively did) leaves input objects and enums
        # empty, and every operation requiring one becomes unreachable because
        # no valid argument value can be constructed.
        raw_fields = node.get("fields") or node.get("inputFields") or []
        if not raw_fields and node.get("enumValues"):
            # Enum members are values, not fields; modelling them as fields with
            # their own type keeps one accessor for "what can this type hold".
            raw_fields = [
                {"name": v["name"], "type": {"kind": "ENUM", "name": name}}
                for v in node["enumValues"]
                if v.get("name")
            ]
        fields = tuple(
            Field(
                name=f["name"],
                type=_flatten(f.get("type")),
                args=tuple((a["name"], _flatten(a.get("type"))) for a in (f.get("args") or [])),
                description=(f.get("description") or "")[:200],
            )
            for f in raw_fields
        )
        types[name] = TypeDef(
            name=name,
            kind=node.get("kind", "OBJECT"),
            fields=fields,
            possible_types=tuple(
                p["name"] for p in (node.get("possibleTypes") or []) if p.get("name")
            ),
        )

    operations: dict[str, Operation] = {}
    for root_name, kind in (
        (query_type, "query"),
        (mutation_type, "mutation"),
        (subscription_type, "subscription"),
    ):
        if not root_name or root_name not in types:
            continue
        for f in types[root_name].fields:
            # Query/mutation take precedence over a same-named subscription field.
            # Hasura-style schemas (e.g. PokeAPI) mirror every query field under
            # the subscription root; without this guard the subscription version
            # overwrites the query, and the generator emits `subscription {…}`
            # operations that return empty over HTTP POST — zero coverage on an
            # API that is in fact fully queryable.
            if kind == "subscription" and f.name in operations:
                continue
            operations[f.name] = Operation(name=f.name, kind=kind, type=f.type, args=f.args,
                                           description=f.description)

    return Schema(
        types=types,
        operations=operations,
        query_type=query_type,
        mutation_type=mutation_type,
        subscription_type=subscription_type,
    )
