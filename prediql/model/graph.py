"""Typed dependency graph over a normalized schema.

GraphQL declares object-to-object field relationships but never says which
*input* an operation needs from which object. Those edges are inferred, which is
what makes ordered chains (CREATE -> READ, CREATE -> DELETE -> READ) possible at
all. The algorithm follows GraphQLer's, re-implemented here so PrediQL does not
depend on having run that tool first:

* **action labelling** — CREATE / UPDATE / DELETE / READ from the operation name,
  ``UNKNOWN`` when the evidence is ambiguous (an honest label beats a confident
  wrong one, which suppresses chains);
* **edge inference** — an ID-typed argument yields a candidate object name
  (``userId`` -> ``User``), matched against declared types by containment and
  edit distance; ``NON_NULL`` gives a hard dependency, nullable a soft one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from prediql.model.schema import Operation, Schema, TypeRef


class Action(StrEnum):
    """Mutation semantics, inferred from the operation name."""

    CREATE = "CREATE"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    READ = "READ"
    UNKNOWN = "UNKNOWN"


_ACTION_VERBS: tuple[tuple[Action, tuple[str, ...]], ...] = (
    (Action.CREATE, ("create", "add", "new", "insert", "register", "signup", "post", "make")),
    (Action.DELETE, ("delete", "remove", "destroy", "drop", "purge", "revoke", "cancel")),
    (Action.UPDATE, ("update", "edit", "modify", "set", "change", "patch", "rename", "toggle")),
)


def infer_action(operation: Operation) -> Action:
    """Label a mutation by verb prefix; queries are always READ."""
    if operation.kind == "query":
        return Action.READ
    name = operation.name.lower()
    for action, verbs in _ACTION_VERBS:
        if any(name.startswith(verb) for verb in verbs):
            return action
    return Action.UNKNOWN


def levenshtein(a: str, b: str) -> int:
    """Edit distance, iterative two-row form."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            )
        previous = current
    return previous[-1]


#: Shortest stem that can plausibly name an entity. Below this, a trailing "id"
#: belonged to an atomic identifier token (pid, uuid, guid, oid, did) rather than
#: an "<entity>Id" suffix, so the remnant must not be used as a match candidate.
_MIN_ENTITY_STEM = 3
#: Shortest candidate that may match a type by containment, for the same reason:
#: "user" in "useraccount" is a real hint, "p" in "accesspoint" is noise.
_MIN_MATCH_LEN = 3


def _candidate_object_name(arg_name: str, operation: Operation) -> str:
    """Derive the object an ID-typed argument probably refers to.

    ``userId``/``userIds`` -> ``user``; a bare ``id`` falls back to the
    operation's return type, then to the operation name with its CRUD verb
    stripped — the same ladder GraphQLer describes.

    A trailing ``id`` is read as an ``<entity>Id`` suffix only when the stem it
    leaves is long enough to name an entity. Opaque identifier tokens — ``pid``,
    ``uuid``, ``guid``, ``oid``, ``did`` — are atomic: stripping ``id`` yields a
    1-2 char remnant that fuzzy-matches an unrelated type, so they keep their
    whole name and usually resolve to no producer (an UNKNOWN edge, preferred
    over a wrong one). This is a schema-general rule, not tied to any argument.
    """
    lowered = arg_name.lower()
    for suffix in ("ids", "id"):
        if lowered.endswith(suffix) and len(lowered) > len(suffix):
            stem = lowered[: -len(suffix)]
            return stem if len(stem) >= _MIN_ENTITY_STEM else lowered
    if lowered in ("id", "ids"):
        # Prefer the entity named by a CRUD operation name (delete<X>/update<X>/
        # get<X>) over the return type: a delete/update often returns a payload
        # wrapper (e.g. DeleteNote), not the entity, which would strand the op on
        # the wrapper and lose its chain. A get<X> returning the entity resolves
        # to the same name either way, so this only corrects the wrapper case.
        stem = operation.name.lower()
        for _, verbs in _ACTION_VERBS:
            for verb in verbs:
                if stem.startswith(verb) and len(stem) - len(verb) >= _MIN_ENTITY_STEM:
                    return stem[len(verb):]
        if operation.type.name not in ("", "Unknown"):
            return operation.type.name.lower()
        return stem
    return lowered


def resolve_object(candidate: str, schema: Schema, *, max_distance: int = 5) -> str | None:
    """Match a candidate name to a declared object type.

    Exact match first, then *substantial* containment (``user`` matches
    ``UserAccount``), then nearest edit distance within a *length-scaled*
    threshold. Both fuzzy paths guard against short, low-information candidates:
    a 1-2 char stem must not match a long type just by appearing inside it, and
    the distance tolerance shrinks with the shorter name so a 3-letter token is
    not matched onto a nearly-unrelated type. Returns ``None`` rather than
    guessing — an UNKNOWN edge is better than a wrong one.
    """
    if not candidate:
        return None
    target = candidate.replace("_", "").lower()
    best: tuple[int, str] | None = None
    for name, type_def in schema.types.items():
        if type_def.kind != "OBJECT" or name.startswith("__"):
            continue
        normalized = name.replace("_", "").lower()
        if normalized == target:
            return name
        contained = (
            len(target) >= _MIN_MATCH_LEN
            and (normalized in target or target in normalized)
        )
        # Tolerance scales with the shorter of the two names, so a short candidate
        # must match closely (``usr`` -> ``user``) instead of drifting onto any
        # 4-letter type within a fixed edit budget.
        limit = min(max_distance, max(1, min(len(target), len(normalized)) // 2))
        distance = levenshtein(normalized, target)
        if contained or distance <= limit:
            score = 0 if contained else distance
            if best is None or score < best[0]:
                best = (score, name)
    return best[1] if best else None


@dataclass(frozen=True, slots=True)
class Edge:
    """A directed dependency between a graph node and an operation."""

    source: str
    target: str
    kind: str  # "hard" | "soft" | "output"
    via: str = ""  # the argument or field that produced the edge


@dataclass
class DependencyGraph:
    """Operations, object types, and the inferred edges between them."""

    actions: dict[str, Action] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    objects: set[str] = field(default_factory=set)
    unresolved: dict[str, list[str]] = field(default_factory=dict)
    """Operation -> arguments whose object could not be resolved. These are the
    ambiguous cases worth spending a strong model on, and nothing else."""

    def producers_of(self, object_name: str) -> list[str]:
        """Operations whose output is ``object_name``."""
        return [e.source for e in self.edges if e.kind == "output" and e.target == object_name]

    def consumers_of(self, object_name: str) -> list[str]:
        """Operations taking ``object_name`` as an input dependency."""
        return [
            e.target for e in self.edges if e.kind in ("hard", "soft") and e.source == object_name
        ]

    def dependencies_of(self, operation: str) -> list[Edge]:
        return [e for e in self.edges if e.target == operation and e.kind in ("hard", "soft")]

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": {k: str(v) for k, v in sorted(self.actions.items())},
            "objects": sorted(self.objects),
            "edges": [
                {"source": e.source, "target": e.target, "kind": e.kind, "via": e.via}
                for e in self.edges
            ],
            "unresolved": {k: sorted(v) for k, v in sorted(self.unresolved.items())},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DependencyGraph:
        return cls(
            actions={k: Action(v) for k, v in data.get("actions", {}).items()},
            objects=set(data.get("objects", [])),
            edges=[Edge(e["source"], e["target"], e["kind"], e.get("via", ""))
                   for e in data.get("edges", [])],
            unresolved={k: list(v) for k, v in data.get("unresolved", {}).items()},
        )


def _is_id_like(ref: TypeRef) -> bool:
    return ref.name in ("ID", "Int", "String")


def build_graph(schema: Schema) -> DependencyGraph:
    """Infer the dependency graph for a schema (the ``native`` backend)."""
    graph = DependencyGraph()

    for name, type_def in schema.types.items():
        if type_def.kind == "OBJECT" and not name.startswith("__"):
            graph.objects.add(name)

    for operation in schema.operations.values():
        graph.actions[operation.name] = infer_action(operation)

        # Output edge: the operation produces its return type.
        if operation.type.name in graph.objects:
            graph.edges.append(
                Edge(operation.name, operation.type.name, "output", via="return")
            )

        # Input edges: ID-like arguments referring to object types.
        for arg_name, ref in operation.args:
            if not _is_id_like(ref):
                continue
            candidate = _candidate_object_name(arg_name, operation)
            resolved = resolve_object(candidate, schema)
            if resolved is None:
                graph.unresolved.setdefault(operation.name, []).append(arg_name)
                continue
            graph.edges.append(
                Edge(resolved, operation.name, "hard" if ref.non_null else "soft", via=arg_name)
            )

    return graph
