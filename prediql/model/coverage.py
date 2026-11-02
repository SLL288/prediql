"""Response-grounded coverage (doc 11).

v1 measured coverage from the *generated query text*: a field that was requested
but came back ``null`` — or inside an errored response — still counted as
covered. That is a construct-validity defect (reviewer 40C-1) and it inflates the
headline number.

Here a field path counts only when the server actually **returned a non-null
value** for it in a successful response:

    covered(op) = ⋃ over successful responses r:
        { p ∈ selection_paths(query(r)) : value_at(r.data, p) is present and non-null }

Two consequences worth stating: selection paths come from a real GraphQL parser
(aliases, fragments and inline fragments handled correctly) rather than a regex
tokenizer, and the denominator is bounded by an explicit depth ``D`` that is
published alongside the metric, so "coverage" has one unambiguous meaning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from graphql import parse
from graphql.language import ast as gql_ast

from prediql.model.schema import Schema

__all__ = [
    "CoverageState",
    "count_reachable_paths",
    "covered_paths",
    "is_reachable_path",
    "reachable_paths",
    "selection_paths",
]


# ---------------------------------------------------------------------------
# Requested paths — from the document, via a real parser
# ---------------------------------------------------------------------------


def selection_paths(document: str) -> set[str]:
    """Dotted field paths a GraphQL document requests.

    Aliases resolve to the underlying field name (``a: name`` -> ``name``), named
    fragments are expanded at their spread sites, and inline fragments contribute
    their fields to the enclosing path. Returns an empty set for unparseable
    input rather than raising: a malformed candidate is a coverage non-event, not
    a crash.
    """
    try:
        doc = parse(document)
    except Exception:
        return set()

    fragments: dict[str, gql_ast.FragmentDefinitionNode] = {
        d.name.value: d for d in doc.definitions
        if isinstance(d, gql_ast.FragmentDefinitionNode)
    }
    paths: set[str] = set()

    def walk(selection_set: gql_ast.SelectionSetNode | None, prefix: tuple[str, ...],
             seen_fragments: frozenset[str]) -> None:
        if selection_set is None:
            return
        for node in selection_set.selections:
            if isinstance(node, gql_ast.FieldNode):
                # The alias is a response key; the *field* is the schema element.
                path = (*prefix, node.name.value)
                paths.add(".".join(path))
                walk(node.selection_set, path, seen_fragments)
            elif isinstance(node, gql_ast.InlineFragmentNode):
                walk(node.selection_set, prefix, seen_fragments)
            elif isinstance(node, gql_ast.FragmentSpreadNode):
                name = node.name.value
                if name in seen_fragments:
                    continue  # cyclic fragment: stop rather than recurse forever
                fragment = fragments.get(name)
                if fragment is not None:
                    walk(fragment.selection_set, prefix, seen_fragments | {name})

    for definition in doc.definitions:
        if isinstance(definition, gql_ast.OperationDefinitionNode):
            walk(definition.selection_set, (), frozenset())
    return paths


def _alias_map(document: str) -> dict[str, str]:
    """Map response keys back to field names, for aliased selections.

    A response carries the *alias* as its key, so walking the data by field name
    would miss aliased fields entirely.
    """
    try:
        doc = parse(document)
    except Exception:
        return {}
    mapping: dict[str, str] = {}

    def walk(selection_set: gql_ast.SelectionSetNode | None) -> None:
        if selection_set is None:
            return
        for node in selection_set.selections:
            if isinstance(node, gql_ast.FieldNode):
                if node.alias:
                    mapping[node.alias.value] = node.name.value
                walk(node.selection_set)
            elif isinstance(node, (gql_ast.InlineFragmentNode,)):
                walk(node.selection_set)

    for definition in doc.definitions:
        if isinstance(definition, gql_ast.OperationDefinitionNode):
            walk(definition.selection_set)
    return mapping


# ---------------------------------------------------------------------------
# Returned paths — from the response data
# ---------------------------------------------------------------------------


def _returned_paths(data: Any, prefix: tuple[str, ...], alias_to_field: dict[str, str],
                    out: set[str], depth_budget: int) -> None:
    """Collect dotted paths that carry a non-null value in ``data``."""
    if depth_budget < 0 or data is None:
        return
    if isinstance(data, list):
        for item in data:
            _returned_paths(item, prefix, alias_to_field, out, depth_budget)
        return
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        if value is None:
            continue  # requested but not returned -> not covered
        name = alias_to_field.get(key, key)
        path = (*prefix, name)
        if isinstance(value, (dict, list)):
            # A composite counts only if something inside it is non-null.
            before = len(out)
            _returned_paths(value, path, alias_to_field, out, depth_budget - 1)
            if len(out) > before or (isinstance(value, list) and _has_scalar(value)):
                out.add(".".join(path))
        else:
            out.add(".".join(path))


def _has_scalar(items: list[Any]) -> bool:
    """True when a list holds at least one non-null scalar element."""
    return any(item is not None and not isinstance(item, (dict, list)) for item in items)


def covered_paths(document: str, data: dict[str, Any] | None, *, max_depth: int = 20) -> set[str]:
    """Field paths that the server actually returned a non-null value for.

    This is the intersection of what the document asked for and what the
    response delivered — the response-grounded definition.
    """
    if not data:
        return set()
    returned: set[str] = set()
    _returned_paths(data, (), _alias_map(document), returned, max_depth)
    return returned & selection_paths(document)


# ---------------------------------------------------------------------------
# The denominator
# ---------------------------------------------------------------------------


def _members(schema: Schema, type_name: str) -> dict[str, str]:
    """Selectable members of a composite type: ``{field_name: child_type_name}``.

    The single definition both the counter and the enumerator use. For a union or
    interface the members are the type's own fields plus those of its possible
    types, **deduplicated by name with the first declaration winning** — a client
    cannot select one field name twice with two different shapes anyway, and the
    rule makes the reachable set exactly countable.
    """
    type_def = schema.type(type_name)
    if type_def is None or not type_def.is_composite:
        return {}
    members: dict[str, str] = {}
    for field_def in type_def.fields:
        members.setdefault(field_def.name, field_def.type.name)
    for possible in type_def.possible_types:
        candidate = schema.type(possible)
        if candidate is None:
            continue
        for field_def in candidate.fields:
            members.setdefault(field_def.name, field_def.type.name)
    return members


def count_reachable_paths(schema: Schema, *, depth: int = 5) -> int:
    """Size of the reachable path set, computed **without materialising it**.

    The set grows as ``fan-out ^ depth``: on a large schema (PokeAPI has ~2,000
    object types) enumerating it means tens of millions of strings and gigabytes
    of memory, which made the metric unusable at exactly the production scale it
    needs to describe. The count is a memoised recurrence over
    ``(type, remaining_depth)`` instead, so it is O(types x depth).
    """
    memo: dict[tuple[str, int], int] = {}

    def below(type_name: str, remaining: int) -> int:
        if remaining <= 0:
            return 0
        key = (type_name, remaining)
        cached = memo.get(key)
        if cached is not None:
            return cached
        # Guard against a cycle re-entering the same (type, depth) mid-computation.
        memo[key] = 0
        total = sum(
            1 + below(child, remaining - 1) for child in _members(schema, type_name).values()
        )
        memo[key] = total
        return total

    return sum(1 + below(op.type.name, depth) for op in schema.operations.values())


def is_reachable_path(schema: Schema, path: str, *, depth: int = 5) -> bool:
    """Whether ``path`` lies in the reachable set, by walking rather than enumerating.

    The numerator is small (the paths actually covered), so testing membership
    one path at a time is far cheaper than building the whole denominator set.
    """
    head, _, rest = path.partition(".")
    operation = schema.operations.get(head)
    if operation is None:
        return False
    current = operation.type.name
    remaining = depth
    while rest:
        segment, _, rest = rest.partition(".")
        if remaining <= 0:
            return False
        child = _members(schema, current).get(segment)
        if child is None:
            return False
        current = child
        remaining -= 1
    return True


def reachable_paths(schema: Schema, *, depth: int = 5) -> set[str]:
    """Enumerate the reachable path set.

    Exposed for small schemas, tests, and diagnostics. Prefer
    :func:`count_reachable_paths` and :func:`is_reachable_path` on anything
    large — this materialises every path.
    """
    paths: set[str] = set()

    def expand(type_name: str, prefix: tuple[str, ...], remaining: int) -> None:
        if remaining <= 0:
            return
        for field_name, child in _members(schema, type_name).items():
            path = (*prefix, field_name)
            paths.add(".".join(path))
            expand(child, path, remaining - 1)

    for operation in schema.operations.values():
        paths.add(operation.name)
        expand(operation.type.name, (operation.name,), depth)
    return paths


def total_schema_elements(schema: Schema) -> int:
    """Number of distinct ``Type.field`` pairs the schema declares.

    The scale-stable denominator. Path counts multiply combinatorially with
    nesting depth (a 200-type schema reaches ~61M paths at depth 5), so a
    path-based ratio on a large API is a vanishingly small number that says more
    about the schema's branching factor than about what the fuzzer reached.
    Element coverage is linear in schema size and is the schema-element coverage
    notion standard elsewhere in testing.
    """
    return sum(
        len(_members(schema, name))
        for name, type_def in schema.types.items()
        if type_def.is_composite
    )


def covered_schema_elements(schema: Schema, paths: set[str], *, depth: int) -> set[str]:
    """``Type.field`` pairs witnessed by a set of covered paths.

    Walks each path through the schema, recording the declaring type at every
    step, so ``continents.countries.name`` credits ``Continent.countries`` and
    ``Country.name`` rather than one opaque string.
    """
    elements: set[str] = set()
    for path in paths:
        head, _, rest = path.partition(".")
        operation = schema.operations.get(head)
        if operation is None:
            continue
        elements.add(f"{schema.query_type if operation.kind == 'query' else operation.kind}.{head}")
        current = operation.type.name
        remaining = depth
        while rest and remaining > 0:
            segment, _, rest = rest.partition(".")
            child = _members(schema, current).get(segment)
            if child is None:
                break
            elements.add(f"{current}.{segment}")
            current = child
            remaining -= 1
    return elements


# ---------------------------------------------------------------------------
# Accumulated state
# ---------------------------------------------------------------------------


@dataclass
class CoverageState:
    """Per-operation accumulated coverage, and the bandit's Δcoverage signal."""

    depth: int = 5
    by_operation: dict[str, set[str]] = field(default_factory=dict)

    def observe(self, operation: str, document: str, data: dict[str, Any] | None) -> int:
        """Fold one successful response in; return the number of *new* paths.

        The return value is Δcoverage — the bandit rewards an arm only when this
        is positive, i.e. the batch made a previously-unseen schema field
        actually return data.
        """
        seen = self.by_operation.setdefault(operation, set())
        fresh = covered_paths(document, data) - seen
        seen |= fresh
        return len(fresh)

    def covered_operations(self) -> set[str]:
        return {op for op, paths in self.by_operation.items() if paths}

    def all_paths(self) -> set[str]:
        return set().union(*self.by_operation.values()) if self.by_operation else set()

    def operation_coverage(self, schema: Schema) -> float:
        """|operations with >=1 covered path| / |operations| (GraphQLer-comparable)."""
        total = len(schema.operations)
        return len(self.covered_operations()) / total if total else 0.0

    def _covered_reachable(self, schema: Schema) -> int:
        """Covered paths that lie inside the reachable denominator."""
        return sum(
            1 for path in self.all_paths()
            if is_reachable_path(schema, path, depth=self.depth)
        )

    def field_coverage(self, schema: Schema) -> float:
        """|distinct covered field paths| / |reachable paths at depth D|."""
        total = count_reachable_paths(schema, depth=self.depth)
        if not total:
            return 0.0
        return self._covered_reachable(schema) / total

    def element_coverage(self, schema: Schema) -> float:
        """|covered Type.field pairs| / |declared Type.field pairs|.

        The scale-stable field metric, and the one to quote on a large schema.
        """
        total = total_schema_elements(schema)
        if not total:
            return 0.0
        return len(covered_schema_elements(schema, self.all_paths(), depth=self.depth)) / total

    def report(self, schema: Schema) -> dict[str, Any]:
        """Every metric plus its raw counts, for the artifact and the dashboard.

        Three numbers, each with a stated denominator, because one number cannot
        answer both "did we reach the operation" and "did we exercise the type":

        * ``operation_coverage`` — GraphQLer-comparable reachability;
        * ``element_coverage`` — distinct ``Type.field`` pairs, scale-stable;
        * ``field_path_coverage`` — depth-bounded nested paths, informative on
          small schemas and reported with its depth so it is never ambiguous.
        """
        total_reachable = count_reachable_paths(schema, depth=self.depth)
        covered_count = self._covered_reachable(schema)
        elements = covered_schema_elements(schema, self.all_paths(), depth=self.depth)
        total_elements = total_schema_elements(schema)
        return {
            "depth": self.depth,
            "operation_coverage": round(self.operation_coverage(schema), 4),
            "element_coverage": round(self.element_coverage(schema), 4),
            "field_path_coverage": round(self.field_coverage(schema), 8),
            "operations_covered": len(self.covered_operations()),
            "operations_total": len(schema.operations),
            "elements_covered": len(elements),
            "elements_total": total_elements,
            "field_paths_covered": covered_count,
            "field_paths_reachable": total_reachable,
            "by_operation": {op: sorted(p) for op, p in sorted(self.by_operation.items()) if p},
        }

    def to_dict(self) -> dict[str, Any]:
        return {"depth": self.depth,
                "by_operation": {k: sorted(v) for k, v in self.by_operation.items()}}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CoverageState:
        return cls(
            depth=int(data.get("depth", 5)),
            by_operation={k: set(v) for k, v in data.get("by_operation", {}).items()},
        )
