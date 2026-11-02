"""Operation prioritization for large schemas (M6).

On a big GraphQL API — PokeAPI has 459 operations over ~2,000 object types — most
operations are near-duplicates of a handful of shapes, and covering them in
schema order spends the budget on a long tail of variants before ever reaching a
distinct one. v1 took ~80 hours on PokeAPI doing exactly that.

The fix is ordering, not sampling: rank operations so the first pass touches the
widest variety of *shapes*, then let the budget decide when to stop. Diversity is
measured on three axes that actually change what a request exercises:

* **return type** — a new object type is new surface; the tenth operation
  returning ``Pokemon`` is not;
* **action** — CREATE/UPDATE/DELETE/READ exercise different code paths;
* **argument shape** — an operation taking an input object differs from a bare
  lookup.

Within a round-robin over unseen (action, return-type) buckets, cheaper
operations (fewer required arguments) come first, because they are the most
likely to succeed and to populate the objects bucket that later operations need.
"""

from __future__ import annotations

from prediql.model.graph import Action, DependencyGraph
from prediql.model.schema import Operation, Schema


def _signature(operation: Operation, graph: DependencyGraph) -> tuple[str, str]:
    """The diversity bucket an operation falls into."""
    action = str(graph.actions.get(operation.name, Action.UNKNOWN))
    return action, operation.type.name


def _cost(operation: Operation) -> tuple[int, int, str]:
    """Cheap-first ordering within a bucket: fewer required args wins."""
    required = len(operation.required_args)
    return required, len(operation.args), operation.name


def prioritize(
    schema: Schema,
    graph: DependencyGraph,
    *,
    limit: int | None = None,
) -> list[Operation]:
    """Order operations for maximum shape diversity, optionally capping the count.

    Round-robins across (action, return-type) buckets so the first N operations
    span N distinct shapes wherever the schema allows, rather than N variants of
    one. Returns every operation when ``limit`` is None — the ordering still
    matters, because the budget may stop the run early.
    """
    buckets: dict[tuple[str, str], list[Operation]] = {}
    for operation in schema.operations.values():
        buckets.setdefault(_signature(operation, graph), []).append(operation)
    for group in buckets.values():
        group.sort(key=_cost)

    # Deterministic bucket order: cheapest representative first, then by name.
    order = sorted(buckets, key=lambda key: (_cost(buckets[key][0]), key))

    ordered: list[Operation] = []
    depth = 0
    while True:
        added = False
        for key in order:
            group = buckets[key]
            if depth < len(group):
                ordered.append(group[depth])
                added = True
                if limit is not None and len(ordered) >= limit:
                    return ordered
        if not added:
            break
        depth += 1
    return ordered


def diversity_report(operations: list[Operation], graph: DependencyGraph) -> dict[str, int]:
    """How much shape variety a selection covers — for the run's metrics."""
    return {
        "operations": len(operations),
        "distinct_return_types": len({op.type.name for op in operations}),
        "distinct_actions": len({str(graph.actions.get(op.name, Action.UNKNOWN))
                                 for op in operations}),
    }
