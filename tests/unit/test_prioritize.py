"""Large-schema prioritization: diversity-first ordering under a cap."""

from __future__ import annotations

from prediql.generation.prioritize import diversity_report, prioritize
from prediql.model.graph import build_graph
from prediql.model.schema import from_introspection


def _schema(n_variants: int = 10):
    """A schema shaped like a real large API: many variants of a few shapes.

    20 `pokemonN` queries all returning Pokemon, plus a handful of operations
    returning distinct types. Schema order puts the long tail first.
    """
    query_fields = [
        {"name": f"pokemon{i}", "type": {"kind": "OBJECT", "name": "Pokemon"}, "args": []}
        for i in range(n_variants)
    ]
    query_fields += [
        {"name": "berry", "type": {"kind": "OBJECT", "name": "Berry"}, "args": []},
        {"name": "move", "type": {"kind": "OBJECT", "name": "Move"}, "args": []},
        {"name": "region", "type": {"kind": "OBJECT", "name": "Region"}, "args": []},
    ]
    types = [
        {"name": "Query", "kind": "OBJECT", "fields": query_fields},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "createTeam", "type": {"kind": "OBJECT", "name": "Team"}, "args": []},
            {"name": "deleteTeam", "type": {"kind": "OBJECT", "name": "Team"},
             "args": [{"name": "teamId", "type": {"kind": "NON_NULL",
                                                  "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
        ]},
    ]
    for name in ("Pokemon", "Berry", "Move", "Region", "Team"):
        types.append({"name": name, "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]})
    return from_introspection({"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": types}}})


def test_prioritized_order_beats_schema_order_on_diversity():
    """The whole point: under a cap, cover more distinct shapes."""
    schema = _schema()
    graph = build_graph(schema)
    cap = 5

    prioritized = prioritize(schema, graph, limit=cap)
    schema_order = list(schema.operations.values())[:cap]

    p_types = len({op.type.name for op in prioritized})
    s_types = len({op.type.name for op in schema_order})
    assert p_types > s_types, f"prioritized {p_types} vs schema-order {s_types} return types"
    assert p_types == cap, "each of the first 5 should be a different shape"


def test_cap_is_respected_exactly():
    schema = _schema()
    graph = build_graph(schema)
    assert len(prioritize(schema, graph, limit=3)) == 3
    assert len(prioritize(schema, graph, limit=1000)) == len(schema.operations)


def test_no_cap_still_returns_every_operation():
    """Ordering matters even uncapped — the budget may stop the run early."""
    schema = _schema()
    graph = build_graph(schema)
    ordered = prioritize(schema, graph, limit=None)
    assert len(ordered) == len(schema.operations)
    assert {op.name for op in ordered} == set(schema.operations)


def test_cheaper_operations_come_before_costlier_ones_in_a_bucket():
    """createTeam (no args) should precede deleteTeam (required id)."""
    schema = _schema()
    graph = build_graph(schema)
    names = [op.name for op in prioritize(schema, graph, limit=None)]
    assert names.index("createTeam") < names.index("deleteTeam")


def test_actions_are_spread_not_clustered():
    schema = _schema()
    graph = build_graph(schema)
    first = prioritize(schema, graph, limit=6)
    actions = {str(graph.actions.get(op.name)) for op in first}
    assert len(actions) >= 2, "the early selection should span more than one action"


def test_ordering_is_deterministic():
    schema = _schema()
    graph = build_graph(schema)
    a = [op.name for op in prioritize(schema, graph, limit=8)]
    b = [op.name for op in prioritize(schema, graph, limit=8)]
    assert a == b


def test_diversity_report_counts_shapes():
    schema = _schema()
    graph = build_graph(schema)
    report = diversity_report(prioritize(schema, graph, limit=4), graph)
    assert report["operations"] == 4
    assert report["distinct_return_types"] == 4
