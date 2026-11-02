"""Chain synthesis: IDOR and UAF plans from graph edges, with gating."""

from __future__ import annotations

from prediql.model.graph import build_graph
from prediql.model.schema import from_introspection
from prediql.security.chains import synthesize

# A note service: createNote -> Note; getNote(id), deleteNote(id) consume Note.
SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "getNote", "type": {"kind": "OBJECT", "name": "Note"},
             "args": [{"name": "noteId", "type": {"kind": "NON_NULL",
                                                  "ofType": {"kind": "SCALAR", "name": "ID"}}}]}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "createNote", "type": {"kind": "OBJECT", "name": "Note"},
             "args": [{"name": "text", "type": {"kind": "SCALAR", "name": "String"}}]},
            {"name": "deleteNote", "type": {"kind": "OBJECT", "name": "Note"},
             "args": [{"name": "noteId", "type": {"kind": "NON_NULL",
                                                  "ofType": {"kind": "SCALAR", "name": "ID"}}}]}]},
        {"name": "Note", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []},
            {"name": "text", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
    ]}}})
GRAPH = build_graph(SCHEMA)


def _plans(**kw):
    defaults = dict(usable_identities=["primary", "secondary"], allow_destructive=True)
    defaults.update(kw)
    return synthesize(GRAPH, SCHEMA, **defaults)


def test_idor_chain_is_synthesized_from_create_and_read():
    idor = [p for p in _plans() if p.strategy == "idor"]
    assert len(idor) == 1
    plan = idor[0]
    assert [s.operation for s in plan.steps] == ["createNote", "getNote"]
    assert plan.steps[0].role == "primary" and plan.steps[0].produces_object
    assert plan.steps[1].role == "secondary"
    assert plan.steps[1].id_argument == "noteId", "the read fills the id arg from the graph edge"


def test_uaf_quadruple_is_synthesized_create_delete_read():
    uaf = [p for p in _plans() if p.strategy == "uaf"]
    assert len(uaf) == 1
    plan = uaf[0]
    assert [s.operation for s in plan.steps] == ["createNote", "deleteNote", "getNote"]
    assert plan.steps[1].id_argument == "noteId"
    assert plan.steps[2].post_delete is True


def test_idor_blocked_without_two_identities():
    plans = _plans(usable_identities=["only_one"])
    idor = [p for p in plans if p.strategy == "idor"]
    assert idor and all(p.blocked == "needs_identities" for p in idor)


def test_uaf_blocked_without_destructive_permission():
    plans = _plans(allow_destructive=False)
    uaf = [p for p in plans if p.strategy == "uaf"]
    assert uaf and all(p.blocked == "needs_destructive" for p in uaf)
    # IDOR does not need destructive, so it stays runnable.
    idor = [p for p in plans if p.strategy == "idor"]
    assert all(not p.blocked for p in idor)


def test_no_chain_without_the_linking_edge():
    """An object with no create, or no id-consuming read, yields no chain."""
    schema = from_introspection({"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "listThings", "type": {"kind": "LIST",
                                                "ofType": {"kind": "OBJECT", "name": "Thing"}},
                 "args": []}]},
            {"name": "Thing", "kind": "OBJECT", "fields": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
        ]}}})
    plans = synthesize(build_graph(schema), schema,
                       usable_identities=["a", "b"], allow_destructive=True)
    assert plans == [], "no CREATE and no id-arg read -> no chain"


def test_plan_round_trips():
    from prediql.security.chains import ChainPlan
    plan = _plans()[0]
    assert ChainPlan.from_dict(plan.to_dict()).to_dict() == plan.to_dict()
