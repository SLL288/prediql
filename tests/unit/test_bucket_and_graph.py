"""Bucket harvesting and dependency-graph inference."""

from __future__ import annotations

from prediql.model.bucket import ObjectRef, ObjectsBucket
from prediql.model.graph import (Action, _candidate_object_name, build_graph,
                                 infer_action, levenshtein, resolve_object)
from prediql.model.schema import from_introspection

SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "continents",
             "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "Continent"}},
             "args": []},
            {"name": "user", "type": {"kind": "OBJECT", "name": "User"},
             "args": [{"name": "userId",
                       "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
        ]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "createUser", "type": {"kind": "OBJECT", "name": "User"}, "args": []},
            {"name": "deleteUser", "type": {"kind": "OBJECT", "name": "User"},
             "args": [{"name": "userId",
                       "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
            {"name": "frobnicate", "type": {"kind": "OBJECT", "name": "User"}, "args": []},
        ]},
        {"name": "Continent", "kind": "OBJECT", "fields": [
            {"name": "code", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
            {"name": "countries",
             "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "Country"}}, "args": []},
        ]},
        {"name": "Country", "kind": "OBJECT", "fields": [
            {"name": "code", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
        {"name": "User", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
    ]}}})


# --------------------------------------------------------------------------
# Bucket
# --------------------------------------------------------------------------


def test_harvest_files_objects_under_their_schema_type_not_the_response_key():
    """The response key is `continents`; the type is `Continent`."""
    bucket = ObjectsBucket()
    data = {"continents": [{"code": "AF"}, {"code": "EU"}]}
    found = bucket.harvest(data, operation="continents", identity="anon",
                           schema=SCHEMA, root_type="Continent")
    assert found == 2
    assert bucket.types() == ["Continent"]
    assert bucket.any_id("Continent") == "AF"


def test_harvest_descends_through_the_schema_into_nested_types():
    bucket = ObjectsBucket()
    data = {"continents": [{"code": "AF", "countries": [{"code": "NG"}]}]}
    bucket.harvest(data, operation="continents", identity="anon",
                   schema=SCHEMA, root_type="Continent")
    assert set(bucket.types()) == {"Continent", "Country"}
    assert bucket.any_id("Country") == "NG"


def test_explicit_typename_overrides_the_inferred_type():
    bucket = ObjectsBucket()
    bucket.harvest({"thing": {"id": "1", "__typename": "Real"}},
                   operation="thing", identity="anon", schema=SCHEMA, root_type="Guess")
    assert bucket.types() == ["Real"]


def test_harvest_records_the_identity_that_obtained_the_resource():
    """Cross-user chains need to know who saw what."""
    bucket = ObjectsBucket()
    bucket.harvest({"user": {"id": "u1"}}, operation="user", identity="alice",
                   schema=SCHEMA, root_type="User")
    assert bucket.get("User", identity="alice")
    assert bucket.get("User", identity="bob") == []


def test_bucket_deduplicates_per_identity():
    bucket = ObjectsBucket()
    for _ in range(3):
        bucket.add(ObjectRef(type_name="User", identifier="u1", identity="alice"))
    bucket.add(ObjectRef(type_name="User", identifier="u1", identity="bob"))
    assert len(bucket) == 2, "same id under a different identity is a distinct observation"


def test_bucket_round_trips():
    bucket = ObjectsBucket()
    bucket.harvest({"continents": [{"code": "AF"}]}, operation="c", identity="anon",
                   schema=SCHEMA, root_type="Continent")
    restored = ObjectsBucket.from_dict(bucket.to_dict())
    assert restored.any_id("Continent") == "AF"


# --------------------------------------------------------------------------
# Graph
# --------------------------------------------------------------------------


def test_action_inference_from_verbs():
    ops = SCHEMA.operations
    assert infer_action(ops["createUser"]) is Action.CREATE
    assert infer_action(ops["deleteUser"]) is Action.DELETE
    assert infer_action(ops["continents"]) is Action.READ


def test_ambiguous_mutation_is_unknown_not_guessed():
    """An honest UNKNOWN beats a confident wrong label that suppresses chains."""
    assert infer_action(SCHEMA.operations["frobnicate"]) is Action.UNKNOWN


def test_unknown_actions_are_surfaced_for_targeted_resolution():
    graph = build_graph(SCHEMA)
    unknown = [op for op, a in graph.actions.items() if a is Action.UNKNOWN]
    assert unknown == ["frobnicate"], "only the ambiguous subset is worth a strong model"


def test_id_argument_resolves_to_its_object_type():
    graph = build_graph(SCHEMA)
    hard = [(e.source, e.target) for e in graph.edges if e.kind == "hard"]
    assert ("User", "deleteUser") in hard
    assert ("User", "user") in hard


def test_output_edges_record_what_an_operation_produces():
    graph = build_graph(SCHEMA)
    assert "createUser" in graph.producers_of("User")
    assert "deleteUser" in graph.consumers_of("User")


def test_uaf_quadruple_is_discoverable_from_the_graph():
    """create -> object -> delete + read is what a UAF chain needs (doc 02 §4)."""
    graph = build_graph(SCHEMA)
    creates = [op for op in graph.producers_of("User") if graph.actions[op] is Action.CREATE]
    deletes = [op for op in graph.consumers_of("User") if graph.actions[op] is Action.DELETE]
    reads = [op for op in graph.consumers_of("User") if graph.actions[op] is Action.READ]
    assert creates == ["createUser"] and deletes == ["deleteUser"] and reads == ["user"]


def test_resolve_object_prefers_containment_then_distance():
    assert resolve_object("user", SCHEMA) == "User"
    assert resolve_object("usr", SCHEMA) == "User"
    assert resolve_object("zzzzzzzzzzzzzz", SCHEMA) is None


def test_levenshtein_is_correct():
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3
    assert levenshtein("same", "same") == 0


def test_graph_round_trips():
    from prediql.model.graph import DependencyGraph

    graph = build_graph(SCHEMA)
    assert DependencyGraph.from_dict(graph.to_dict()).to_dict() == graph.to_dict()


# --------------------------------------------------------------------------
# Opaque identifier arguments (pid/uuid/guid/oid) must not manufacture edges.
# A general soundness property of the id-argument heuristic — not tied to any
# target API. Surfaced by EHRI's `itemByPid(pid: ID!)`, reproduced synthetically.
# --------------------------------------------------------------------------

OPAQUE_SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "itemByPid", "type": {"kind": "OBJECT", "name": "Node"},
             "args": [{"name": "pid",
                       "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
            {"name": "thing", "type": {"kind": "OBJECT", "name": "Thing"},
             "args": [{"name": "thingId",
                       "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
        ]},
        # AccessPoint exists only to tempt a "p" containment match, as on EHRI.
        {"name": "AccessPoint", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
        {"name": "Thing", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
        {"name": "Node", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
    ]}}})


def test_opaque_id_tokens_are_not_split_into_meaningless_stems():
    """pid/uuid/guid/oid/did are atomic identifiers, not <entity>Id suffixes."""
    op = OPAQUE_SCHEMA.operations["itemByPid"]
    for arg in ("pid", "uuid", "guid", "oid", "did"):
        assert _candidate_object_name(arg, op) == arg, arg
    # a genuine <entity>Id / <entity>Ids suffix is still split
    assert _candidate_object_name("thingId", op) == "thing"
    assert _candidate_object_name("userIds", op) == "user"


def test_short_candidates_do_not_fuzzy_match_unrelated_types():
    """A 1-char stem must not match a long type by mere containment."""
    assert resolve_object("p", OPAQUE_SCHEMA) is None      # was: "AccessPoint"
    assert resolve_object("pid", OPAQUE_SCHEMA) is None
    assert resolve_object("thing", OPAQUE_SCHEMA) == "Thing"  # good case preserved


def test_opaque_pid_argument_makes_no_spurious_dependency_edge():
    """The regression: itemByPid(pid: ID!) manufactured a hard edge to a random type."""
    graph = build_graph(OPAQUE_SCHEMA)
    into = [e for e in graph.edges if e.target == "itemByPid" and e.kind in ("hard", "soft")]
    assert into == [], "an opaque pid must not invent a producer edge"
    # a well-formed <entity>Id argument still resolves to its object type
    hard = [(e.source, e.target) for e in graph.edges if e.kind == "hard"]
    assert ("Thing", "thing") in hard
    # and the unmatched argument is surfaced honestly, not silently dropped
    assert "pid" in graph.unresolved.get("itemByPid", [])
