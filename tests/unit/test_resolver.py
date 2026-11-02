"""Action-label resolver: resolves the heuristic's UNKNOWN subset only."""

from __future__ import annotations

from prediql.generation.resolver import resolve_actions
from prediql.model.graph import Action, build_graph, infer_action
from prediql.model.schema import from_introspection
from prediql.providers.echo import EchoProvider
from prediql.providers.router import Router

# `archivePost` and `sunsetAccount` carry no recognized CRUD verb -> UNKNOWN.
SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "post", "type": {"kind": "OBJECT", "name": "Post"}, "args": []}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "createPost", "type": {"kind": "OBJECT", "name": "Post"}, "args": []},
            {"name": "archivePost", "description": "Soft-deletes a post, hiding it from listings.",
             "type": {"kind": "OBJECT", "name": "Post"},
             "args": [{"name": "postId", "type": {"kind": "SCALAR", "name": "ID"}}]},
            {"name": "sunsetAccount", "description": "Permanently removes a user account.",
             "type": {"kind": "OBJECT", "name": "Account"}, "args": []}]},
        {"name": "Post", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
        {"name": "Account", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
    ]}}})


def _router(labels):
    return Router({"resolver": EchoProvider(responder=lambda r: {"labels": labels})})


def test_heuristic_leaves_verbless_mutations_unknown():
    assert infer_action(SCHEMA.operations["createPost"]) is Action.CREATE
    assert infer_action(SCHEMA.operations["archivePost"]) is Action.UNKNOWN
    assert infer_action(SCHEMA.operations["sunsetAccount"]) is Action.UNKNOWN


async def test_resolver_labels_the_unknown_subset():
    unknown = [SCHEMA.operations["archivePost"], SCHEMA.operations["sunsetAccount"]]
    router = _router([
        {"operation": "archivePost", "action": "DELETE"},
        {"operation": "sunsetAccount", "action": "DELETE"},
    ])
    resolved = await resolve_actions(router, unknown, SCHEMA)
    assert resolved == {"archivePost": Action.DELETE, "sunsetAccount": Action.DELETE}


async def test_resolver_ignores_labels_for_operations_not_asked_about():
    router = _router([{"operation": "somethingElse", "action": "CREATE"}])
    resolved = await resolve_actions(router, [SCHEMA.operations["archivePost"]], SCHEMA)
    assert resolved == {}


async def test_resolver_drops_unknown_and_invalid_actions():
    router = _router([
        {"operation": "archivePost", "action": "UNKNOWN"},   # still ambiguous -> omit
        {"operation": "sunsetAccount", "action": "NONSENSE"},  # invalid -> omit
    ])
    resolved = await resolve_actions(
        router, [SCHEMA.operations["archivePost"], SCHEMA.operations["sunsetAccount"]], SCHEMA)
    assert resolved == {}


async def test_resolver_prompt_includes_description_and_signature():
    seen = {}

    def capture(request):
        seen["prompt"] = request.prompt
        return {"labels": []}

    await resolve_actions(Router({"resolver": EchoProvider(responder=capture)}),
                          [SCHEMA.operations["archivePost"]], SCHEMA)
    assert "archivePost" in seen["prompt"]
    assert "Soft-deletes a post" in seen["prompt"], "the description must reach the model"
    assert "postId: ID" in seen["prompt"], "and the argument signature"


async def test_empty_input_makes_no_call():
    provider = EchoProvider(responder=lambda r: {"labels": []})
    resolved = await resolve_actions(Router({"resolver": provider}), [], SCHEMA)
    assert resolved == {} and provider.calls == []


def test_resolved_delete_label_unlocks_a_uaf_chain():
    """The point of resolving: a corrected DELETE label enables the chain."""
    from prediql.security.chains import synthesize

    graph = build_graph(SCHEMA)
    # Heuristically archivePost is UNKNOWN -> no UAF chain via it.
    before = [c for c in synthesize(graph, SCHEMA, usable_identities=["a"],
                                    allow_destructive=True) if c.strategy == "uaf"]
    assert not any(c for c in before if "archivePost" in c.id)

    # Apply the resolver's DELETE label, and a create->delete->read chain appears.
    graph.actions["archivePost"] = Action.DELETE
    graph.actions["post"] = Action.READ  # the query reads a Post
    # give `post` an id arg so it consumes Post
    schema2 = from_introspection({"data": {"__schema": {
        "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "post", "type": {"kind": "OBJECT", "name": "Post"},
                 "args": [{"name": "postId", "type": {"kind": "SCALAR", "name": "ID"}}]}]},
            {"name": "Mutation", "kind": "OBJECT", "fields": [
                {"name": "createPost", "type": {"kind": "OBJECT", "name": "Post"}, "args": []},
                {"name": "archivePost", "type": {"kind": "OBJECT", "name": "Post"},
                 "args": [{"name": "postId", "type": {"kind": "SCALAR", "name": "ID"}}]}]},
            {"name": "Post", "kind": "OBJECT", "fields": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
        ]}}})
    g2 = build_graph(schema2)
    g2.actions["archivePost"] = Action.DELETE   # the resolver's contribution
    after = [c for c in synthesize(g2, schema2, usable_identities=["a"],
                                   allow_destructive=True) if c.strategy == "uaf"]
    assert any("archivePost" in c.id for c in after), "resolved DELETE label unlocks the UAF chain"
