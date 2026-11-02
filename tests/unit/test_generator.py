"""Candidate generation: argument resolution and type-correct placeholders.

Each test here corresponds to a defect found by running against a live API,
where operation coverage went 3/6 -> 4/6 -> 6/6 as they were fixed.
"""

from __future__ import annotations

import pytest
from graphql import parse

from prediql.generation.bandit import Arm
from prediql.generation.generator import HeuristicGenerator
from prediql.model.bucket import ObjectsBucket
from prediql.model.schema import from_introspection

SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            # Natural-key lookup: `code` is a field of the *return* type.
            {"name": "continent", "type": {"kind": "OBJECT", "name": "Continent"},
             "args": [{"name": "code", "type": {"kind": "NON_NULL",
                                                "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
            # Optional INPUT_OBJECT argument: unfillable by a placeholder.
            {"name": "continents",
             "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "Continent"}},
             "args": [{"name": "filter",
                       "type": {"kind": "INPUT_OBJECT", "name": "ContinentFilterInput"}}]},
            # Classic ID reference: `userId` -> User.
            {"name": "user", "type": {"kind": "OBJECT", "name": "User"},
             "args": [{"name": "userId", "type": {"kind": "NON_NULL",
                                                  "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
        ]},
        {"name": "Continent", "kind": "OBJECT", "fields": [
            {"name": "code", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
            {"name": "name", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
        {"name": "User", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
        {"name": "ContinentFilterInput", "kind": "INPUT_OBJECT", "fields": []},
    ]}}})

ARM = Arm("t", include_schema=True, arg_mode="known", depth=1, top_k=0, n_candidates=1)
ARM_REAL = Arm("t_real", arg_mode="real", depth=1, top_k=0, n_candidates=1)


async def _document(operation: str, bucket: ObjectsBucket, arm: Arm = ARM) -> str:
    candidates = await HeuristicGenerator().generate(
        schema=SCHEMA, operation=SCHEMA.operations[operation], arm=arm, bucket=bucket
    )
    assert candidates, f"no candidate generated for {operation}"
    return candidates[0].document


@pytest.fixture
def stocked_bucket() -> ObjectsBucket:
    bucket = ObjectsBucket()
    bucket.harvest({"continents": [{"code": "AF", "name": "Africa"}]},
                   operation="continents", identity="anon",
                   schema=SCHEMA, root_type="Continent")
    bucket.harvest({"user": {"id": "u-1"}}, operation="user", identity="anon",
                   schema=SCHEMA, root_type="User")
    return bucket


async def test_natural_key_argument_uses_an_observed_value(stocked_bucket):
    """`continent(code:)` must reuse a real code seen from `continents`.

    Without this rule every lookup-by-natural-key operation is unreachable —
    GraphQLer's documented "scalar materialization" gap.
    """
    assert 'continent(code: "AF")' in await _document("continent", stocked_bucket)


async def test_exact_return_type_rule_beats_the_fuzzy_name_match(stocked_bucket):
    """`code` is within edit distance of other type names; exact must win."""
    document = await _document("continent", stocked_bucket)
    assert '"AF"' in document, document
    assert '"u-1"' not in document, "must not borrow an unrelated object's id"


async def test_id_suffixed_argument_resolves_to_its_object(stocked_bucket):
    assert 'user(userId: "u-1")' in await _document("user", stocked_bucket)


async def test_optional_argument_without_an_observed_value_is_omitted():
    """A placeholder buys nothing in an optional slot and risks rejection.

    The concrete defect this guards: a scalar placeholder handed to an
    INPUT_OBJECT argument (`filter: "test"`) is always a type error and fails
    the whole document.
    """
    for arm in (ARM, ARM_REAL):
        document = await _document("continents", ObjectsBucket(), arm=arm)
        assert "filter" not in document, document
        assert document.startswith("query { continents {")


async def test_required_argument_still_attempted_when_unfillable():
    """An empty bucket must not silently drop a required argument."""
    document = await _document("continent", ObjectsBucket())
    assert "continent(code:" in document


async def test_every_generated_document_is_valid_graphql(stocked_bucket):
    for arm in (ARM, ARM_REAL, Arm("nulls", arg_mode="nulls", n_candidates=2)):
        for name in SCHEMA.operations:
            candidates = await HeuristicGenerator().generate(
                schema=SCHEMA, operation=SCHEMA.operations[name],
                arm=arm, bucket=stocked_bucket,
            )
            for candidate in candidates:
                parse(candidate.document)  # raises if malformed


async def test_batched_arm_returns_multiple_candidates(stocked_bucket):
    """v1 hardcoded one candidate per call; a batching arm must return more."""
    candidates = await HeuristicGenerator().generate(
        schema=SCHEMA, operation=SCHEMA.operations["continents"],
        arm=Arm("batch", n_candidates=2, depth=1), bucket=stocked_bucket,
    )
    assert len(candidates) == 2
    assert candidates[0].document != candidates[1].document


# --------------------------------------------------------------------------
# Input objects — required arguments must be constructible
# --------------------------------------------------------------------------

MUTATION_SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "ping", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "createPaste", "type": {"kind": "OBJECT", "name": "Paste"},
             "args": [{"name": "input", "type": {"kind": "NON_NULL", "ofType": {
                 "kind": "INPUT_OBJECT", "name": "PasteInput"}}}]},
            {"name": "setMode", "type": {"kind": "OBJECT", "name": "Paste"},
             "args": [{"name": "mode", "type": {"kind": "NON_NULL", "ofType": {
                 "kind": "ENUM", "name": "Mode"}}}]},
        ]},
        {"name": "Paste", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
        {"name": "PasteInput", "kind": "INPUT_OBJECT", "inputFields": [
            {"name": "content", "type": {"kind": "NON_NULL",
                                         "ofType": {"kind": "SCALAR", "name": "String"}}},
            {"name": "title", "type": {"kind": "SCALAR", "name": "String"}}]},
        {"name": "Mode", "kind": "ENUM", "fields": [], "enumValues": [{"name": "PUBLIC"}]},
    ]}}})


def test_input_object_members_are_read_from_the_schema():
    """Without inputFields, every input-object mutation is unreachable."""
    paste_input = MUTATION_SCHEMA.type("PasteInput")
    assert paste_input.is_input
    assert [f.name for f in paste_input.fields] == ["content", "title"]
    assert [f.name for f in paste_input.required_fields] == ["content"]


async def test_required_input_object_is_built_with_its_required_members():
    candidates = await HeuristicGenerator().generate(
        schema=MUTATION_SCHEMA, operation=MUTATION_SCHEMA.operations["createPaste"],
        arm=ARM, bucket=ObjectsBucket(),
    )
    document = candidates[0].document
    parse(document)
    assert "input: {content:" in document, document
    assert "title" not in document, "optional members stay out of a minimal payload"


async def test_required_enum_argument_uses_an_unquoted_member():
    candidates = await HeuristicGenerator().generate(
        schema=MUTATION_SCHEMA, operation=MUTATION_SCHEMA.operations["setMode"],
        arm=ARM, bucket=ObjectsBucket(),
    )
    document = candidates[0].document
    parse(document)
    assert "mode: PUBLIC" in document, document
    assert '"PUBLIC"' not in document, "enum members are not strings"
