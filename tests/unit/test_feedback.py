"""Error feedback: a server naming a missing argument fixes the next attempt."""

from __future__ import annotations

from prediql.generation.bandit import DEFAULT_ARMS
from prediql.generation.feedback import missing_arguments
from prediql.generation.generator import HeuristicGenerator
from prediql.model.bucket import ObjectsBucket
from prediql.model.schema import from_introspection

_STRING = {"kind": "SCALAR", "name": "String"}
SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "ping", "type": _STRING, "args": []}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "createPaste", "type": {"kind": "OBJECT", "name": "Paste"},
             "args": [{"name": "title", "type": _STRING}, {"name": "content", "type": _STRING},
                      {"name": "burn", "type": {"kind": "SCALAR", "name": "Boolean"}}]}]},
        {"name": "Paste", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
    ]}}})
OP = SCHEMA.operations["createPaste"]


def test_python_resolver_message_names_the_arguments():
    errors = [{"message": "CreatePaste.mutate() missing 2 required positional arguments: "
                          "'title' and 'content'"}]
    assert missing_arguments(errors, OP) == {"title", "content"}


def test_graphql_js_message_names_the_argument():
    errors = [{"message": 'Field "createPaste" argument "title" of type "String!" is required, '
                          "but it was not provided."}]
    assert missing_arguments(errors, OP) == {"title"}


def test_only_real_arguments_are_kept():
    """An unrelated name in an error message must never invent an argument."""
    errors = [{"message": "missing 1 required positional argument: 'session'"},
              {"message": "Syntax Error: Unexpected Name \"content\""}]
    assert missing_arguments(errors, OP) == set()


async def test_the_next_attempt_supplies_server_required_arguments():
    gen = HeuristicGenerator()
    arm = DEFAULT_ARMS[0]
    before = await gen.generate(schema=SCHEMA, operation=OP, arm=arm, bucket=ObjectsBucket())
    assert "title" not in before[0].document  # optional in the schema: omitted
    after = await gen.generate(schema=SCHEMA, operation=OP, arm=arm, bucket=ObjectsBucket(),
                               context={"required_args": ["content", "title"]})
    assert "title:" in after[0].document and "content:" in after[0].document
    assert "burn:" not in after[0].document  # still optional, still omitted
