"""LLM generator: structured parsing, validation, metering, fallback."""

from __future__ import annotations

from prediql.engine.budget import BudgetLedger
from prediql.generation.bandit import Arm
from prediql.generation.llm_generator import LLMGenerator
from prediql.model.bucket import ObjectsBucket
from prediql.model.schema import from_introspection
from prediql.providers.echo import EchoProvider
from prediql.providers.router import Router

SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "continents", "type": {"kind": "LIST",
                                            "ofType": {"kind": "OBJECT", "name": "Continent"}},
             "args": []}]},
        {"name": "Continent", "kind": "OBJECT", "fields": [
            {"name": "code", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
    ]}}})
OP = SCHEMA.operations["continents"]
ARM = Arm("t", n_candidates=2)


def _router(responder, ledger=None):
    return Router({"generator": EchoProvider(responder=responder)}, ledger=ledger)


async def test_parses_valid_documents_from_structured_output():
    router = _router(lambda r: {"documents": [
        {"query": "query { continents { code } }", "rationale": "minimal"},
        {"query": "query { continents { code name } }"},
    ]})
    candidates = await LLMGenerator(router).generate(
        schema=SCHEMA, operation=OP, arm=ARM, bucket=ObjectsBucket())
    assert len(candidates) == 2
    assert all(c.source == "llm" for c in candidates)
    assert candidates[0].rationale == "minimal"


async def test_invalid_graphql_is_dropped():
    router = _router(lambda r: {"documents": [
        {"query": "query { continents { code } }"},
        {"query": "this is not ) valid graphql"},
    ]})
    candidates = await LLMGenerator(router).generate(
        schema=SCHEMA, operation=OP, arm=ARM, bucket=ObjectsBucket())
    assert len(candidates) == 1, "the malformed document must be dropped"


async def test_duplicate_documents_are_deduped():
    router = _router(lambda r: {"documents": [
        {"query": "query { continents { code } }"},
        {"query": "query { continents { code } }"},
    ]})
    candidates = await LLMGenerator(router).generate(
        schema=SCHEMA, operation=OP, arm=ARM, bucket=ObjectsBucket())
    assert len(candidates) == 1


async def test_empty_output_falls_back_to_the_heuristic_builder():
    """A dead LLM round must not waste the round."""
    router = _router(lambda r: {"documents": []})
    candidates = await LLMGenerator(router).generate(
        schema=SCHEMA, operation=OP, arm=ARM, bucket=ObjectsBucket())
    assert candidates, "fallback should have produced a valid candidate"
    assert candidates[0].source == "heuristic"


async def test_generation_is_metered_into_the_ledger():
    ledger = BudgetLedger(max_tokens=100_000)
    router = _router(lambda r: {"documents": [{"query": "query { continents { code } }"}]},
                     ledger=ledger)
    await LLMGenerator(router).generate(
        schema=SCHEMA, operation=OP, arm=ARM, bucket=ObjectsBucket())
    snap = ledger.snapshot()
    assert snap["total"]["calls"] == 1
    assert "cover" in snap["by_step"], "generation is attributed to the cover step"


async def test_prompt_places_the_schema_slice_in_the_cacheable_prefix():
    """Stable content first, so a vendor prefix cache can hit across rounds."""
    seen = {}

    def capture(request):
        seen["prefix"] = request.prefix
        seen["system"] = request.system
        return {"documents": [{"query": "query { continents { code } }"}]}

    await LLMGenerator(_router(capture)).generate(
        schema=SCHEMA, operation=OP, arm=ARM, bucket=ObjectsBucket())
    assert "operation: continents" in seen["prefix"]
    assert "type Continent" in seen["prefix"]
    assert "fuzzer" in seen["system"].lower()


async def test_schema_slice_expands_nested_types_to_depth():
    """The gap the fix closes: a deep selection needs the nested type's fields."""
    from prediql.generation.bandit import Arm

    schema = from_introspection({"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "continents", "type": {"kind": "LIST",
                    "ofType": {"kind": "OBJECT", "name": "Continent"}}, "args": []}]},
            {"name": "Continent", "kind": "OBJECT", "fields": [
                {"name": "code", "type": {"kind": "SCALAR", "name": "ID"}, "args": []},
                {"name": "countries", "type": {"kind": "LIST",
                    "ofType": {"kind": "OBJECT", "name": "Country"}}, "args": []}]},
            {"name": "Country", "kind": "OBJECT", "fields": [
                {"name": "capital", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
        ]}}})
    gen = LLMGenerator(Router({"generator": EchoProvider()}))
    op = schema.operations["continents"]

    deep = gen._schema_slice(schema, op, Arm("deep", depth=2, n_candidates=1))
    assert "type Continent" in deep and "type Country" in deep, "depth-2 shows the nested type"
    assert "capital" in deep, "the model can now select Country.capital"

    shallow = gen._schema_slice(schema, op, Arm("shallow", depth=1, n_candidates=1))
    assert "type Country" not in shallow, "depth-1 does not over-share nested types"


async def test_schema_slice_terminates_on_a_cyclic_schema():
    from prediql.generation.bandit import Arm

    schema = from_introspection({"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "node", "type": {"kind": "OBJECT", "name": "Node"}, "args": []}]},
            {"name": "Node", "kind": "OBJECT", "fields": [
                {"name": "child", "type": {"kind": "OBJECT", "name": "Node"}, "args": []}]},
        ]}}})
    gen = LLMGenerator(Router({"generator": EchoProvider()}))
    slice_ = gen._schema_slice(schema, schema.operations["node"], Arm("t", depth=5, n_candidates=1))
    assert slice_.count("type Node") == 1, "a cyclic type is emitted once, not infinitely"


async def test_minimal_prompt_is_the_instruction_alone_and_never_falls_back():
    """+Base measures the bare LLM: no seed, feedback, directives, or rescue."""
    seen = {}

    def capture(request):
        seen["prompt"] = request.prompt
        return {"documents": []}

    candidates = await LLMGenerator(_router(capture)).generate(
        schema=SCHEMA, operation=OP, arm=ARM, bucket=ObjectsBucket(),
        context={"minimal_prompt": True, "required_args": ["code"], "round": 2})
    assert candidates == [], "an empty minimal round is not rescued by the heuristic builder"
    assert seen["prompt"].startswith("Generate")
    for leaked in ("minimal valid selection", "rejected", "round", "Real values"):
        assert leaked not in seen["prompt"]
