"""Coverage-metric tests.

The headline claim in the paper rests on this metric, so these tests pin the
construct: a field counts only when the server *returned* it, aliases and
fragments resolve to real schema fields, and the denominator is depth-bounded.
The first test is the v1 defect, encoded as a regression guard.
"""

from __future__ import annotations

from prediql.model.coverage import (
    CoverageState,
    covered_paths,
    reachable_paths,
    selection_paths,
)
from prediql.model.schema import from_introspection

# --------------------------------------------------------------------------
# selection_paths — a real parser, not a regex
# --------------------------------------------------------------------------


def test_simple_nested_selection():
    doc = "{ continents { code countries { name } } }"
    assert selection_paths(doc) == {
        "continents",
        "continents.code",
        "continents.countries",
        "continents.countries.name",
    }


def test_alias_resolves_to_the_underlying_field():
    """`a: name` covers the schema field `name`, not a phantom field `a`."""
    assert selection_paths("{ country { a: name } }") == {"country", "country.name"}


def test_named_fragment_is_expanded_at_its_spread_site():
    doc = """
    { country { ...CountryBits } }
    fragment CountryBits on Country { name capital }
    """
    assert selection_paths(doc) == {"country", "country.name", "country.capital"}


def test_inline_fragment_contributes_to_the_enclosing_path():
    doc = "{ search { ... on Country { name } } }"
    assert selection_paths(doc) == {"search", "search.name"}


def test_cyclic_fragment_terminates():
    doc = """
    { a { ...F } }
    fragment F on A { b ...F }
    """
    assert selection_paths(doc) == {"a", "a.b"}


def test_unparseable_document_is_a_non_event():
    assert selection_paths("{ this is not ) valid") == set()
    assert selection_paths("") == set()


# --------------------------------------------------------------------------
# covered_paths — the v1 fix
# --------------------------------------------------------------------------


def test_requested_but_null_field_is_not_covered():
    """The v1 defect: v1 counted this field because the *query* named it."""
    doc = "{ country { name capital } }"
    data = {"country": {"name": "Canada", "capital": None}}
    covered = covered_paths(doc, data)
    assert "country.name" in covered
    assert "country.capital" not in covered, "a null field must not count as covered"


def test_empty_or_errored_response_covers_nothing():
    doc = "{ country { name } }"
    assert covered_paths(doc, None) == set()
    assert covered_paths(doc, {}) == set()
    assert covered_paths(doc, {"country": None}) == set()


def test_list_response_covers_fields_present_on_any_element():
    doc = "{ continents { code name } }"
    data = {"continents": [{"code": "AF", "name": None}, {"code": "EU", "name": "Europe"}]}
    covered = covered_paths(doc, data)
    assert covered == {"continents", "continents.code", "continents.name"}


def test_empty_list_does_not_cover_its_children():
    doc = "{ continents { code } }"
    assert covered_paths(doc, {"continents": []}) == set()


def test_aliased_response_key_maps_back_to_the_field():
    doc = "{ country { a: name } }"
    data = {"country": {"a": "Canada"}}  # response is keyed by the alias
    assert covered_paths(doc, data) == {"country", "country.name"}


def test_covered_never_exceeds_requested():
    """A server returning extra keys cannot inflate coverage."""
    doc = "{ country { name } }"
    data = {"country": {"name": "Canada", "surprise": "extra"}}
    assert covered_paths(doc, data) == {"country", "country.name"}


# --------------------------------------------------------------------------
# Denominator and aggregate metrics
# --------------------------------------------------------------------------

INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": None,
            "types": [
                {"name": "Query", "kind": "OBJECT", "fields": [
                    {"name": "continents",
                     "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "Continent"}},
                     "args": []},
                    {"name": "country",
                     "type": {"kind": "OBJECT", "name": "Country"}, "args": []},
                ]},
                {"name": "Continent", "kind": "OBJECT", "fields": [
                    {"name": "code", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
                ]},
                {"name": "Country", "kind": "OBJECT", "fields": [
                    {"name": "name", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
                ]},
            ],
        }
    }
}


def test_reachable_paths_respect_the_depth_bound():
    schema = from_introspection(INTROSPECTION)
    shallow = reachable_paths(schema, depth=1)
    assert shallow == {"continents", "continents.code", "country", "country.name"}
    # Depth 0 admits only the operations themselves.
    assert reachable_paths(schema, depth=0) == {"continents", "country"}


def test_cyclic_schema_terminates_at_depth():
    cyclic = {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "types": [
            {"name": "Query", "kind": "OBJECT", "fields": [
                {"name": "node", "type": {"kind": "OBJECT", "name": "Node"}, "args": []}]},
            {"name": "Node", "kind": "OBJECT", "fields": [
                {"name": "child", "type": {"kind": "OBJECT", "name": "Node"}, "args": []}]},
        ]}}}
    schema = from_introspection(cyclic)
    paths = reachable_paths(schema, depth=3)
    assert "node.child.child.child" in paths
    assert "node.child.child.child.child" not in paths, "must unroll to exactly D"


def test_state_reports_both_metrics_and_delta():
    schema = from_introspection(INTROSPECTION)
    state = CoverageState(depth=1)

    delta = state.observe("continents", "{ continents { code } }",
                          {"continents": [{"code": "AF"}]})
    assert delta == 2, "continents + continents.code are new"

    # Re-observing the same response yields no new coverage -> reward 0.
    assert state.observe("continents", "{ continents { code } }",
                         {"continents": [{"code": "AF"}]}) == 0

    state.observe("country", "{ country { name } }", {"country": {"name": "Canada"}})
    report = state.report(schema)
    assert report["operations_covered"] == 2
    assert report["operations_total"] == 2
    assert report["operation_coverage"] == 1.0
    assert report["field_paths_covered"] == 4
    assert report["field_path_coverage"] == 1.0
    assert report["element_coverage"] == 1.0
    assert report["depth"] == 1


def test_state_round_trips_through_the_artifact_store():
    state = CoverageState(depth=3)
    state.observe("country", "{ country { name } }", {"country": {"name": "X"}})
    restored = CoverageState.from_dict(state.to_dict())
    assert restored.depth == 3
    assert restored.all_paths() == state.all_paths()


# --------------------------------------------------------------------------
# Denominator scalability — the counter must agree with the enumerator,
# and must not materialise the set on a large schema.
# --------------------------------------------------------------------------


def _synthetic_schema(n_types: int, fan_out: int, n_ops: int):
    """A cyclic schema with a controllable fan-out."""
    types = [{"name": "Query", "kind": "OBJECT", "fields": [
        {"name": f"op{i}", "type": {"kind": "OBJECT", "name": f"T{i % n_types}"}, "args": []}
        for i in range(n_ops)]}]
    for i in range(n_types):
        fields = [{"name": f"s{j}", "type": {"kind": "SCALAR", "name": "String"}, "args": []}
                  for j in range(2)]
        fields += [{"name": f"r{j}",
                    "type": {"kind": "OBJECT", "name": f"T{(i + j + 1) % n_types}"}, "args": []}
                   for j in range(fan_out)]
        types.append({"name": f"T{i}", "kind": "OBJECT", "fields": fields})
    return from_introspection({"data": {"__schema": {"queryType": {"name": "Query"},
                                                     "types": types}}})


def test_counter_agrees_with_the_enumerator_on_small_schemas():
    """One definition, two implementations — they must not drift."""
    from prediql.model.coverage import count_reachable_paths

    for schema in (from_introspection(INTROSPECTION), _synthetic_schema(5, 2, 3)):
        for depth in (0, 1, 2, 3):
            assert count_reachable_paths(schema, depth=depth) == len(
                reachable_paths(schema, depth=depth)
            ), f"disagreement at depth {depth}"


def test_denominator_is_computable_at_production_scale():
    """PokeAPI-scale: enumerating this set is tens of millions of strings."""
    import time

    from prediql.model.coverage import count_reachable_paths

    schema = _synthetic_schema(n_types=200, fan_out=10, n_ops=460)
    started = time.perf_counter()
    total = count_reachable_paths(schema, depth=5)
    elapsed = time.perf_counter() - started

    assert total > 10_000_000, "the set really is that large; that is the point"
    assert elapsed < 2.0, f"counting must stay fast, took {elapsed:.2f}s"


def test_membership_test_avoids_building_the_denominator():
    from prediql.model.coverage import is_reachable_path

    schema = _synthetic_schema(n_types=200, fan_out=10, n_ops=460)
    assert is_reachable_path(schema, "op0.r0.r1.s0", depth=5)
    assert not is_reachable_path(schema, "op0.r0.r1.nope", depth=5)
    assert not is_reachable_path(schema, "op0.r0.r1.r2.r3.r4.s0", depth=5), "beyond depth"
    assert not is_reachable_path(schema, "nosuchop", depth=5)


def test_field_coverage_is_reported_on_a_large_schema():
    """The metric must produce a number rather than exhaust memory."""
    schema = _synthetic_schema(n_types=200, fan_out=10, n_ops=460)
    state = CoverageState(depth=5)
    state.observe("op0", "{ op0 { s0 } }", {"op0": {"s0": "x"}})
    report = state.report(schema)
    assert report["field_paths_covered"] == 2
    assert report["field_paths_reachable"] > 10_000_000
    # The path ratio is meaninglessly small at this scale; element coverage is
    # the number to quote, and it stays interpretable.
    assert report["field_path_coverage"] < 1e-6
    assert report["elements_total"] < 3_000, "element denominator is linear, not combinatorial"
    assert report["elements_covered"] == 2
    assert report["element_coverage"] > 0.0
