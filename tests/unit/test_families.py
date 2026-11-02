"""Probe families: applicability, payload construction, refinement, isolation."""

from __future__ import annotations

from graphql import parse

from prediql.model.graph import build_graph
from prediql.model.schema import from_introspection
from prediql.oracle.evidence import Evidence
from prediql.security.families.base import Observation
from prediql.security.registry import build_families
from prediql.security.families.sqli import SqlInjectionFamily
from prediql.security.families.oscmd import OsCommandInjectionFamily
from prediql.security.families.path_traversal import PathTraversalFamily
from prediql.security.families.introspection import IntrospectionFamily

SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "search", "type": {"kind": "OBJECT", "name": "Post"},
             "args": [{"name": "q", "type": {"kind": "NON_NULL",
                                             "ofType": {"kind": "SCALAR", "name": "String"}}}]},
            {"name": "readFile", "type": {"kind": "SCALAR", "name": "String"},
             "args": [{"name": "path", "type": {"kind": "SCALAR", "name": "String"}}]},
            # No injectable argument -> injection families must skip it.
            {"name": "allPosts", "type": {"kind": "LIST",
                                          "ofType": {"kind": "OBJECT", "name": "Post"}}, "args": []},
        ]},
        {"name": "Post", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []},
            {"name": "title", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
    ]}}})
GRAPH = build_graph(SCHEMA)


def _op(name):
    return SCHEMA.operations[name]


# --------------------------------------------------------------------------
# Applicability — most families skip most operations
# --------------------------------------------------------------------------


def test_injection_family_applies_only_to_operations_with_injectable_args():
    sqli = SqlInjectionFamily()
    assert sqli.applies(_op("search"), SCHEMA, GRAPH)
    assert sqli.applies(_op("readFile"), SCHEMA, GRAPH)
    assert not sqli.applies(_op("allPosts"), SCHEMA, GRAPH), "no args -> nothing to inject"


def test_introspection_family_probes_once_not_per_operation():
    fam = IntrospectionFamily()
    applied = [name for name in SCHEMA.operations if fam.applies(_op(name), SCHEMA, GRAPH)]
    assert len(applied) == 1, "a schema-level probe must not fire per operation"


# --------------------------------------------------------------------------
# Payload construction — always valid GraphQL, injected in one argument
# --------------------------------------------------------------------------


def test_every_seed_payload_is_valid_graphql():
    for family in build_families():
        for name in SCHEMA.operations:
            op = _op(name)
            if not family.applies(op, SCHEMA, GRAPH):
                continue
            for payload in family.seed_payloads(op, SCHEMA):
                parse(payload.document)  # raises if malformed


def test_sqli_injects_the_breaker_into_the_argument():
    payloads = SqlInjectionFamily().seed_payloads(_op("search"), SCHEMA)
    documents = [p.document for p in payloads]
    assert any("'" in d and "search(q:" in d for d in documents)
    assert all(p.class_id == "sql_injection" for p in payloads)


def test_oscmd_sentinel_is_the_product_not_present_in_the_payload():
    """Reflection of the payload cannot fake the computed sentinel."""
    payloads = OsCommandInjectionFamily().seed_payloads(_op("search"), SCHEMA)
    for payload in payloads:
        sentinel = payload.expectation.sentinel
        assert sentinel and sentinel not in payload.document, \
            "the confirming value must not appear in the payload text"


def test_path_traversal_confirms_on_file_content():
    payloads = PathTraversalFamily().seed_payloads(_op("readFile"), SCHEMA)
    assert payloads
    for payload in payloads:
        assert payload.expectation.sentinel == "root:x:0:0"
        assert payload.expectation.evidence is Evidence.SENTINEL
        # The path is the reflection marker, never the confirmation.
        assert "passwd" in payload.expectation.marker


def test_path_traversal_prioritizes_path_like_arguments():
    payloads = PathTraversalFamily().seed_payloads(_op("readFile"), SCHEMA)
    assert payloads[0].argument == "path"


# --------------------------------------------------------------------------
# Refinement — evidence-directed escalation
# --------------------------------------------------------------------------


def test_sqli_escalates_to_time_based_only_where_an_error_showed():
    family = SqlInjectionFamily()
    seed = family.seed_payloads(_op("search"), SCHEMA)[0]

    # No error observed -> no escalation.
    quiet = [Observation(seed, "nothing", None, "", 10.0, True)]
    assert family.refine(_op("search"), SCHEMA, quiet) == []

    # A DB error on that argument -> time-based follow-ups appear.
    errored = [Observation(seed, "signal", Evidence.ERROR_SIGNATURE, "db error", 10.0, True)]
    followups = family.refine(_op("search"), SCHEMA, errored)
    assert followups
    assert all(p.expectation.evidence is Evidence.LATENCY for p in followups)
    assert all("sleep" in p.document.lower() or "pg_sleep" in p.document.lower()
               for p in followups)


# --------------------------------------------------------------------------
# Isolation — a family produces exactly its own class (the ablation guarantee)
# --------------------------------------------------------------------------


def test_each_family_emits_only_its_own_class():
    for family in build_families():
        for name in SCHEMA.operations:
            op = _op(name)
            if not family.applies(op, SCHEMA, GRAPH):
                continue
            for payload in family.seed_payloads(op, SCHEMA):
                # introspection family emits a paired field_suggestion probe.
                assert payload.class_id in (family.id, "field_suggestion")


# --------------------------------------------------------------------------
# Authenticated-scan credentials — auth_args fill a gated required argument
# --------------------------------------------------------------------------

_GATED = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "diagnostics", "type": {"kind": "SCALAR", "name": "String"}, "args": [
                {"name": "username", "type": {"kind": "NON_NULL",
                                              "ofType": {"kind": "SCALAR", "name": "String"}}},
                {"name": "password", "type": {"kind": "NON_NULL",
                                              "ofType": {"kind": "SCALAR", "name": "String"}}},
                {"name": "cmd", "type": {"kind": "NON_NULL",
                                         "ofType": {"kind": "SCALAR", "name": "String"}}},
            ]},
        ]},
    ]}}})


def test_auth_args_fill_gated_required_arguments_in_every_payload():
    creds = {"username": "admin", "password": "changeme"}
    [fam] = build_families(("os_command_injection",), auth_args=creds)
    payloads = fam.seed_payloads(_GATED.operations["diagnostics"], _GATED)
    assert payloads, "expected OS-command payloads on the cmd argument"
    cmd_payloads = [p for p in payloads if p.argument == "cmd"]
    assert cmd_payloads, "the injectable arg should be cmd, not a credential field"
    for p in cmd_payloads:
        # credentials supplied verbatim so the resolver gate opens...
        assert 'username: "admin"' in p.document
        assert 'password: "changeme"' in p.document
        # ...while the payload is injected only into cmd.
        assert "91273" in p.document or "curl" in p.document


def test_auth_args_absent_by_default_leaves_behaviour_unchanged():
    [fam] = build_families(("os_command_injection",))
    assert fam.auth_args == {}
    payloads = fam.seed_payloads(_GATED.operations["diagnostics"], _GATED)
    # Without creds the gate fields get generic defaults, not the real values.
    assert all('password: "changeme"' not in p.document for p in payloads)
