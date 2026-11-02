"""SSRF against a resolver that builds its URL from separate scheme/host parts."""

from __future__ import annotations

from prediql.security.families.ssrf import SsrfFamily, _split_url_args
from prediql.model.schema import from_introspection

_S = {"kind": "SCALAR", "name": "String"}
_I = {"kind": "SCALAR", "name": "Int"}
SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "ping", "type": _S, "args": []}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "importPaste", "type": _S, "args": [
                {"name": "host", "type": {"kind": "NON_NULL", "ofType": _S}},
                {"name": "port", "type": _I},
                {"name": "path", "type": {"kind": "NON_NULL", "ofType": _S}},
                {"name": "scheme", "type": {"kind": "NON_NULL", "ofType": _S}}]}]},
    ]}}})
OP = SCHEMA.operations["importPaste"]


class _FakeOOB:
    def new_token(self): return "pqloobTОKEN".replace("О", "O")
    def url_for(self, t): return f"http://host.docker.internal:9/{t}"
    def parts_for(self, t):
        return {"scheme": "http", "host": "host.docker.internal", "port": 9, "path": f"/{t}"}


def test_split_url_arguments_are_detected():
    assert _split_url_args(OP, SCHEMA) == {
        "host": "host", "scheme": "scheme", "path": "path", "port": "port"}


def test_split_url_payload_points_every_part_at_the_collaborator():
    family = SsrfFamily()
    family.oob = _FakeOOB()
    docs = [p.document for p in family.seed_payloads(OP, SCHEMA)]
    split = next(d for d in docs if 'scheme: "http"' in d)
    assert 'host: "host.docker.internal"' in split
    assert "port: 9" in split
    assert "/pqloob" in split  # the token is in the path, as one reachable URL
    assert 'scheme: "http"' in split and split.count("http://") <= 1
