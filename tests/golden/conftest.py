"""Shared fixtures: a small recorded GraphQL API for deterministic runs."""

from __future__ import annotations

import pytest

from prediql.targets.replay import ReplayTarget

COUNTRIES_INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {"name": "Query", "kind": "OBJECT", "fields": [
                    {"name": "continents",
                     "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "Continent"}},
                     "args": []},
                    {"name": "country",
                     "type": {"kind": "OBJECT", "name": "Country"},
                     "args": [{"name": "code",
                               "type": {"kind": "NON_NULL",
                                        "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
                    {"name": "brokenField",
                     "type": {"kind": "OBJECT", "name": "Country"}, "args": []},
                ]},
                {"name": "Mutation", "kind": "OBJECT", "fields": [
                    {"name": "createCountry",
                     "type": {"kind": "OBJECT", "name": "Country"},
                     "args": [{"name": "name",
                               "type": {"kind": "SCALAR", "name": "String"}}]},
                    {"name": "deleteCountry",
                     "type": {"kind": "OBJECT", "name": "Country"},
                     "args": [{"name": "countryId",
                               "type": {"kind": "NON_NULL",
                                        "ofType": {"kind": "SCALAR", "name": "ID"}}}]},
                ]},
                {"name": "Continent", "kind": "OBJECT", "fields": [
                    {"name": "code", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
                    {"name": "name", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
                ]},
                {"name": "Country", "kind": "OBJECT", "fields": [
                    {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []},
                    {"name": "name", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
                ]},
            ],
        }
    }
}

#: Recorded responses keyed by whitespace-normalized document text.
RESPONSES = {
    "query { continents { code } }": {
        "status": 200,
        "body": {"data": {"continents": [{"code": "AF"}, {"code": "EU"}]}},
        "elapsed_ms": 12.0,
    },
    "query { continents { code name } }": {
        "status": 200,
        "body": {"data": {"continents": [{"code": "AF", "name": "Africa"}]}},
        "elapsed_ms": 14.0,
    },
    'query { country(code: "1") { id } }': {
        "status": 200,
        "body": {"data": {"country": {"id": "CA"}}},
        "elapsed_ms": 9.0,
    },
    'query { country(code: "1") { id name } }': {
        "status": 200,
        "body": {"data": {"country": {"id": "CA", "name": "Canada"}}},
        "elapsed_ms": 10.0,
    },
    # brokenField is reachable but always errors -> must NOT count as covered.
    "query { brokenField { id } }": {
        "status": 200,
        "body": {"data": None, "errors": [{"message": "resolver exploded"}]},
        "elapsed_ms": 5.0,
    },
    "query { brokenField { id name } }": {
        "status": 200,
        "body": {"data": None, "errors": [{"message": "resolver exploded"}]},
        "elapsed_ms": 5.0,
    },
    "query { __typename }": {"status": 200, "body": {"data": {"__typename": "Query"}},
                             "elapsed_ms": 2.0},
}

DEFAULT_RESPONSE = {
    "status": 200,
    "body": {"data": None, "errors": [{"message": "unrecognized document"}]},
    "elapsed_ms": 3.0,
}


@pytest.fixture
def replay_target() -> ReplayTarget:
    return ReplayTarget(COUNTRIES_INTROSPECTION, RESPONSES, default=DEFAULT_RESPONSE)
