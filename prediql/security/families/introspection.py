"""Introspection / field-suggestion exposure.

A configuration probe, not an injection: it applies once per target (not per
operation) and confirms differentially — introspection returning a schema, or
the server offering a "did you mean" field suggestion, when a hardened endpoint
would refuse. Low severity, but a real information-disclosure signal.
"""

from __future__ import annotations

from prediql.oracle.evidence import Evidence, Expectation
from prediql.security.families.base import Observation, Payload, ProbeFamily
from prediql.model.schema import Operation, Schema

_INTROSPECTION = "query { __schema { queryType { name } } }"
_SUGGESTION = "query { __thisFieldDoesNotExist }"


class IntrospectionFamily(ProbeFamily):
    id = "introspection_enabled"
    max_rounds = 1

    def applies(self, operation, schema, graph) -> bool:
        # Schema-level, so probe exactly one representative operation and skip
        # the rest — otherwise the same finding is raised N times.
        first = next(iter(schema.operations.values()), None)
        return first is not None and operation.name == first.name

    def seed_payloads(self, operation: Operation, schema: Schema) -> list[Payload]:
        return [
            Payload("__schema", _INTROSPECTION,
                    Expectation(self.id, Evidence.DIFFERENTIAL, stage="introspection")),
            Payload("__schema", _SUGGESTION,
                    Expectation("field_suggestion", Evidence.DIFFERENTIAL, stage="suggestion")),
        ]
