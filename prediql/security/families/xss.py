"""Reflected cross-site scripting family.

In a JSON API, verbatim reflection of a script marker is a *signal*, not a
confirmation — the browser context that would make it executable is not
observable here. So this family confirms nothing on its own; it raises a
``potential`` finding on reflection, and the stored/second-order case (inject on
a write, observe on a chained read) is confirmed by the chain layer in M4.
"""

from __future__ import annotations

from prediql.oracle.evidence import Evidence, Expectation
from prediql.security.families.base import (
    Payload,
    ProbeFamily,
    injectable_arguments,
    unique_token,
)
from prediql.model.schema import Operation, Schema


class ReflectedXssFamily(ProbeFamily):
    id = "xss_reflected"

    def seed_payloads(self, operation: Operation, schema: Schema) -> list[Payload]:
        payloads: list[Payload] = []
        for argument in self.injectable(operation, schema):
            token = unique_token()
            # Distinct HTML/JS breakouts sharing one detectable token, so a
            # single reflected marker attributes back to this probe.
            for value in (f"<script>{token}</script>",
                          f"\"><img src=x onerror={token}>",
                          f"';{token}//"):
                payloads.append(self._inject(
                    operation, schema, argument, value,
                    Expectation(self.id, Evidence.REFLECTION, marker=token, stage="reflect"),
                ))
        return payloads
