"""Path traversal family.

Confirmation is **file content**, not path reflection — the exact distinction
GraphQLer's detector misses (doc 09 §4). The sentinel is a stable substring of a
well-known file (``root:x:0:0`` from ``/etc/passwd``); its presence can only come
from the file actually being read. The traversal string is the reflection marker.
"""

from __future__ import annotations

from prediql.oracle.evidence import Evidence, Expectation
from prediql.security.families.base import (
    Payload,
    ProbeFamily,
    injectable_arguments,
)
from prediql.model.schema import Operation, Schema

# A path-ish argument name raises this family's priority but is not required —
# many file reads take a generic ``name``/``id``.
_PATH_HINTS = ("path", "file", "name", "dir", "folder", "template", "page", "doc")

_SENTINEL = "root:x:0:0"
_TRAVERSALS = (
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\etc\\passwd",
    "/etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
)


class PathTraversalFamily(ProbeFamily):
    id = "path_traversal"

    def applies(self, operation, schema, graph) -> bool:
        return bool(self.injectable(operation, schema))

    def seed_payloads(self, operation: Operation, schema: Schema) -> list[Payload]:
        arguments = self.injectable(operation, schema)
        # Probe the most path-likely argument first, but do not exclude others.
        arguments.sort(key=lambda a: (not any(h in a.lower() for h in _PATH_HINTS), a))
        payloads: list[Payload] = []
        for argument in arguments:
            for traversal in _TRAVERSALS:
                payloads.append(self._inject(
                    operation, schema, argument, traversal,
                    Expectation(self.id, Evidence.SENTINEL, sentinel=_SENTINEL,
                                marker=traversal, stage="traversal"),
                ))
        return payloads
