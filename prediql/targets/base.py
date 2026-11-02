"""GraphQL target adapter interface and the success oracle.

The adapter is the transport to a GraphQL endpoint. Everything above it —
coverage, the bandit, probe families — works against :class:`HttpResult`, so the
live HTTP adapter and the in-memory replay adapter (used for deterministic tests)
are interchangeable. The seam is about *transport*, not about supporting a
different API style: PrediQL is a GraphQL fuzzer.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from prediql.engine.config import Identity


@dataclass(frozen=True, slots=True)
class HttpResult:
    """One request/response exchange with the target."""

    document: str
    identity: str
    status: int
    body: dict[str, Any] | None = None
    elapsed_ms: float = 0.0
    error: str | None = None
    variables: dict[str, Any] = field(default_factory=dict)

    @property
    def data(self) -> dict[str, Any] | None:
        return (self.body or {}).get("data")

    @property
    def errors(self) -> list[dict[str, Any]]:
        return list((self.body or {}).get("errors") or [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "document": self.document,
            "identity": self.identity,
            "status": self.status,
            "body": self.body,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "error": self.error,
            "variables": self.variables,
        }


def has_real_data(data: Any) -> bool:
    """True when a ``data`` payload carries at least one genuine value.

    Ported from v1's ``is_successful_graphql_response``: a response of
    ``{"data": {"x": null}}`` or ``{"data": {"x": []}}`` is *not* a success, since
    nothing was actually returned.
    """
    if not isinstance(data, dict) or not data:
        return False
    for value in data.values():
        if value is None:
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    if any(v is not None for v in item.values()):
                        return True
                elif item is not None:
                    return True
            continue
        if isinstance(value, dict):
            if any(v is not None for v in value.values()):
                return True
            continue
        return True  # non-null scalar
    return False


def is_success(result: HttpResult) -> bool:
    """The success definition the coverage metric and bandit reward share.

    HTTP 200 **and** no ``errors[]`` **and** ``data`` carrying a real value.
    Explicitly not "status == 200": GraphQL returns 200 for schema and resolver
    errors alike, which is the distinction that matters for GraphQL.
    """
    if result.status != 200 or result.error:
        return False
    body = result.body
    if not isinstance(body, dict):
        return False
    if body.get("errors"):
        return False
    return has_real_data(body.get("data"))


def is_negative_success(result: HttpResult) -> bool:
    """A syntactically valid document that the server rejected.

    Useful as negative coverage and as a probe signal; distinct from a transport
    failure, where we learned nothing about the API.
    """
    if result.error or result.status == 0:
        return False
    if result.status != 200:
        return True
    return bool((result.body or {}).get("errors"))


class TargetAdapter(abc.ABC):
    """GraphQL transport (live HTTP, or a recorded replay for tests)."""

    @abc.abstractmethod
    async def introspect(self, identity: Identity) -> dict[str, Any]:
        """Fetch the schema description."""

    @abc.abstractmethod
    async def send(
        self,
        document: str,
        identity: Identity,
        *,
        variables: dict[str, Any] | None = None,
    ) -> HttpResult:
        """Execute one document and return the exchange."""

    async def aclose(self) -> None:
        """Release transport resources."""
