"""HTTP GraphQL target adapter."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from prediql.engine.config import Identity, Limits
from prediql.targets.base import HttpResult, TargetAdapter

#: Standard introspection query, trimmed to what :mod:`prediql.model.schema`
#: consumes, plus field descriptions (the action-label resolver reads them).
#: Deliberately not the full reference query: type-level descriptions and most
#: deprecation metadata are a large share of a big schema's bytes and unused.
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      possibleTypes { name }
      fields(includeDeprecated: true) {
        name
        description
        args { name type { ...TypeRef } }
        type { ...TypeRef }
      }
      inputFields { name type { ...TypeRef } }
      enumValues(includeDeprecated: true) { name }
    }
  }
}
fragment TypeRef on __Type {
  kind name
  ofType { kind name
    ofType { kind name
      ofType { kind name
        ofType { kind name
          ofType { kind name
            ofType { kind name } } } } } }
}
"""


class GraphQLTarget(TargetAdapter):
    """Async GraphQL-over-HTTP adapter with connection pooling."""

    def __init__(self, url: str, limits: Limits | None = None) -> None:
        self.url = url
        self.limits = limits or Limits()
        self._client = httpx.AsyncClient(
            timeout=self.limits.request_timeout,
            follow_redirects=True,
            # Pooling matters: v1 opened a fresh connection per request.
            limits=httpx.Limits(max_connections=max(4, self.limits.max_http * 2)),
        )

    async def introspect(self, identity: Identity) -> dict[str, Any]:
        result = await self.send(INTROSPECTION_QUERY, identity)
        if result.error:
            from prediql.engine.errors import TargetError

            raise TargetError(f"introspection failed: {result.error}")
        return result.body or {}

    #: Transient throttle/overload statuses that earn a backoff-and-retry rather
    #: than being counted as a failed query. Without this, a public endpoint that
    #: rate-limits (429) sees the engine plough straight on and sink its own
    #: coverage — exactly what hollowed out the pokeapi and countries runs.
    _RETRY_STATUS = frozenset({429, 503})
    _MAX_RETRIES = 4
    _BACKOFF_CAP_S = 30.0

    async def send(
        self,
        document: str,
        identity: Identity,
        *,
        variables: dict[str, Any] | None = None,
    ) -> HttpResult:
        payload: dict[str, Any] = {"query": document}
        if variables:
            payload["variables"] = variables
        headers = {"Content-Type": "application/json", **identity.headers}

        started = time.perf_counter()
        try:
            response = await self._client.post(self.url, json=payload, headers=headers)
            for attempt in range(self._MAX_RETRIES):
                if response.status_code not in self._RETRY_STATUS:
                    break
                # Honour Retry-After when the server sends it; otherwise use
                # exponential backoff with a cap. This paces us under the limit
                # instead of hammering through it.
                delay = self._retry_after(response.headers.get("retry-after"))
                if delay is None:
                    delay = min(self._BACKOFF_CAP_S, 0.5 * (2 ** attempt))
                await asyncio.sleep(delay)
                response = await self._client.post(self.url, json=payload, headers=headers)
            elapsed = (time.perf_counter() - started) * 1000
            try:
                body = response.json()
            except ValueError:
                body = None
            return HttpResult(
                document=document,
                identity=identity.name,
                status=response.status_code,
                body=body if isinstance(body, dict) else None,
                elapsed_ms=elapsed,
                error=None if isinstance(body, dict) else "non-JSON response body",
                variables=variables or {},
            )
        except httpx.HTTPError as exc:
            # Status 0 marks "never reached the API" — distinct from a rejection,
            # which tells us something real about the schema.
            return HttpResult(
                document=document,
                identity=identity.name,
                status=0,
                elapsed_ms=(time.perf_counter() - started) * 1000,
                error=f"{type(exc).__name__}: {exc}",
                variables=variables or {},
            )

    @staticmethod
    def _retry_after(value: str | None) -> float | None:
        """Parse a Retry-After header (delta-seconds form); ignore an HTTP-date."""
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            return None

    async def aclose(self) -> None:
        await self._client.aclose()
