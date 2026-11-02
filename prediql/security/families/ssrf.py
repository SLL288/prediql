"""Server-Side Request Forgery family — out-of-band confirmation.

SSRF is blind: a vulnerable resolver fetches an attacker-supplied URL, but the
response rarely reveals it. The proof is *interaction* — the target reaching a
collaborator we control. This family plants ``http://<oob>/<token>`` in URL-like
arguments and expects a CALLBACK on that token; the oracle confirms iff the
collaborator was hit. With no OOB server configured the family is inert (it emits
no payloads), so it never manufactures a finding from a response alone.
"""
from __future__ import annotations

from prediql.oracle.evidence import Evidence, Expectation
from prediql.security.families.base import Payload, ProbeFamily, injectable_arguments
from prediql.model.schema import Operation, Schema

# Argument names that usually carry a URL/host the server will dereference.
_URLISH = ("url", "uri", "href", "link", "src", "source", "image", "img", "avatar",
           "photo", "icon", "webhook", "callback", "endpoint", "host", "redirect",
           "fetch", "proxy", "feed", "document", "file", "path", "import", "load")


# A resolver that builds its own URL from these separate parts (DVGA's
# importPaste is the canonical case): injecting a whole URL into just one of them
# yields a malformed address the server never fetches.
_HOST_ARG = ("host", "hostname", "domain", "server", "addr", "address")
_SCHEME_ARG = ("scheme", "protocol", "proto")


def _split_url_args(operation: Operation, schema: Schema, exclude=frozenset()) -> dict[str, str] | None:
    """If the operation takes a host *and* a scheme argument, the names of the
    URL-part arguments it exposes (host/scheme and any path/port). Else None."""
    names = {a.lower(): a for a in injectable_arguments(operation, schema, exclude=exclude)}
    # port is an Int, so it is not in injectable_arguments; take it from the schema.
    names |= {n.lower(): n for n, _ref in operation.args}
    host = next((names[k] for k in _HOST_ARG if k in names), None)
    scheme = next((names[k] for k in _SCHEME_ARG if k in names), None)
    if host is None or scheme is None:
        return None
    parts = {"host": host, "scheme": scheme}
    if "path" in names:
        parts["path"] = names["path"]
    if "port" in names:
        parts["port"] = names["port"]
    return parts


def _urlish_args(operation: Operation, schema: Schema, exclude=frozenset()) -> list[str]:
    injectable = injectable_arguments(operation, schema, exclude=exclude)
    named = [a for a in injectable if any(k in a.lower() for k in _URLISH)]
    # Prefer URL-like names; fall back to all string args, since names are not
    # always indicative and SSRF only triggers where the value is dereferenced.
    return named or injectable


class SsrfFamily(ProbeFamily):
    id = "ssrf"

    def applies(self, operation, schema, graph) -> bool:
        ex = set(self.auth_args)
        return self.oob is not None and bool(
            _urlish_args(operation, schema, ex) or _split_url_args(operation, schema, ex))

    def seed_payloads(self, operation: Operation, schema: Schema) -> list[Payload]:
        if self.oob is None:
            return []
        ex = set(self.auth_args)
        payloads: list[Payload] = []

        # Split-URL resolver: fill scheme/host/port/path as one coherent callback.
        split = _split_url_args(operation, schema, ex)
        if split is not None:
            token = self.oob.new_token()
            parts = self.oob.parts_for(token)
            values = {split[k]: parts[k] for k in split if k in parts}
            payloads.append(self._inject_many(
                operation, schema, values,
                Expectation(self.id, Evidence.CALLBACK, token=token,
                            marker=self.oob.url_for(token), stage="ssrf-oob-split"),
                argument="+".join(sorted(values)),
            ))

        for argument in _urlish_args(operation, schema, ex):
            token = self.oob.new_token()
            url = self.oob.url_for(token)
            payloads.append(self._inject(
                operation, schema, argument, url,
                Expectation(self.id, Evidence.CALLBACK, token=token, marker=url,
                            stage="ssrf-oob"),
            ))
        return payloads
