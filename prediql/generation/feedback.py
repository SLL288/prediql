"""Error feedback: what a failed response says about the next attempt.

A schema can declare an argument optional while the resolver needs it. DVGA's
``createPaste(title, content)`` is the canonical case: both are nullable in the
schema, and every call without them fails with ``CreatePaste.mutate() missing 2
required positional arguments: 'title' and 'content'``. A generator that only
fills non-null arguments retries the same doomed shape forever.

This reads the server's own words for which arguments it wanted. It is
target-agnostic: the patterns are the common resolver and validation phrasings
(Python, graphql-js, Apollo, Hot Chocolate), and only names that really are
arguments of the operation are kept, so an unrelated message can never invent
one.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from prediql.model.schema import Operation

# Each pattern captures the span that names the missing argument(s).
_PATTERNS = (
    # Python resolvers: "missing 2 required positional arguments: 'title' and 'content'"
    re.compile(r"missing \d+ required (?:positional |keyword-only )?arguments?: (?P<names>[^\n\"]+)",
               re.I),
    # graphql-js / Apollo: 'Field "x" argument "title" of type "String!" is required'
    re.compile(r"argument \"(?P<names>\w+)\"[^\n]*? is required", re.I),
    # Generic: 'Argument "title" is required' / 'missing required argument: title'
    re.compile(r"missing required (?:argument|field|parameter)s?:?\s+(?P<names>[\w'\", ]+)", re.I),
    re.compile(r"\"(?P<names>\w+)\" (?:argument )?is required", re.I),
)
_NAME = re.compile(r"[A-Za-z_]\w*")
_STOPWORDS = frozenset({"and", "or", "argument", "arguments", "field", "required"})


def missing_arguments(errors: Iterable[Any] | None, operation: Operation) -> set[str]:
    """Argument names the server reported as missing, restricted to ``operation``'s."""
    declared = {name for name, _ref in operation.args}
    found: set[str] = set()
    for error in errors or ():
        message = error.get("message", "") if isinstance(error, dict) else str(error)
        for pattern in _PATTERNS:
            for match in pattern.finditer(message):
                for name in _NAME.findall(match.group("names")):
                    if name.lower() not in _STOPWORDS and name in declared:
                        found.add(name)
    return found
