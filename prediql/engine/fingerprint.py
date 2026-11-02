"""Stable content fingerprints.

Resume and cascade invalidation both hinge on one property: the same logical
inputs must hash to the same string across processes and Python versions. That
rules out :func:`hash` (salted per process) and any dict-ordering dependence.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

_ALGO = "sha256"


def canonical(value: Any) -> str:
    """Render ``value`` as deterministic JSON.

    Dict keys are sorted and separators are fixed, so two structurally equal
    values always produce the same text regardless of construction order.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint(*parts: Any) -> str:
    """Return a stable ``sha256:<hex>`` fingerprint over ``parts``.

    Parts are canonicalised individually and joined with a separator that cannot
    appear in JSON output, so ``("ab", "c")`` and ``("a", "bc")`` differ.
    """
    digest = hashlib.new(_ALGO)
    for part in parts:
        digest.update(canonical(part).encode("utf-8"))
        digest.update(b"\x1e")  # ASCII record separator
    return f"{_ALGO}:{digest.hexdigest()}"


def short(fp: str, length: int = 12) -> str:
    """Shorten a fingerprint for run ids and log lines."""
    return fp.split(":", 1)[-1][:length]
