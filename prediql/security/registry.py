"""Probe-family registry (doc 07 §1).

Maps canonical class id -> family instance. ``--families`` selects a subset,
which is both the isolated-run mode and the RQ3 disable-one-family ablation.
"""

from __future__ import annotations

from prediql.security.families.base import ProbeFamily
from prediql.security.families.dos import DenialOfServiceFamily
from prediql.security.families.introspection import IntrospectionFamily
from prediql.security.families.oscmd import OsCommandInjectionFamily
from prediql.security.families.path_traversal import PathTraversalFamily
from prediql.security.families.sqli import SqlInjectionFamily
from prediql.security.families.ssrf import SsrfFamily
from prediql.security.families.xss import ReflectedXssFamily

_FAMILIES: tuple[type[ProbeFamily], ...] = (
    SqlInjectionFamily,
    OsCommandInjectionFamily,
    PathTraversalFamily,
    ReflectedXssFamily,
    SsrfFamily,
    IntrospectionFamily,
    DenialOfServiceFamily,
)

FAMILY_REGISTRY: dict[str, type[ProbeFamily]] = {cls.id: cls for cls in _FAMILIES}


def build_families(
    selected: tuple[str, ...] = (),
    *,
    oob: object | None = None,
    auth_args: dict[str, str] | None = None,
) -> list[ProbeFamily]:
    """Instantiate families, optionally restricted to ``selected`` ids.

    An unknown id is a hard error rather than a silent skip: a mistyped
    ``--families sqi`` should fail loudly, not run nothing. ``oob`` is attached to
    every family; those that can plant a callback (SSRF, blind OS-command) use it,
    the rest ignore it. ``auth_args`` are the authenticated tester's known
    argument values, used by every family to fill a non-injected required
    argument whose name matches, so a probe can reach a gated resolver.
    """
    ids = selected or tuple(FAMILY_REGISTRY)
    unknown = [i for i in ids if i not in FAMILY_REGISTRY]
    if unknown:
        known = ", ".join(sorted(FAMILY_REGISTRY))
        raise ValueError(f"unknown probe family/families {unknown}; known: {known}")
    families = []
    for i in ids:
        fam = FAMILY_REGISTRY[i]()
        fam.oob = oob
        fam.auth_args = dict(auth_args or {})
        families.append(fam)
    return families
