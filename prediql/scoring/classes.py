"""Canonical vulnerability-class registry (doc 03 §4).

One table, read by probe families, the oracle, the report, and (in M3) the
scorer, so a class id, its severity, and the evidence that may confirm it are
defined exactly once. This is what replaces v1's scattered per-script
``NAME_MAP`` aliases.

The registry is deliberately OWASP-class-generic and target-agnostic: nothing
here names DVGA. A DVGA label lives only in a ground-truth file; a class here is
"SQL injection", not "the DVGA pastes bug".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Evidence(StrEnum):
    """How a finding may be proven.

    Ordered from strongest to weakest. The oracle (doc 04 §4) confirms only on
    the stronger kinds; ``REFLECTION`` and ``ERROR_SIGNATURE`` are signals that
    drive refinement, never confirmations on their own — which is what keeps a
    read-only API from manufacturing findings.
    """

    SENTINEL = "sentinel"
    """An injected marker or known file content appears in the response."""

    DIFFERENTIAL = "differential"
    """The response differs from the benign control in a payload-attributable way."""

    LATENCY = "latency"
    """Response time exceeds the per-operation baseline (median + k·MAD)."""

    DISCLOSURE = "disclosure"
    """Data is visible to an identity that should not see it (IDOR/UAF — M4)."""

    CALLBACK = "callback"
    """An out-of-band request reached a collaborator we control, carrying a token
    only our payload could have planted — the near-zero-FP proof for blind SSRF,
    blind command execution, and other out-of-band injections."""

    DOS = "dos"
    """Measurable amplification past a threshold."""

    REFLECTION = "reflection"
    """A payload is echoed verbatim — the weakest signal; potential, not confirmed."""

    ERROR_SIGNATURE = "error_signature"
    """A known error pattern appears — a signal that drives refinement."""


# Evidence kinds strong enough to *confirm* a finding. The rest are signals.
#
# DoS/amplification is deliberately NOT here: black-box response timing is
# confounded by network jitter and — critically — by the tool's own concurrent
# probes contending for the same server, so a single timing sample cannot
# distinguish a missing complexity limit from load. A DoS probe therefore yields
# a *potential* finding that reports the measured amplification factor for an
# analyst, rather than an overclaimed confirmation. Robust confirmation would
# need isolated, repeated measurement (a documented enhancement).
CONFIRMING_EVIDENCE: frozenset[Evidence] = frozenset(
    {Evidence.SENTINEL, Evidence.DIFFERENTIAL, Evidence.LATENCY, Evidence.DISCLOSURE,
     Evidence.CALLBACK}
)


@dataclass(frozen=True, slots=True)
class VulnClass:
    """One vulnerability class."""

    id: str
    title: str
    severity: Severity
    evidence: tuple[Evidence, ...]
    """Evidence kinds that can confirm this class, strongest first."""
    aliases: tuple[str, ...] = ()
    owasp: str = ""


_CLASSES: tuple[VulnClass, ...] = (
    VulnClass("sql_injection", "SQL Injection", Severity.HIGH,
              (Evidence.SENTINEL, Evidence.DIFFERENTIAL, Evidence.LATENCY),
              aliases=("sqli", "sql injection (sqli)"), owasp="API8:2023"),
    VulnClass("os_command_injection", "OS Command Injection", Severity.CRITICAL,
              (Evidence.SENTINEL, Evidence.CALLBACK),
              aliases=("os command injection", "command execution", "rce"), owasp="API8:2023"),
    VulnClass("xss_reflected", "Reflected Cross-Site Scripting", Severity.MEDIUM,
              (Evidence.REFLECTION,),
              aliases=("reflected xss", "xss"), owasp="API8:2023"),
    VulnClass("xss_stored", "Stored Cross-Site Scripting", Severity.HIGH,
              (Evidence.DIFFERENTIAL, Evidence.REFLECTION),
              aliases=("stored xss", "persistent xss"), owasp="API8:2023"),
    VulnClass("path_traversal", "Path Traversal", Severity.HIGH,
              (Evidence.SENTINEL,),
              aliases=("directory traversal", "lfi", "path injection"), owasp="API8:2023"),
    VulnClass("ssrf", "Server-Side Request Forgery", Severity.HIGH,
              (Evidence.CALLBACK, Evidence.SENTINEL, Evidence.DIFFERENTIAL),
              aliases=("server-side request forgery",), owasp="API7:2023"),
    VulnClass("html_injection", "HTML Injection", Severity.MEDIUM,
              (Evidence.REFLECTION,), aliases=("html inj",), owasp="API8:2023"),
    VulnClass("introspection_enabled", "Introspection Enabled", Severity.LOW,
              (Evidence.DIFFERENTIAL,),
              aliases=("introspection", "graphql introspection", "field_suggestions"),
              owasp="API9:2023"),
    VulnClass("field_suggestion", "Field Suggestions Enabled", Severity.LOW,
              (Evidence.DIFFERENTIAL,),
              aliases=("field suggestions",), owasp="API9:2023"),
    VulnClass("denial_of_service", "Denial of Service", Severity.MEDIUM,
              (Evidence.DOS, Evidence.LATENCY),
              aliases=("dos", "query depth abuse", "query_depth_abuse", "resource exhaustion",
                       "alias_overloading", "batch_query_attack"), owasp="API4:2023"),
    # Chain classes (M4); registered here so the scorer and report know them.
    VulnClass("idor", "Insecure Direct Object Reference", Severity.HIGH,
              (Evidence.DISCLOSURE, Evidence.DIFFERENTIAL),
              aliases=("bola", "broken object level authorization"), owasp="API1:2023"),
    VulnClass("uaf", "Use-After-Free / Phantom Resource", Severity.HIGH,
              (Evidence.DISCLOSURE,), aliases=("phantom resource",), owasp="API1:2023"),
)


_BY_ID: dict[str, VulnClass] = {c.id: c for c in _CLASSES}
_BY_ALIAS: dict[str, str] = {}
for _c in _CLASSES:
    _BY_ALIAS[_c.id] = _c.id
    _BY_ALIAS[_c.title.lower()] = _c.id
    for _a in _c.aliases:
        _BY_ALIAS[_a.lower()] = _c.id


def get(class_id: str) -> VulnClass:
    """Look up a class by its canonical id."""
    try:
        return _BY_ID[class_id]
    except KeyError:
        raise KeyError(f"unknown vulnerability class {class_id!r}") from None


def normalize(name: str) -> str | None:
    """Resolve any known alias to a canonical class id, or ``None``.

    Subsumes v1's ``NAME_MAP``: a detector or ground-truth file may use a
    human label, and it maps to one id here rather than in each consumer.
    """
    return _BY_ALIAS.get((name or "").strip().lower())


def all_classes() -> tuple[VulnClass, ...]:
    return _CLASSES


def confirms(class_id: str, evidence: Evidence) -> bool:
    """Whether ``evidence`` is strong enough to confirm ``class_id``.

    Both conditions must hold: the evidence must be a confirming kind at all,
    and it must be one this class accepts. A reflection can confirm nothing; a
    latency delta confirms SQLi but not path traversal.
    """
    return (
        evidence in CONFIRMING_EVIDENCE
        and evidence in get(class_id).evidence
    )
