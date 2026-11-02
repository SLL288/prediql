"""The finding model (doc 07 §3).

A finding is one vulnerability with the evidence that proves it. Findings are the
currency between ``adjudicate``, the scorer (M3), and the report (M5), so the
shape is fixed here once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from prediql.scoring.classes import Severity, get


class FindingState(StrEnum):
    CONFIRMED = "confirmed"
    """A deterministic oracle produced confirming evidence."""

    POTENTIAL = "potential"
    """A signal (reflection, error) that no confirmation followed."""


@dataclass
class Finding:
    """One vulnerability finding with its witness."""

    id: str
    class_id: str
    severity: str
    state: FindingState
    operation: str
    identity: str
    evidence_kind: str
    oracle_verdict: str
    witness: dict[str, Any]
    family: str
    stage: str = ""
    chain: list[dict[str, str]] | None = None
    judge_verdict: dict[str, Any] | None = None

    def to_dict(self, *, run_id: str = "") -> dict[str, Any]:
        return {
            "id": self.id,
            "class": self.class_id,
            "title": get(self.class_id).title if _known(self.class_id) else self.class_id,
            "severity": self.severity,
            "state": str(self.state),
            "operation": self.operation,
            "chain": self.chain,
            "identity": self.identity,
            "evidence_kind": self.evidence_kind,
            "oracle_verdict": self.oracle_verdict,
            "judge_verdict": self.judge_verdict,
            "witness": self.witness,
            "family": self.family,
            "stage": self.stage,
            "repro": f"predql repro --run {run_id} --finding {self.id}" if run_id else "",
        }


def _known(class_id: str) -> bool:
    try:
        get(class_id)
        return True
    except KeyError:
        return False


def severity_of(class_id: str) -> str:
    """Registry severity for a class, defaulting to medium for the unknown."""
    try:
        return str(get(class_id).severity)
    except KeyError:
        return str(Severity.MEDIUM)


# Rank order for sorting findings most-severe first.
_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_RANK[Severity(severity)]
    except ValueError:
        return 4
