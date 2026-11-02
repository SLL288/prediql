"""CSV renderer — one row per finding (doc 05 §4).

The machine format that replaces RESULTS.xlsx: flat, stable columns for
spreadsheets and statistics.
"""

from __future__ import annotations

import csv
import io
from typing import Any

_COLUMNS = [
    "id", "class", "severity", "state", "operation", "identity",
    "evidence_kind", "oracle_verdict", "judge_agrees", "stage", "family",
    "chain_length", "matched", "repro",
]


def render(findings: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for finding in findings:
        witness = finding.get("witness") or {}
        judge = finding.get("judge_verdict") or {}
        writer.writerow({
            "id": finding.get("id", ""),
            "class": finding.get("class", ""),
            "severity": finding.get("severity", ""),
            "state": finding.get("state", ""),
            "operation": finding.get("operation", ""),
            "identity": finding.get("identity", ""),
            "evidence_kind": finding.get("evidence_kind", ""),
            "oracle_verdict": finding.get("oracle_verdict", ""),
            "judge_agrees": judge.get("agrees", "") if judge else "",
            "stage": finding.get("stage", ""),
            "family": finding.get("family", ""),
            "chain_length": len(finding.get("chain") or []) or "",
            "matched": witness.get("matched", ""),
            "repro": finding.get("repro", ""),
        })
    return buffer.getvalue()
