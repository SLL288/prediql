"""SARIF 2.1.0 renderer (doc 05 §4).

Findings load into GitHub code scanning, VS Code, or any SARIF viewer with no
glue. Each finding is a result; its class is a rule; its chain (if any) becomes a
codeFlow so a multi-step vulnerability reads as the sequence it is.
"""

from __future__ import annotations

import json
from typing import Any

from prediql.scoring.classes import all_classes, get

# SARIF severity levels, mapped from our four-band severity.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def render(findings: list[dict[str, Any]], *, target: str = "") -> str:
    rules = [_rule(c) for c in all_classes()]
    rule_index = {c.id: i for i, c in enumerate(all_classes())}

    results = [_result(f, rule_index) for f in findings]
    document = {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [{
            "tool": {"driver": {
                "name": "PrediQL",
                "informationUri": "https://github.com/SLL288/prediql",
                "rules": rules,
            }},
            "properties": {"target": target},
            "results": results,
        }],
    }
    return json.dumps(document, indent=2)


def _rule(vuln_class) -> dict[str, Any]:
    return {
        "id": vuln_class.id,
        "name": "".join(part.capitalize() for part in vuln_class.id.split("_")),
        "shortDescription": {"text": vuln_class.title},
        "defaultConfiguration": {"level": _LEVEL.get(str(vuln_class.severity), "warning")},
        "properties": {"security-severity": _numeric_severity(str(vuln_class.severity)),
                       "owasp": vuln_class.owasp},
    }


def _result(finding: dict[str, Any], rule_index: dict[str, int]) -> dict[str, Any]:
    class_id = finding["class"]
    witness = finding.get("witness") or {}
    requests = witness.get("requests") or []
    operation = finding["operation"]

    message = (f"{finding.get('title', class_id)} on operation `{operation}` "
               f"({finding['state']}). {witness.get('matched', '')}")

    result: dict[str, Any] = {
        "ruleId": class_id,
        "ruleIndex": rule_index.get(class_id, 0),
        "level": _LEVEL.get(finding.get("severity", "medium"), "warning"),
        "message": {"text": message.strip()},
        "locations": [{"logicalLocations": [{
            "name": operation,
            "kind": "function",
            "fullyQualifiedName": f"{finding.get('identity', 'anon')}::{operation}",
        }]}],
        "properties": {
            "state": finding["state"],
            "evidence_kind": finding.get("evidence_kind", ""),
            "oracle_verdict": finding.get("oracle_verdict", ""),
            "repro": finding.get("repro", ""),
        },
    }
    if finding.get("judge_verdict"):
        result["properties"]["judge_verdict"] = finding["judge_verdict"]

    # A chain becomes a codeFlow: one location per step, in order.
    chain = finding.get("chain")
    if chain:
        result["codeFlows"] = [{"threadFlows": [{"locations": [
            {"location": {"logicalLocations": [{
                "name": step["operation"],
                "fullyQualifiedName": f"{step.get('identity', '')}::{step['operation']}",
            }]}, "properties": {"role": step.get("role", "")}}
            for step in chain
        ]}]}]
    elif requests:
        result["properties"]["request"] = requests[0].get("document", "")
    return result


def _numeric_severity(severity: str) -> str:
    """GitHub's 0.0–10.0 security-severity scale."""
    return {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}.get(severity, "5.0")
