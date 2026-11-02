"""summary.md — the paper artifact (doc 05 §4).

A per-run table, backed by findings and a defined coverage denominator
rather than raw counts.
"""

from __future__ import annotations

from typing import Any


def _pct(value) -> str:
    return "—" if value is None else f"{value:.1%}"


def render(
    *,
    target: str,
    coverage: dict[str, Any] | None,
    findings: dict[str, Any],
    score: dict[str, Any] | None,
    budget: dict[str, Any] | None,
) -> str:
    lines: list[str] = [f"# PrediQL — {target}", ""]

    # Coverage
    if coverage:
        lines += [
            "## Coverage", "",
            f"- operation coverage: **{_pct(coverage.get('operation_coverage'))}** "
            f"({coverage.get('operations_covered')}/{coverage.get('operations_total')})",
            f"- element coverage: **{_pct(coverage.get('element_coverage'))}** "
            f"({coverage.get('elements_covered')}/{coverage.get('elements_total')} Type.field pairs)",
            f"- field-path coverage: {_pct(coverage.get('field_path_coverage'))} "
            f"(depth {coverage.get('depth')})", "",
        ]

    # Findings by class
    by_class = findings.get("by_class") or {}
    lines += ["## Findings", "",
              f"- **{findings.get('confirmed', 0)} confirmed**, "
              f"{findings.get('potential', 0)} potential", ""]
    if by_class:
        lines += ["| class | confirmed | potential |", "|---|--:|--:|"]
        for cid, counts in sorted(by_class.items()):
            lines.append(f"| {cid} | {counts.get('confirmed', 0)} | {counts.get('potential', 0)} |")
        lines.append("")

    # Score
    if score and score.get("confirmed"):
        m = score["confirmed"]
        lines += [
            "## Score vs ground truth", "",
            f"- certification: **{score.get('certification', '—')}**",
            "",
            "| matrix | TP | FP | FN | precision | recall | F1 |",
            "|---|--:|--:|--:|--:|--:|--:|",
            f"| confirmed | {m['tp']} | {m['fp']} | {m['fn']} | "
            f"{_pct(m['precision'])} | {_pct(m['recall'])} | {_pct(m['f1'])} |",
        ]
        wp = score.get("with_potential")
        if wp:
            lines.append(f"| + potential | {wp['tp']} | {wp['fp']} | {wp['fn']} | "
                         f"{_pct(wp['precision'])} | {_pct(wp['recall'])} | {_pct(wp['f1'])} |")
        lines.append("")

    # Cost
    if budget and budget.get("total"):
        t = budget["total"]
        lines += [
            "## Cost", "",
            f"- LLM calls: {t.get('calls', 0)}",
            f"- tokens: {t.get('total_tokens', 0)} "
            f"({t.get('prompt_tokens', 0)} in / {t.get('completion_tokens', 0)} out)",
            f"- USD: {t.get('usd', 0)}",
            f"- LLM wall time: {t.get('wall_seconds', 0)}s", "",
        ]
    return "\n".join(lines)
