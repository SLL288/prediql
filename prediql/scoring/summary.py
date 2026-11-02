"""Human-readable score summary (``score.md``).

The reviewer/paper artifact: the same per-target table shape v1's RESULTS.md had,
now backed by findings and a defined denominator rather than raw counts.
"""

from __future__ import annotations

from typing import Any


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.1%}"


def render(result: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Score — {result['target']}")
    lines.append("")
    lines.append(f"- certification: **{result['certification']}**")
    if result.get("partial"):
        lines.append(f"- partial scoring over: {', '.join(result['scored_operations'])}")
    lines.append("")

    lines.append("| matrix | TP | FP | FN | precision | recall | cov-cond. recall | F1 |")
    lines.append("|---|--:|--:|--:|--:|--:|--:|--:|")
    for label, key in (("confirmed", "confirmed"), ("+ potential", "with_potential")):
        m = result[key]
        lines.append(
            f"| {label} | {m['tp']} | {m['fp']} | {m['fn']} | "
            f"{_pct(m['precision'])} | {_pct(m['recall'])} | "
            f"{_pct(m['coverage_conditioned_recall'])} | {_pct(m['f1'])} |"
        )
    lines.append("")

    by_class = result.get("by_class") or {}
    if by_class:
        lines.append("## By class (confirmed)")
        lines.append("")
        lines.append("| class | TP | FP | FN |")
        lines.append("|---|--:|--:|--:|")
        for cid, counts in sorted(by_class.items()):
            lines.append(f"| {cid} | {counts['tp']} | {counts['fp']} | {counts['fn']} |")
        lines.append("")

    m = result["confirmed"]
    if m["fn_uncovered_cells"]:
        lines.append("## Missed only because uncovered (a coverage gap, not a detection miss)")
        lines.append("")
        for cell in m["fn_uncovered_cells"]:
            lines.append(f"- {cell}")
        lines.append("")

    if result.get("unlabelled_confirmed_cells"):
        lines.append("## Confirmed on unlabelled operations (need triage, not scored)")
        lines.append("")
        for cell in result["unlabelled_confirmed_cells"]:
            lines.append(f"- {cell}")
        lines.append("")

    return "\n".join(lines)
