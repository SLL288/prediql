"""
Jaccard overlap on normalized *finding-type* keys for vulnerability results.

    J(A, B) = |A ∩ B| / |A ∪ B|

Used by offline tools (e.g. ``prediql_jaccard.py``, ``output_folder_analysis.run_jaccard_scan``)
to compare finding sets across detector exports or across model runs — not during ``main`` fuzzing.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set


def finding_type_keys(
    results: List[Dict[str, Any]],
    *,
    exclude_safe: bool = True,
) -> Set[str]:
    """
    Build a set of comparable finding keys from detector result dicts.

    Uses normalized ``detection_name`` when present, else ``category`` prefixed
    with ``cat:``. Skips entries marked ``safe`` when ``exclude_safe`` is True.
    """
    keys: Set[str] = set()
    for r in results or []:
        if not isinstance(r, dict):
            continue
        det = str(r.get("detection", "")).lower()
        if exclude_safe and det == "safe":
            continue
        name = (r.get("detection_name") or "").strip().lower()
        cat = (r.get("category") or "").strip().lower()
        if name:
            keys.add(name)
        elif cat:
            keys.add(f"cat:{cat}")
    return keys


def jaccard_coefficient(set_a: Set[str], set_b: Set[str]) -> Dict[str, Any]:
    """Return counts and Jaccard index; ``jaccard`` is 1.0 when both empty."""
    inter = set_a & set_b
    union = set_a | set_b
    u = len(union)
    i = len(inter)
    if u == 0:
        coef = 0.0
        note = "both_empty"
    else:
        coef = i / u
        note = "computed"
    return {
        "formula": "|A ∩ B| / |A ∪ B|",
        "|A|": len(set_a),
        "|B|": len(set_b),
        "|A ∩ B|": i,
        "|A ∪ B|": u,
        "jaccard": round(coef, 6),
        "keys_a": sorted(set_a),
        "keys_b": sorted(set_b),
        "intersection_keys": sorted(inter),
        "note": note,
    }


def interpret_jaccard(
    metrics: Dict[str, Any],
    *,
    comparison_kind: str,
    label_a: str,
    label_b: str,
) -> str:
    """Short human-readable read of the coefficient."""
    j = float(metrics.get("jaccard", 0.0))
    ua = int(metrics.get("|A|", 0))
    ub = int(metrics.get("|B|", 0))
    if ua == 0 and ub == 0:
        return f"No {comparison_kind} findings on either side ({label_a} vs {label_b})."
    if ua == 0 or ub == 0:
        return (
            f"Asymmetric findings ({label_a}: {ua}, {label_b}: {ub}); Jaccard={j:.3f} "
            f"(union driven by one side)."
        )
    if j >= 0.65:
        if comparison_kind == "cross_llm":
            hint = (
                "High overlap across independent LLMs — stronger evidence of a real issue "
                "(consistent finding types)."
            )
        else:
            hint = "High overlap between rule-based and LLM finding types — corroboration."
    elif j >= 0.35:
        hint = "Moderate overlap — mixed agreement; review both result lists."
    else:
        if comparison_kind == "cross_llm":
            hint = (
                "Low overlap across LLMs — investigate for one-sided hallucination or "
                "different taxonomies."
            )
        else:
            hint = "Low overlap — rule engine and LLM disagree on finding types."
    return f"{label_a} vs {label_b}: Jaccard={j:.3f}. {hint}"


def jaccard_pair_report(
    results_a: List[Dict[str, Any]],
    results_b: List[Dict[str, Any]],
    *,
    label_a: str,
    label_b: str,
    comparison_kind: str,
) -> Dict[str, Any]:
    """Full bundle: keys, coefficient dict, and interpretation."""
    ka = finding_type_keys(results_a)
    kb = finding_type_keys(results_b)
    metrics = jaccard_coefficient(ka, kb)
    metrics["interpretation"] = interpret_jaccard(
        metrics, comparison_kind=comparison_kind, label_a=label_a, label_b=label_b
    )
    metrics["label_a"] = label_a
    metrics["label_b"] = label_b
    metrics["comparison_kind"] = comparison_kind
    return metrics
