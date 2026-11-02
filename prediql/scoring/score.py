"""Scoring findings against ground truth (doc 03 §3).

Produces precision / recall / F1 with two things v1's hardcoded DVGA scripts
lacked: **negative ground truth** (so a false positive is counted, not inferred)
and **coverage-conditioned recall** (so "never reached the operation" is
separated from "reached it and missed the bug").

Two confusion matrices are reported — confirmed-only, and confirmed+potential —
so the precision cost of trusting potential findings is a number, which is the
direct answer to v1's "2,130 findings on a read-only API".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from prediql.scoring.classes import normalize
from prediql.scoring.groundtruth import GroundTruth


@dataclass
class ConfusionMatrix:
    """Counts and the metrics derived from them, over a set of (op, class) cells."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    tp_cells: list[str] = field(default_factory=list)
    fp_cells: list[str] = field(default_factory=list)
    fn_cells: list[str] = field(default_factory=list)
    # FN cells that fall on operations the run never covered — a coverage gap,
    # not a detection miss.
    fn_uncovered_cells: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def coverage_conditioned_recall(self) -> float | None:
        """Recall counting only misses on operations we actually reached."""
        covered_fn = self.fn - len(self.fn_uncovered_cells)
        denom = self.tp + covered_fn
        return self.tp / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if not p or not r:
            return None
        return 2 * p * r / (p + r)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": _round(self.precision),
            "recall": _round(self.recall),
            "f1": _round(self.f1),
            "coverage_conditioned_recall": _round(self.coverage_conditioned_recall),
            "tp_cells": sorted(self.tp_cells),
            "fp_cells": sorted(self.fp_cells),
            "fn_cells": sorted(self.fn_cells),
            "fn_uncovered_cells": sorted(self.fn_uncovered_cells),
        }


def _round(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None


def _cell(operation: str, class_id: str) -> str:
    return f"{operation}::{class_id}"


def score(
    findings: list[dict[str, Any]],
    truth: GroundTruth,
    *,
    covered_operations: set[str] | None = None,
    only_operations: set[str] | None = None,
) -> dict[str, Any]:
    """Score a finding set against ground truth.

    ``covered_operations`` drives coverage-conditioned recall.
    ``only_operations`` restricts scoring to a chosen subset (partial scoring),
    with the subset stated in the result so recall is never silently diluted.
    """
    covered = covered_operations or set()

    # Restrict the labelled universe to the scored subset if one was given.
    scored_ops = only_operations if only_operations is not None else truth.labelled_operations()
    contracts = [c for c in truth.contracts if c.operation in scored_ops]

    confirmed = _matrix(findings, contracts, covered, include_potential=False,
                        only_operations=only_operations)
    with_potential = _matrix(findings, contracts, covered, include_potential=True,
                             only_operations=only_operations)

    # Findings on operations with no contract at all: reported separately rather
    # than silently folded into precision, so an unlabelled operation is honest.
    labelled = {c.operation for c in contracts}
    unlabelled = sorted(
        _cell(f["operation"], _canon(f["class"]))
        for f in findings
        if f.get("state") == "confirmed" and f["operation"] not in labelled
        and (only_operations is None or f["operation"] in only_operations)
    )

    result = {
        "target": truth.slug,
        "certification": truth.certification_status(),
        "scored_operations": sorted(scored_ops),
        "partial": only_operations is not None,
        "confirmed": confirmed.as_dict(),
        "with_potential": with_potential.as_dict(),
        "unlabelled_confirmed_cells": unlabelled,
        "by_class": _by_class(findings, contracts, only_operations),
        "post_hoc_labels": sorted(
            _cell(c.operation, _canon(cc.id)) for c in contracts for cc in c.classes
            if cc.origin == "post_hoc"
        ),
        "without_post_hoc": None,
    }
    # The disclosure: the same findings scored against the labels as they were
    # before anything was added after seeing tool output.
    if truth.has_post_hoc():
        original = score(findings, truth.without_post_hoc(),
                         covered_operations=covered, only_operations=only_operations)
        result["without_post_hoc"] = {
            k: original[k] for k in ("confirmed", "with_potential", "unlabelled_confirmed_cells")
        }
    return result


def _canon(class_id: str) -> str:
    return normalize(class_id) or class_id


def _matrix(
    findings: list[dict[str, Any]],
    contracts: list,
    covered: set[str],
    *,
    include_potential: bool,
    only_operations: set[str] | None,
) -> ConfusionMatrix:
    matrix = ConfusionMatrix()

    # Positive findings we are counting for this matrix.
    states = {"confirmed", "potential"} if include_potential else {"confirmed"}
    positives: dict[tuple[str, str], dict] = {}
    for finding in findings:
        if finding.get("state") not in states:
            continue
        op = finding["operation"]
        if only_operations is not None and op not in only_operations:
            continue
        positives[(op, _canon(finding["class"]))] = finding

    contract_by_op = {c.operation: c for c in contracts}
    matched: set[tuple[str, str]] = set()

    # TP / FN over every labelled vulnerable (operation, class) cell.
    for contract in contracts:
        for class_id in contract.class_ids():
            key = (contract.operation, class_id)
            if not contract.vulnerable:
                continue
            if key in positives:
                matrix.tp += 1
                matrix.tp_cells.append(_cell(*key))
                matched.add(key)
            else:
                matrix.fn += 1
                matrix.fn_cells.append(_cell(*key))
                if contract.operation not in covered:
                    matrix.fn_uncovered_cells.append(_cell(*key))

    # FP: a positive finding that no vulnerable contract cell claimed.
    #     TN: a negative contract with no positive finding on it.
    for (op, class_id), finding in positives.items():
        if (op, class_id) in matched:
            continue
        contract = contract_by_op.get(op)
        if contract is not None:  # examined this operation; the class was not labelled present
            matrix.fp += 1
            matrix.fp_cells.append(_cell(op, class_id))
        # findings on unlabelled operations are handled by the caller (unlabelled_confirmed_cells)

    for contract in contracts:
        if contract.vulnerable:
            continue
        # A clean operation with no positive finding is a true negative.
        if not any(op == contract.operation for (op, _cls) in positives):
            matrix.tn += 1

    return matrix


def _by_class(
    findings: list[dict[str, Any]], contracts: list, only_operations: set[str] | None
) -> dict[str, dict[str, int]]:
    """Per-class TP/FP/FN, for the report's class breakdown."""
    vulnerable_cells = {
        (c.operation, cid) for c in contracts if c.vulnerable for cid in c.class_ids()
    }
    # Only labelled operations, exactly as the confusion matrix counts them:
    # a confirmed finding on an unlabelled operation is reported separately
    # (``unlabelled_confirmed_cells``), never as a per-class false positive.
    labelled = {c.operation for c in contracts}
    confirmed_cells = {
        (f["operation"], _canon(f["class"]))
        for f in findings if f.get("state") == "confirmed"
        and f["operation"] in labelled
        and (only_operations is None or f["operation"] in only_operations)
    }
    classes = {cid for _op, cid in vulnerable_cells} | {cid for _op, cid in confirmed_cells}
    result: dict[str, dict[str, int]] = {}
    for cid in sorted(classes):
        v = {cell for cell in vulnerable_cells if cell[1] == cid}
        c = {cell for cell in confirmed_cells if cell[1] == cid}
        result[cid] = {
            "tp": len(v & c),
            "fp": len(c - v),
            "fn": len(v - c),
        }
    return result
