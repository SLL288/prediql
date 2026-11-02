"""Step: score findings against a target's ground truth (doc 03).

Non-gating (like ``ground_truth_eval``): a missing or stale truth file yields a
``null`` score with a reason, never a crash. Requires only on-disk artifacts, so
``score`` mode re-scores a finished run after the truth is edited — no target, no
LLM.
"""

from __future__ import annotations

from pathlib import Path

from prediql.engine import artifacts as A
from prediql.engine import provenance
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.model.coverage import CoverageState
from prediql.scoring import summary
from prediql.scoring.groundtruth import GroundTruthError, load
from prediql.scoring.score import score as compute_score


@register
class ScoreStep(Step):
    name = "score"
    requires = frozenset({A.FINDINGS})
    produces = frozenset({A.SCORE})
    cost_class = "cpu"
    description = "Score findings against the target's ground-truth contracts."

    def config_signature(self, ctx: RunContext) -> dict:
        truth_path = ctx.config.truth_path or ctx.services.get("truth_path") or ""
        return {
            "truth": truth_path,
            # The labels, not just the path: editing a truth file must re-score.
            "truth_sha256": provenance.file_sha256(truth_path) if truth_path else None,
            "operations": sorted(ctx.services.get("score_operations", []) or []),
        }

    async def run(self, ctx: RunContext) -> StepResult:
        truth_path = ctx.config.truth_path or ctx.services.get("truth_path")
        if not truth_path:
            return self._null("no ground-truth file supplied (--truth)")
        if not Path(truth_path).exists():
            return self._null(f"ground-truth file not found: {truth_path}")

        try:
            truth = load(truth_path)
        except GroundTruthError as exc:
            return self._null(f"invalid ground truth: {exc}")

        findings = (ctx.get(A.FINDINGS) or {}).get("findings", [])
        covered = self._covered_operations(ctx)
        only = ctx.services.get("score_operations")
        only_set = set(only) if only else None

        result = compute_score(
            findings, truth, covered_operations=covered, only_operations=only_set
        )
        result["schema_drift"] = self._schema_drift(ctx, truth)
        result["truth_file"] = {"path": str(truth_path),
                                "sha256": provenance.file_sha256(truth_path)}

        (ctx.run_dir / "score.md").write_text(summary.render(result), encoding="utf-8")

        m = result["confirmed"]
        return StepResult(
            artifacts={A.SCORE: result},
            metrics={
                "certification": result["certification"],
                "precision": m["precision"],
                "recall": m["recall"],
                "f1": m["f1"],
                "coverage_conditioned_recall": m["coverage_conditioned_recall"],
                "schema_drift": result["schema_drift"],
            },
            note=(f"P={_fmt(m['precision'])} R={_fmt(m['recall'])} F1={_fmt(m['f1'])} "
                  f"({truth.certification_status()})"),
        )

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _covered_operations(ctx: RunContext) -> set[str]:
        coverage = ctx.get(A.COVERAGE)
        if not coverage:
            return set()
        state = CoverageState.from_dict({
            "depth": coverage.get("depth", 5),
            "by_operation": coverage.get("by_operation", {}),
        })
        return state.covered_operations()

    def _schema_drift(self, ctx: RunContext, truth) -> bool | None:
        """Whether the run's schema differs from the one the truth was written for."""
        if not truth.schema_fingerprint:
            return None
        schema_artifact = ctx.get(A.SCHEMA)
        if not schema_artifact:
            return None
        from prediql.engine.fingerprint import fingerprint

        return fingerprint(schema_artifact) != truth.schema_fingerprint

    def _null(self, reason: str) -> StepResult:
        return StepResult(
            artifacts={A.SCORE: {"score": None, "reason": reason}},
            metrics={"scored": False, "reason": reason},
            note=f"not scored: {reason}",
        )


def _fmt(value) -> str:
    return "—" if value is None else f"{value:.2f}"
