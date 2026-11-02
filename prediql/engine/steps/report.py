"""Step: render findings into the four report formats (doc 05 §4).

Requires only ``findings``; coverage, score, and budget are folded in when
present, so ``report`` mode re-renders a finished run over on-disk artifacts with
no target and no LLM.
"""

from __future__ import annotations

from typing import Any

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.reporting import csv_report, html, sarif, summary_md


@register
class ReportStep(Step):
    name = "report"
    requires = frozenset({A.FINDINGS})
    produces = frozenset({A.REPORT})
    cost_class = "cpu"
    description = "Render HTML / SARIF / CSV / summary from the findings."

    def config_signature(self, ctx: RunContext) -> dict:
        # Re-render when any input the report shows changes.
        return {
            "coverage": ctx.artifact_fingerprint(A.COVERAGE),
            "score": ctx.artifact_fingerprint(A.SCORE),
        }

    async def run(self, ctx: RunContext) -> StepResult:
        findings = ctx.get(A.FINDINGS) or {"findings": [], "confirmed": 0, "potential": 0}
        coverage = ctx.get(A.COVERAGE)
        score = ctx.get(A.SCORE)
        budget = ctx.ledger.snapshot()
        target = ctx.config.target_url or ctx.config.target_slug
        rows = findings.get("findings", [])

        directory = ctx.run_dir / "report"
        directory.mkdir(parents=True, exist_ok=True)

        outputs = {
            "index.html": html.render(target=target, run_id=ctx.run_id, coverage=coverage,
                                      findings=findings, score=score, budget=budget),
            "findings.sarif": sarif.render(rows, target=target),
            "findings.csv": csv_report.render(rows),
            "summary.md": summary_md.render(target=target, coverage=coverage, findings=findings,
                                            score=score, budget=budget),
        }
        for name, content in outputs.items():
            (directory / name).write_text(content, encoding="utf-8")

        return StepResult(
            artifacts={A.REPORT: {
                "formats": sorted(outputs),
                "path": str(directory),
                "confirmed": findings.get("confirmed", 0),
                "potential": findings.get("potential", 0),
            }},
            metrics={"formats": len(outputs), "findings": len(rows)},
            note=f"wrote {', '.join(sorted(outputs))}",
        )
