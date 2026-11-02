"""Step: turn probe evidence into ranked findings (doc 02 §2).

The deterministic split the design insists on: ``probe`` gathers evidence,
``adjudicate`` classifies it. A CONFIRMED oracle verdict becomes a ``confirmed``
finding; a SIGNAL that no confirmation followed becomes a ``potential`` one.
Findings are deduplicated per (operation, class), keeping the strongest witness,
and written one-file-per-finding plus a ranked index.

Keeping this separate from ``probe`` is what lets a run be re-adjudicated — with
a different potential-policy, or (later) an LLM judge on the residual — without
re-issuing a single request.
"""

from __future__ import annotations

from typing import Any

from prediql.engine import artifacts as A
from prediql.engine.context import RunContext
from prediql.engine.stepgraph import Step, StepResult, register
from prediql.oracle.evidence import Verdict
from prediql.scoring.findings import (
    Finding,
    FindingState,
    severity_of,
    severity_rank,
)


@register
class AdjudicateStep(Step):
    name = "adjudicate"
    requires = frozenset({A.PROBE_RESULTS})
    produces = frozenset({A.FINDINGS})
    cost_class = "cpu"
    description = "Classify probe evidence into confirmed and potential findings."

    def config_signature(self, ctx: RunContext) -> dict:
        # Chain results are an optional input; fold their fingerprint in so that
        # re-running execute_chains re-adjudicates even without a requires edge.
        return {"chain_results": ctx.artifact_fingerprint(A.CHAIN_RESULTS)}

    async def run(self, ctx: RunContext) -> StepResult:
        results = list((ctx.get(A.PROBE_RESULTS) or {}).get("results", []))
        # Chain findings (IDOR/UAF) arrive as probe_result rows and are ranked
        # and written exactly like single-operation findings.
        results += (ctx.get(A.CHAIN_RESULTS) or {}).get("results", [])

        # Best evidence per (operation, class): a confirmation always wins over a
        # signal, so one operation cannot be reported twice for the same class.
        best: dict[tuple[str, str], dict[str, Any]] = {}
        for result in results:
            verdict = result.get("verdict")
            if verdict not in (Verdict.CONFIRMED, Verdict.SIGNAL):
                continue
            key = (result["operation"], result["class_id"])
            current = best.get(key)
            if current is None or _stronger(result, current):
                best[key] = result

        findings: list[Finding] = []
        for (operation, class_id), result in best.items():
            state = (
                FindingState.CONFIRMED
                if result["verdict"] == Verdict.CONFIRMED
                else FindingState.POTENTIAL
            )
            findings.append(Finding(
                id=_finding_id(operation, class_id, state),
                class_id=class_id,
                severity=severity_of(class_id),
                state=state,
                operation=operation,
                identity=result.get("identity", ""),
                evidence_kind=result.get("evidence") or "",
                oracle_verdict=result["verdict"],
                witness=result.get("witness") or {},
                family=result.get("family", class_id),
                stage=result.get("stage", ""),
                chain=result.get("chain"),
            ))

        # Rank: confirmed before potential, then by severity, then by class.
        findings.sort(key=lambda f: (
            0 if f.state is FindingState.CONFIRMED else 1,
            severity_rank(f.severity),
            f.class_id,
        ))

        # Optional LLM judge on the POTENTIAL residual only. Confirmed findings
        # are the oracle's call and are never sent; the judge is a second opinion
        # for triage, recorded alongside, not a gate.
        judged = await self._judge_potentials(ctx, findings)

        self._write_finding_files(ctx, findings)
        confirmed = sum(1 for f in findings if f.state is FindingState.CONFIRMED)
        index = [f.to_dict(run_id=ctx.run_id) for f in findings]

        return StepResult(
            artifacts={A.FINDINGS: {
                "findings": index,
                "confirmed": confirmed,
                "potential": len(findings) - confirmed,
                "by_class": _counts_by_class(findings),
                "judged": judged,
            }},
            metrics={
                "findings": len(findings),
                "confirmed": confirmed,
                "potential": len(findings) - confirmed,
                "judged": judged,
            },
            note=(f"{confirmed} confirmed, {len(findings) - confirmed} potential"
                  + (f", {judged} judged" if judged else "")),
        )

    async def _judge_potentials(self, ctx: RunContext, findings) -> int:
        """Have the LLM judge review potential findings, if a judge is configured."""
        router = ctx.services.get("router")
        judge_configured = router is not None and "judge" in ctx.config.providers
        if not judge_configured:
            return 0
        from prediql.security.judge import judge_finding

        potentials = [f for f in findings if f.state is FindingState.POTENTIAL]
        judged = 0
        for finding in potentials:
            try:
                finding.judge_verdict = await judge_finding(
                    router, finding.to_dict(run_id=ctx.run_id),
                    samples=ctx.config.strategy.judge_samples,
                )
                judged += 1
            except Exception as exc:  # noqa: BLE001 - a judge failure is non-fatal
                ctx.progress(self.name, judge_error=str(exc))
        return judged

    def _write_finding_files(self, ctx: RunContext, findings: list[Finding]) -> None:
        """One JSON file per finding — the dashboard's per-issue page source."""
        import json

        directory = ctx.findings_dir
        for existing in directory.glob("*.json"):
            existing.unlink()  # re-adjudication replaces the finding set cleanly
        for finding in findings:
            path = directory / f"{finding.id}.json"
            path.write_text(
                json.dumps(finding.to_dict(run_id=ctx.run_id), indent=2, default=str),
                encoding="utf-8",
            )


def _stronger(candidate: dict[str, Any], current: dict[str, Any]) -> bool:
    """A confirmation beats a signal; otherwise keep the first seen."""
    return candidate["verdict"] == Verdict.CONFIRMED and current["verdict"] != Verdict.CONFIRMED


def _finding_id(operation: str, class_id: str, state: FindingState) -> str:
    prefix = "f" if state is FindingState.CONFIRMED else "p"
    safe_op = "".join(ch if ch.isalnum() else "_" for ch in operation)
    return f"{prefix}_{safe_op}_{class_id}"


def _counts_by_class(findings: list[Finding]) -> dict[str, dict[str, int]]:
    counts: dict[str, dict[str, int]] = {}
    for finding in findings:
        bucket = counts.setdefault(finding.class_id, {"confirmed": 0, "potential": 0})
        bucket[str(finding.state)] += 1
    return counts
