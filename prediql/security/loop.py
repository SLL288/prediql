"""The iterative refinement loop (doc 02 §3).

For one (operation, family): seed payloads, execute, observe, and either confirm
or refine — bounded, evidence-directed, with every stop reason recorded. This is
the single behavioural change from v1's one-shot Stage 3.

The loop calls the deterministic oracle to decide confirm/refine/stop, and
records the full trace (every payload, its verdict, the reasoning) as
``ProbeResult`` objects. It emits *evidence*, not final findings: turning
signals into potential findings and consulting an optional judge is
``adjudicate``'s job, so the loop stays deterministic and re-runnable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from prediql.oracle.evidence import Judgement, Oracle, Verdict
from prediql.scoring.classes import Evidence
from prediql.oracle.witness import RequestRecord, Witness
from prediql.security.families.base import Observation, Payload, ProbeFamily
from prediql.model.schema import Operation, Schema
from prediql.targets.base import HttpResult

# Executes one payload document under an identity; supplied by the probe step so
# the loop itself never touches the network or the concurrency limiter.
Executor = Callable[[str], Awaitable[HttpResult]]


@dataclass
class ProbeResult:
    """One executed payload and the oracle's verdict on it."""

    operation: str
    class_id: str
    family: str
    stage: str
    argument: str
    document: str
    identity: str
    verdict: str
    evidence: str | None
    detail: str
    witness: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "class_id": self.class_id,
            "family": self.family,
            "stage": self.stage,
            "argument": self.argument,
            "document": self.document,
            "identity": self.identity,
            "verdict": self.verdict,
            "evidence": self.evidence,
            "detail": self.detail,
            "witness": self.witness,
        }


@dataclass
class LoopOutcome:
    """What one (operation, family) run produced."""

    operation: str
    family: str
    results: list[ProbeResult] = field(default_factory=list)
    confirmed: bool = False
    stop_reason: str = ""
    rounds: int = 0
    payloads_sent: int = 0

    @property
    def signals(self) -> list[ProbeResult]:
        return [r for r in self.results if r.verdict == Verdict.SIGNAL]

    @property
    def confirmations(self) -> list[ProbeResult]:
        return [r for r in self.results if r.verdict == Verdict.CONFIRMED]


async def run_family(
    family: ProbeFamily,
    operation: Operation,
    schema: Schema,
    *,
    executor: Executor,
    oracle: Oracle,
    identity: str,
    baseline: dict[str, Any] | None,
    max_payloads: int,
) -> LoopOutcome:
    """Drive one family against one operation to a bounded fixpoint.

    Stops on the first of: every class the family probes here is confirmed,
    two consecutive refinement rounds with no new signal, the family's round
    cap, or the per-operation payload budget. The stop reason is always
    recorded. Most families probe one class, so their first confirmation ends
    the loop; a family probing several (introspection and field suggestion)
    keeps going until each is settled, instead of letting one confirmation hide
    the others.
    """
    outcome = LoopOutcome(operation=operation.name, family=family.id)
    observations: list[Observation] = []
    payloads = family.seed_payloads(operation, schema)
    seen_documents: set[str] = set()
    targeted = {p.expectation.class_id for p in payloads}
    confirmed_classes: set[str] = set()
    quiet_rounds = 0

    for round_index in range(family.max_rounds):
        outcome.rounds = round_index + 1
        signals_before = len(observations)

        for payload in payloads:
            if outcome.payloads_sent >= max_payloads:
                outcome.stop_reason = "payload_budget"
                return outcome
            if payload.document in seen_documents or payload.expectation.class_id in confirmed_classes:
                continue
            seen_documents.add(payload.document)

            result = await executor(payload.document)
            outcome.payloads_sent += 1
            judgement = oracle.judge(payload.expectation, result, baseline=baseline)
            outcome.results.append(_record(payload, identity, judgement))
            observations.append(_observe(payload, judgement, result))

            if judgement.confirmed:
                outcome.confirmed = True
                confirmed_classes.add(payload.expectation.class_id)
                if targeted <= confirmed_classes:
                    outcome.stop_reason = "confirmed"
                    return outcome

        # Pairwise confirmation (e.g. boolean SQLi: tautology vs contradiction),
        # which the per-payload oracle cannot see.
        pairwise = family.differential_confirm(observations)
        if pairwise is not None and pairwise[0].expectation.class_id not in confirmed_classes:
            payload, detail = pairwise
            request = RequestRecord(payload.document, identity, {})
            judgement = Judgement(Verdict.CONFIRMED, Evidence.DIFFERENTIAL,
                                  witness=Witness((request,), matched=detail), detail=detail)
            outcome.results.append(_record(payload, identity, judgement))
            outcome.confirmed = True
            confirmed_classes.add(payload.expectation.class_id)
            if targeted <= confirmed_classes:
                outcome.stop_reason = "confirmed"
                return outcome

        # Evidence-directed refinement from everything seen so far, for the
        # classes still open.
        payloads = [p for p in family.refine(operation, schema, observations)
                    if p.expectation.class_id not in confirmed_classes]
        targeted |= {p.expectation.class_id for p in payloads}
        new_signals = sum(
            1 for o in observations[signals_before:] if o.verdict == Verdict.SIGNAL
        )
        if not payloads:
            outcome.stop_reason = "confirmed" if outcome.confirmed else "no_refinement"
            return outcome
        quiet_rounds = quiet_rounds + 1 if new_signals == 0 else 0
        if quiet_rounds >= 2:
            outcome.stop_reason = "converged_no_new_signal"
            return outcome

    outcome.stop_reason = "round_cap"
    return outcome


def _record(payload: Payload, identity: str, judgement: Judgement) -> ProbeResult:
    return ProbeResult(
        operation=payload.operation,
        class_id=payload.class_id,
        family=payload.expectation.class_id,
        stage=payload.stage,
        argument=payload.argument,
        document=payload.document,
        identity=identity,
        verdict=str(judgement.verdict),
        evidence=str(judgement.evidence) if judgement.evidence else None,
        detail=judgement.detail,
        witness=judgement.witness.to_dict() if judgement.witness else None,
    )


def _observe(payload: Payload, judgement: Judgement, result: HttpResult) -> Observation:
    return Observation(
        payload=payload,
        verdict=str(judgement.verdict),
        evidence=str(judgement.evidence) if judgement.evidence else None,
        detail=judgement.detail,
        elapsed_ms=result.elapsed_ms,
        body_present=result.body is not None,
        body=result.body if isinstance(result.body, dict) else None,
    )
