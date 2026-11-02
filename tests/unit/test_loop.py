"""The iterative refinement loop: bounded, evidence-directed, honest stops."""

from __future__ import annotations

import pytest

from prediql.model.schema import from_introspection
from prediql.oracle.evidence import Oracle
from prediql.security.families.sqli import SqlInjectionFamily
from prediql.security.loop import run_family
from prediql.targets.base import HttpResult

SCHEMA = from_introspection({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "search", "type": {"kind": "OBJECT", "name": "Post"},
             "args": [{"name": "q", "type": {"kind": "NON_NULL",
                                             "ofType": {"kind": "SCALAR", "name": "String"}}}]}]},
        {"name": "Post", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []}]},
    ]}}})
OP = SCHEMA.operations["search"]
BASELINE = {"latency_median_ms": 12.0, "latency_mad_ms": 3.0, "negative_control": {"data": {}}}


def _executor(responder):
    """Wrap a plain function into the async executor the loop expects."""
    async def execute(document: str) -> HttpResult:
        return responder(document)
    return execute


async def test_clean_responses_confirm_nothing():
    """The anti-false-positive property, end to end through the loop."""
    async def clean(document):
        return HttpResult(document=document, identity="anon", status=200,
                          body={"data": {"search": {"id": "1"}}}, elapsed_ms=11.0)

    outcome = await run_family(SqlInjectionFamily(), OP, SCHEMA, executor=clean,
                               oracle=Oracle(), identity="anon", baseline=BASELINE,
                               max_payloads=50)
    assert not outcome.confirmed
    assert outcome.confirmations == []
    assert outcome.stop_reason in ("no_refinement", "round_cap", "converged_no_new_signal")


async def test_error_then_time_delay_confirms_via_refinement():
    """The signature signal must escalate to a confirming time-based payload."""
    def responder(document):
        if "sleep" in document.lower() or "pg_sleep" in document.lower():
            return HttpResult(document=document, identity="anon", status=200,
                              body={"data": {"search": None}}, elapsed_ms=5200.0)
        if "'" in document:  # syntax breaker provokes a DB error
            return HttpResult(document=document, identity="anon", status=200,
                              body={"errors": [{"message": "sqlite3.OperationalError: near"}]},
                              elapsed_ms=10.0)
        return HttpResult(document=document, identity="anon", status=200,
                          body={"data": {"search": {"id": "1"}}}, elapsed_ms=10.0)

    outcome = await run_family(SqlInjectionFamily(), OP, SCHEMA, executor=_executor(responder),
                               oracle=Oracle(), identity="anon", baseline=BASELINE,
                               max_payloads=50)
    assert outcome.confirmed, outcome.stop_reason
    assert outcome.stop_reason == "confirmed"
    assert outcome.rounds >= 2, "confirmation required a refinement round"
    confirmation = outcome.confirmations[0]
    assert confirmation.evidence == "latency"
    assert confirmation.stage == "time-based"


async def test_error_signal_without_a_working_escalation_stays_a_signal():
    """An error that never leads to a confirmation is reported, not inflated."""
    def responder(document):
        # Every payload provokes an error, but the time-based ones are NOT slow.
        return HttpResult(document=document, identity="anon", status=200,
                          body={"errors": [{"message": "SQLSTATE[42000] syntax error"}]},
                          elapsed_ms=10.0)

    outcome = await run_family(SqlInjectionFamily(), OP, SCHEMA, executor=_executor(responder),
                               oracle=Oracle(), identity="anon", baseline=BASELINE,
                               max_payloads=50)
    assert not outcome.confirmed
    assert outcome.signals, "the error signal is still recorded"
    assert all(s.verdict == "signal" for s in outcome.signals)


async def test_payload_budget_is_respected():
    async def clean(document):
        return HttpResult(document=document, identity="anon", status=200,
                          body={"data": {"search": {"id": "1"}}}, elapsed_ms=11.0)

    outcome = await run_family(SqlInjectionFamily(), OP, SCHEMA, executor=clean,
                               oracle=Oracle(), identity="anon", baseline=BASELINE,
                               max_payloads=2)
    assert outcome.payloads_sent == 2
    assert outcome.stop_reason == "payload_budget"


async def test_the_same_document_is_never_sent_twice():
    sent: list[str] = []

    async def record(document):
        sent.append(document)
        return HttpResult(document=document, identity="anon", status=200,
                          body={"data": {"search": {"id": "1"}}}, elapsed_ms=11.0)

    await run_family(SqlInjectionFamily(), OP, SCHEMA, executor=record,
                     oracle=Oracle(), identity="anon", baseline=BASELINE, max_payloads=50)
    assert len(sent) == len(set(sent)), "the loop must dedupe payloads it has already tried"


async def test_every_result_carries_a_trace_for_the_dashboard():
    """The 'security fuzzing inputs + reasoning' the brief asks to surface."""
    async def clean(document):
        return HttpResult(document=document, identity="anon", status=200,
                          body={"data": {"search": {"id": "1"}}}, elapsed_ms=11.0)

    outcome = await run_family(SqlInjectionFamily(), OP, SCHEMA, executor=clean,
                               oracle=Oracle(), identity="anon", baseline=BASELINE,
                               max_payloads=50)
    assert outcome.results
    for result in outcome.results:
        record = result.to_dict()
        assert record["document"] and record["stage"] and record["verdict"]
        assert record["operation"] == "search"


async def test_one_confirmation_does_not_hide_the_familys_other_class():
    """Introspection confirming must not stop the field-suggestion probe."""
    from prediql.security.families.introspection import IntrospectionFamily

    sent: list[str] = []

    def responder(document):
        sent.append(document)
        if "__schema" in document:
            body = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
        else:
            body = {"errors": [{"message": 'Cannot query field "__thisFieldDoesNotExist". '
                                           'Did you mean "search"?'}]}
        return HttpResult(document=document, identity="anon", status=200, body=body,
                          elapsed_ms=10.0)

    outcome = await run_family(IntrospectionFamily(), OP, SCHEMA, executor=_executor(responder),
                               oracle=Oracle(), identity="anon", baseline=BASELINE,
                               max_payloads=10)
    assert len(sent) == 2
    assert {c.class_id for c in outcome.confirmations} == {"introspection_enabled",
                                                           "field_suggestion"}
