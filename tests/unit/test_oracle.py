"""Evidence oracle: confirmation is deterministic, differential, and picky."""

from __future__ import annotations

from prediql.oracle.evidence import Expectation, Oracle, Verdict
from prediql.scoring.classes import Evidence
from prediql.targets.base import HttpResult


def _result(body=None, *, elapsed=10.0, status=200, error=None):
    return HttpResult(document="q", identity="anon", status=status, body=body,
                      elapsed_ms=elapsed, error=error)


BASELINE = {"latency_median_ms": 12.0, "latency_mad_ms": 3.0, "negative_control": {"data": {"x": 1}}}


# --------------------------------------------------------------------------
# Sentinel — the strongest evidence
# --------------------------------------------------------------------------


def test_sentinel_in_response_confirms():
    """OS-command: the echoed token proves the command executed."""
    oracle = Oracle()
    exp = Expectation("os_command_injection", Evidence.SENTINEL, sentinel="PQL_9f3a")
    judgement = oracle.judge(exp, _result({"data": {"run": "PQL_9f3a\n"}}))
    assert judgement.verdict is Verdict.CONFIRMED
    assert judgement.evidence is Evidence.SENTINEL
    assert "PQL_9f3a" in judgement.witness.matched


def test_path_traversal_confirmed_by_file_content_not_reflection():
    """GraphQLer's documented gap: reflection is not leakage."""
    oracle = Oracle()
    exp = Expectation("path_traversal", Evidence.SENTINEL, sentinel="root:x:0:0")
    leaked = oracle.judge(exp, _result({"data": {"readFile": "root:x:0:0:root:/root"}}))
    assert leaked.verdict is Verdict.CONFIRMED

    # The path is reflected (marker) but the file content (sentinel) is absent:
    # a signal, never a confirmation.
    reflected = Expectation("path_traversal", Evidence.SENTINEL,
                            sentinel="root:x:0:0", marker="/etc/passwd")
    echoed = oracle.judge(reflected, _result({"errors": [{"message": "cannot open /etc/passwd"}]}))
    assert echoed.verdict is Verdict.SIGNAL
    assert echoed.evidence is Evidence.REFLECTION


def test_sentinel_absent_is_nothing():
    oracle = Oracle()
    exp = Expectation("os_command_injection", Evidence.SENTINEL, sentinel="PQL_x")
    assert oracle.judge(exp, _result({"data": {"run": "ok"}})).verdict is Verdict.NOTHING


# --------------------------------------------------------------------------
# Latency — time-based, against the baseline
# --------------------------------------------------------------------------


def test_latency_beyond_baseline_confirms_sqli():
    oracle = Oracle()
    exp = Expectation("sql_injection", Evidence.LATENCY, stage="time-based")
    slow = oracle.judge(exp, _result({"data": {"x": 1}}, elapsed=5000.0), baseline=BASELINE)
    assert slow.verdict is Verdict.CONFIRMED
    assert slow.witness.latency_ms == 5000.0


def test_ordinary_jitter_does_not_confirm_latency():
    """The MAD floor stops a low-variance baseline from flagging noise."""
    oracle = Oracle()
    exp = Expectation("sql_injection", Evidence.LATENCY)
    normal = oracle.judge(exp, _result({"data": {"x": 1}}, elapsed=30.0), baseline=BASELINE)
    assert normal.verdict is Verdict.NOTHING


def test_latency_without_a_baseline_cannot_confirm():
    oracle = Oracle()
    exp = Expectation("sql_injection", Evidence.LATENCY)
    assert oracle.judge(exp, _result({"data": {}}, elapsed=9999.0)).verdict is Verdict.NOTHING


# --------------------------------------------------------------------------
# Signals — error signatures and reflection drive refinement, never confirm alone
# --------------------------------------------------------------------------


def test_db_error_signature_is_a_signal_not_a_confirmation():
    oracle = Oracle()
    exp = Expectation("sql_injection", Evidence.DIFFERENTIAL, stage="error-based")
    judged = oracle.judge(
        exp, _result({"errors": [{"message": "sqlite3.OperationalError: unrecognized token"}]}),
        baseline=BASELINE,
    )
    assert judged.verdict is Verdict.SIGNAL
    assert judged.evidence is Evidence.ERROR_SIGNATURE
    assert judged.witness.differential["control_clean"] is True


def test_reflection_alone_is_only_a_signal():
    """Picky by design (doc 09 §4): a JSON API echoing a string is not XSS."""
    oracle = Oracle()
    exp = Expectation("xss_reflected", Evidence.REFLECTION, marker="<script>PQL</script>")
    judged = oracle.judge(exp, _result({"data": {"echo": "<script>PQL</script>"}}))
    assert judged.verdict is Verdict.SIGNAL
    assert judged.evidence is Evidence.REFLECTION


# --------------------------------------------------------------------------
# The registry is authoritative
# --------------------------------------------------------------------------


def test_evidence_a_class_does_not_accept_cannot_confirm_it():
    """Latency confirms SQLi but must not confirm path traversal."""
    oracle = Oracle()
    exp = Expectation("path_traversal", Evidence.LATENCY)
    judged = oracle.judge(exp, _result({"data": {}}, elapsed=9999.0), baseline=BASELINE)
    assert judged.verdict is not Verdict.CONFIRMED


def test_read_only_success_manufactures_nothing():
    """The anti-'2,130 findings' invariant, at the oracle level."""
    oracle = Oracle()
    for evidence in (Evidence.SENTINEL, Evidence.LATENCY, Evidence.DIFFERENTIAL):
        exp = Expectation("sql_injection", evidence, sentinel="never")
        clean = oracle.judge(exp, _result({"data": {"country": {"name": "Canada"}}}),
                             baseline=BASELINE)
        assert clean.verdict is Verdict.NOTHING


def test_marker_reflection_cannot_be_mistaken_for_a_sentinel():
    """An echoed payload must not confirm just because it contains the marker."""
    oracle = Oracle()
    # oscmd sentinel is a computed value; the payload (marker) echoes but the
    # computed result does not appear -> not confirmed.
    exp = Expectation("os_command_injection", Evidence.SENTINEL,
                      sentinel="273819", marker="; echo $((91273*3))")
    echoed = oracle.judge(exp, _result({"data": {"run": "; echo $((91273*3))"}}))
    assert echoed.verdict is Verdict.SIGNAL, "reflection of the input is not execution"
    # When the computed result actually appears, the command really ran.
    executed = oracle.judge(exp, _result({"data": {"run": "273819\n"}}))
    assert executed.verdict is Verdict.CONFIRMED


# --------------------------------------------------------------------------
# DoS — super-linear only; a bigger query being proportionally slower is fine
# --------------------------------------------------------------------------


def test_dos_super_linear_is_a_signal_not_a_confirmation():
    """Timing under concurrent probing is confounded; DoS is potential, not proof."""
    oracle = Oracle()
    exp = Expectation("denial_of_service", Evidence.DOS, amplification=50, stage="alias-overload")
    base = {"latency_median_ms": 170.0, "latency_mad_ms": 20.0}

    # 129x for 50 aliases -> past the linear expectation -> a signal, with the
    # amplification measured for the analyst.
    superlinear = oracle.judge(exp, _result({"data": {}}, elapsed=22000.0), baseline=base)
    assert superlinear.verdict is Verdict.SIGNAL
    assert "super-linear" in superlinear.witness.matched

    # Sub-linear -> not even a signal.
    sublinear = oracle.judge(exp, _result({"data": {}}, elapsed=3400.0), baseline=base)
    assert sublinear.verdict is Verdict.NOTHING


def test_dos_respects_an_absolute_floor():
    """A fast tiny API must not trip on sub-second noise even if super-linear."""
    oracle = Oracle()
    exp = Expectation("denial_of_service", Evidence.DOS, amplification=50)
    base = {"latency_median_ms": 2.0, "latency_mad_ms": 1.0}
    # 500ms is 5x the 100ms linear expectation, but under the 1s absolute floor.
    judged = oracle.judge(exp, _result({"data": {}}, elapsed=500.0), baseline=base)
    assert judged.verdict is Verdict.NOTHING
