"""The evidence oracle (doc 04 §4).

Confirmation is **deterministic and differential**, never an LLM opinion. The
oracle takes what a probe expected to see and what actually came back, and
returns one of three verdicts:

* ``CONFIRMED`` — a confirming evidence kind matched (a sentinel appeared, a
  latency delta held, a controlled difference showed). Carries a witness.
* ``SIGNAL`` — something suggestive but not conclusive (a payload reflected, an
  error signature surfaced). Drives refinement; becomes a *potential* finding.
* ``NOTHING`` — no evidence.

This is the mechanism that answers "2,130 findings on a read-only Pokédex": with
no write, no differential, and no sentinel, the oracle returns ``NOTHING`` and
the loop emits no finding.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from prediql.oracle.witness import RequestRecord, Witness
from prediql.scoring.classes import Evidence, confirms
from prediql.targets.base import HttpResult

# Latency confirmation: elapsed must exceed median + K·MAD. K=6 with a MAD floor
# keeps a low-variance baseline from flagging ordinary jitter as a finding.
LATENCY_K = 6.0
LATENCY_MAD_FLOOR_MS = 20.0
# DoS must also clear an absolute floor, so a sub-second API cannot trip on noise.
DOS_FLOOR_MS = 1000.0

# Generic DB-error signatures, spanning engines — a *signal*, not a confirmation.
# Deliberately vendor-generic (doc 02 §3a): these are OWASP-class patterns, not
# a target's strings.
_DB_ERROR_SIGNATURES = (
    r"sql syntax", r"sqlite3?\.\w*error", r"sqlite_", r"psql:", r"pg::\w+",
    r"postgresql", r"mysql_fetch", r"you have an error in your sql",
    r"unclosed quotation mark", r"quoted string not properly terminated",
    r"ora-\d{5}", r"odbc", r"sqlstate", r"syntax error at or near",
    r"warning:\s+\w+_", r"unterminated quoted string",
)
_DB_ERROR_RE = re.compile("|".join(_DB_ERROR_SIGNATURES), re.IGNORECASE)


class Verdict(StrEnum):
    CONFIRMED = "confirmed"
    SIGNAL = "signal"
    NOTHING = "nothing"




@dataclass(frozen=True, slots=True)
class Expectation:
    """What a probe payload is looking for — supplied by the family.

    Two markers, deliberately distinct:

    * ``sentinel`` — content whose appearance **confirms**. It must be
      un-reflectable by construction: not a literal in the payload, but
      something only exploitation can produce (a file's contents, or the result
      of an injected computation like ``echo $((a*b))``). If the sentinel could
      appear merely because the server echoed the input, it is the wrong
      sentinel and would manufacture a false positive.
    * ``marker`` — the injected payload string itself, whose verbatim reflection
      is only a **signal** (a JSON API echoing a string is not, by itself, an
      exploit). Kept separate so reflection can never be mistaken for proof.
    """

    class_id: str
    evidence: Evidence
    sentinel: str = ""
    marker: str = ""
    token: str = ""
    """For CALLBACK evidence: the out-of-band token planted in the payload. The
    finding confirms iff the collaborator server received a request for it."""
    stage: str = "seed"
    """Which refinement stage produced the payload — kept for the reasoning trace."""

    amplification: int = 1
    """For DoS probes: how many times the injected query multiplies the work.

    A response merely being slower than a one-unit baseline is expected — the
    query is bigger. The *vulnerability* is super-linear cost: the server has no
    complexity limit, so the response time exceeds even the linear expectation
    (baseline x amplification). That is the only thing this confirms."""


@dataclass(frozen=True, slots=True)
class Judgement:
    """The oracle's decision about one executed payload."""

    verdict: Verdict
    evidence: Evidence | None = None
    witness: Witness | None = None
    detail: str = ""

    @property
    def confirmed(self) -> bool:
        return self.verdict is Verdict.CONFIRMED


def _body_text(result: HttpResult) -> str:
    """Response body as searchable text, errors included.

    Injection evidence often surfaces inside a GraphQL ``errors[]`` message, so
    the whole body is serialised rather than just ``data``.
    """
    if result.body is None:
        return result.error or ""
    return json.dumps(result.body, default=str)


class Oracle:
    """Deterministic evidence checker."""

    def __init__(self, *, latency_k: float = LATENCY_K, oob: Any = None) -> None:
        self.latency_k = latency_k
        self._oob = oob
        """Optional out-of-band collaborator with a ``seen(token) -> bool``; set
        when the run is configured with an OOB server, else callback probes can
        only ever be signals."""

    def judge(
        self,
        expectation: Expectation,
        payload_result: HttpResult,
        *,
        baseline: dict[str, Any] | None = None,
    ) -> Judgement:
        """Classify one payload's response into a verdict with a witness."""
        request = RequestRecord(payload_result.document, payload_result.identity,
                                payload_result.variables)
        body = _body_text(payload_result)

        # 1. Sentinel — a marker or known content we injected must appear.
        if expectation.evidence is Evidence.SENTINEL and expectation.sentinel:
            if expectation.sentinel in body:
                return self._confirm(
                    expectation, Evidence.SENTINEL, request, body,
                    matched=f"sentinel present: {expectation.sentinel!r}",
                )

        # 1b. Callback — an out-of-band request carrying our token reached the
        #     collaborator. The strongest, near-zero-FP proof for blind bugs:
        #     the token cannot be produced by anything but our payload executing.
        if expectation.evidence is Evidence.CALLBACK and expectation.token:
            if self._oob is not None and self._oob.seen(expectation.token):
                return self._confirm(
                    expectation, Evidence.CALLBACK, request, body,
                    matched=f"out-of-band callback received for token {expectation.token}",
                )

        # 1c. Configuration disclosure (introspection / field suggestions). These
        #     are differential by nature: a hardened endpoint refuses, a leaky one
        #     answers. Confirm on the answer itself — the type system came back, or
        #     the server offered a "did you mean" — not on a reflected marker.
        if expectation.evidence is Evidence.DIFFERENTIAL:
            data = payload_result.body.get("data") if isinstance(payload_result.body, dict) else None
            errs = payload_result.body.get("errors") if isinstance(payload_result.body, dict) else None
            if expectation.class_id == "introspection_enabled" and data and not errs \
                    and "queryType" in body:
                return self._confirm(
                    expectation, Evidence.DIFFERENTIAL, request, body,
                    matched="introspection enabled: __schema returned the type system",
                )
            if expectation.class_id == "field_suggestion" and re.search(r"did you mean", body, re.I):
                return self._confirm(
                    expectation, Evidence.DIFFERENTIAL, request, body,
                    matched="field suggestions enabled: server offered 'did you mean'",
                )

        # 2. Latency — a timing payload must exceed the operation's baseline.
        if expectation.evidence is Evidence.LATENCY and baseline:
            judged = self._judge_latency(expectation, payload_result, request, baseline)
            if judged is not None:
                return judged

        # 3. DoS — confirm only on *super-linear* amplification. A query with
        #    N aliases doing N times the work in ~N times the baseline is a
        #    well-behaved server, not a finding; exceeding the linear expectation
        #    is what shows a missing complexity limit.
        if expectation.evidence is Evidence.DOS and baseline:
            judged = self._judge_dos(expectation, payload_result, request, baseline)
            if judged is not None:
                return judged

        # 4. Reflection — the injected marker echoed verbatim. Signal only: a
        #    JSON API reflecting a string is not, by itself, an exploitable XSS.
        if expectation.marker and expectation.marker in body:
            return Judgement(
                Verdict.SIGNAL, Evidence.REFLECTION,
                witness=Witness((request,), matched="payload reflected verbatim",
                                response_excerpt=body),
                detail="reflected; needs a differential or a sink to confirm",
            )

        # 5. Error signature — a DB error the benign control did not provoke.
        #    Signal only (never a confirmation): a reflected DB error is exactly
        #    the weak evidence a looser tool would over-claim on. It drives
        #    refinement toward a *confirming* payload — a time-based delay, or a
        #    boolean tautology/contradiction cardinality differential.
        if _DB_ERROR_RE.search(body):
            differential = self._error_is_differential(baseline)
            return Judgement(
                Verdict.SIGNAL, Evidence.ERROR_SIGNATURE,
                witness=Witness((request,), matched="database error signature",
                                response_excerpt=body, differential=differential),
                detail="db error surfaced; refine to a confirming payload",
            )

        return Judgement(Verdict.NOTHING)

    # -- evidence kinds ---------------------------------------------------

    def _confirm(self, expectation, evidence, request, body, *, matched, **extra) -> Judgement:
        if not confirms(expectation.class_id, evidence):
            # A class that does not accept this evidence cannot be confirmed by
            # it, even if it matched — keeps the registry authoritative.
            return Judgement(Verdict.SIGNAL, evidence,
                             witness=Witness((request,), matched=matched, response_excerpt=body),
                             detail=f"{evidence} does not confirm {expectation.class_id}")
        return Judgement(
            Verdict.CONFIRMED, evidence,
            witness=Witness((request,), matched=matched, response_excerpt=body, **extra),
            detail=matched,
        )

    def _judge_dos(self, expectation, result, request, baseline):
        median = float(baseline.get("latency_median_ms", 0.0))
        factor = max(1, expectation.amplification)
        # Linear expectation for an amplification-N query, plus an absolute floor
        # so a fast tiny API cannot trip on sub-second noise.
        linear = median * factor
        if median <= 0 or result.elapsed_ms <= max(linear, DOS_FLOOR_MS):
            return None
        ratio = result.elapsed_ms / linear
        return self._confirm(
            expectation, Evidence.DOS, request, _body_text(result),
            matched=(f"super-linear cost: {result.elapsed_ms:.0f}ms is {ratio:.1f}x the linear "
                     f"expectation ({factor} x baseline {median:.0f}ms) — no complexity limit"),
            latency_ms=result.elapsed_ms, baseline_ms=median,
        )

    def _judge_latency(self, expectation, result, request, baseline, *, label="response time"):
        median = float(baseline.get("latency_median_ms", 0.0))
        mad = max(float(baseline.get("latency_mad_ms", 0.0)), LATENCY_MAD_FLOOR_MS)
        threshold = median + self.latency_k * mad
        if result.elapsed_ms > threshold and result.elapsed_ms > 0:
            return self._confirm(
                expectation, expectation.evidence, request, _body_text(result),
                matched=(f"{label} {result.elapsed_ms:.0f}ms > "
                         f"{threshold:.0f}ms (median {median:.0f} + {self.latency_k}·MAD {mad:.0f})"),
                latency_ms=result.elapsed_ms, baseline_ms=median,
            )
        return None

    @staticmethod
    def _error_is_differential(baseline: dict[str, Any] | None) -> dict[str, Any]:
        """Note whether the benign control was clean, strengthening an error signal."""
        if not baseline:
            return {}
        control = baseline.get("negative_control")
        control_text = json.dumps(control, default=str) if control else ""
        return {"control_clean": not _DB_ERROR_RE.search(control_text)}
