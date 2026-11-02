"""Probe-family plugin interface (doc 02 §3a, doc 07 §2).

Each vulnerability class is a family: an applicability predicate, declared
preconditions, seed payloads, and an evidence-directed refinement rule. Families
share the dependency graph and the objects bucket but carry independent
detection logic, so disabling one (``--families``) removes exactly its findings —
which is also the RQ3 ablation.

A family never confirms anything itself; it only proposes payloads and says what
evidence would confirm them. The oracle (deterministic) decides. That division
is what keeps detection honest.
"""

from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass
from typing import ClassVar

from prediql.generation.query_builder import build_operation, default_argument
from prediql.model.graph import DependencyGraph
from prediql.model.schema import Operation, Schema
from prediql.oracle.evidence import Expectation

# Scalar argument types that can carry an injected string payload.
INJECTABLE_SCALARS = frozenset({"String", "ID"})
# Built-in scalars that CANNOT: GraphQL validates a Boolean/Int/Float literal
# against its type before the resolver runs, so a string payload is rejected at
# the type layer and never reaches a sink. Probing them only wastes the
# per-operation payload budget (and can starve the real String/ID target), so
# they are excluded while custom scalars — which usually serialise as strings —
# stay injectable.
_NON_INJECTABLE_SCALARS = frozenset({"Boolean", "Int", "Float"})


@dataclass(frozen=True, slots=True)
class Payload:
    """One probe: a document to send and what would confirm it."""

    operation: str
    document: str
    expectation: Expectation
    argument: str = ""
    """The argument the payload was injected into (for the reasoning trace)."""

    @property
    def class_id(self) -> str:
        return self.expectation.class_id

    @property
    def stage(self) -> str:
        return self.expectation.stage


@dataclass
class Observation:
    """A payload's outcome, as the loop accumulates evidence."""

    payload: Payload
    verdict: str
    evidence: str | None
    detail: str
    elapsed_ms: float
    body_present: bool
    body: dict | None = None
    """The response data, kept for families that confirm by comparing two
    payloads' responses (e.g. boolean SQLi: tautology vs contradiction)."""


def unique_token(prefix: str = "PQL") -> str:
    """A collision-free marker for one probe (8 hex chars is plenty here)."""
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def injectable_arguments(
    operation: Operation, schema: Schema, exclude: frozenset[str] | set[str] = frozenset()
) -> list[str]:
    """String/ID arguments a payload can be injected into.

    An operation with none is not injectable, so injection families skip it —
    the applicability predicate that keeps most families off most operations.

    ``exclude`` drops argument *names* that should not be fuzzed — notably the
    authenticated tester's declared credentials: those are how the probe
    authenticates, not what it attacks, so injecting into them wastes the
    per-operation budget (and can starve the real target, e.g. a gated
    ``cmd``) and is not the vulnerability under test.
    """
    result: list[str] = []
    for name, ref in operation.args:
        if name in exclude:
            continue
        base = schema.type(ref.name)
        injectable_scalar = (
            base is not None
            and base.kind == "SCALAR"
            and ref.name not in _NON_INJECTABLE_SCALARS
        )
        if ref.name in INJECTABLE_SCALARS or injectable_scalar:
            result.append(name)
    return result


class ProbeFamily(abc.ABC):
    """Base class for a vulnerability probe family."""

    id: ClassVar[str] = ""
    """Canonical class id from :mod:`prediql.scoring.classes`."""

    oob: object | None = None
    """Set by the registry when an out-of-band collaborator is configured. A
    family that can plant a callback (SSRF, blind OS-command) uses it to mint a
    token+URL; when it is ``None`` those payloads are skipped (default behaviour
    is unchanged for runs without an OOB server)."""

    auth_args: ClassVar[dict[str, str]] = {}
    """Authenticated tester's known argument values (e.g. credentials), set by the
    registry. ``_inject`` uses them to fill a non-injected *required* argument
    whose name matches, so a probe can pass a resolver's credential gate. Empty by
    default, so an unauthenticated run behaves exactly as before. Assigned
    per-instance by :func:`build_families`, never mutated in place here."""

    #: Max evidence-directed refinement rounds before the loop gives up. A dead
    #: probe stops after the seed round; only a live signal earns more.
    max_rounds: ClassVar[int] = 3

    def applies(self, operation: Operation, schema: Schema, graph: DependencyGraph) -> bool:
        """Whether this family should probe ``operation`` at all."""
        return bool(self.injectable(operation, schema))

    def injectable(self, operation: Operation, schema: Schema) -> list[str]:
        """Argument names this family should inject into — the injectable scalars
        minus the authenticated tester's declared credentials, which are supplied
        intact (not fuzzed). Families inject over this, not ``injectable_arguments``
        directly, so credentials never consume the per-operation budget."""
        return injectable_arguments(operation, schema, exclude=set(self.auth_args))

    def preconditions(self) -> list[str]:
        """Input fields that must be satisfiable before probing. Usually none."""
        return []

    @abc.abstractmethod
    def seed_payloads(self, operation: Operation, schema: Schema) -> list[Payload]:
        """Initial probes to try."""

    def refine(
        self, operation: Operation, schema: Schema, observations: list[Observation]
    ) -> list[Payload]:
        """Evidence-directed follow-ups. Empty means "no further escalation".

        The default escalates nothing; families that have a second stage (SQLi
        error-based → time-based) override this.
        """
        return []

    def differential_confirm(
        self, observations: list[Observation]
    ) -> tuple[Payload, str] | None:
        """Confirm by comparing *two* payloads' responses, which the per-payload
        oracle cannot (e.g. boolean SQLi: a tautology that returns strictly more
        than its paired contradiction). Returns the confirming payload and a
        witness detail, or ``None``. Default: no pairwise test."""
        return None

    # -- helpers for subclasses ------------------------------------------

    def _inject(
        self,
        operation: Operation,
        schema: Schema,
        argument: str,
        value: str,
        expectation: Expectation,
    ) -> Payload:
        """Build a document with ``value`` substituted into one argument.

        Other required arguments get benign defaults, so the payload differs
        from a valid request in exactly the injected field — which is what lets
        the oracle attribute any difference to the payload.
        """
        args: dict[str, object] = {}
        for name, ref in operation.args:
            if name == argument:
                args[name] = value
            elif name in self.auth_args:
                # Authenticated-scan credential (e.g. username/password): use the
                # tester's known-good value so the payload clears a resolver gate
                # instead of being rejected before it reaches the sink.
                args[name] = self.auth_args[name]
            elif ref.non_null:
                args[name] = default_argument(ref, schema)
        document = build_operation(schema, operation, args=args, depth=1, style="minimal")
        return Payload(operation.name, document, expectation, argument=argument)

    def _inject_many(
        self,
        operation: Operation,
        schema: Schema,
        values: dict[str, object],
        expectation: Expectation,
        *,
        argument: str,
    ) -> Payload:
        """Like :meth:`_inject`, but set a coherent *group* of arguments.

        For a resolver that assembles a URL from separate ``scheme``/``host``/
        ``path`` arguments, injecting a whole URL into one of them produces a
        malformed address that is never dereferenced. ``values`` supplies the
        whole group so the resolver builds a valid callback; ``argument`` names
        the group for the witness.
        """
        args: dict[str, object] = dict(values)
        for name, ref in operation.args:
            if name not in args and ref.non_null:
                args[name] = default_argument(ref, schema)
        document = build_operation(schema, operation, args=args, depth=1, style="minimal")
        return Payload(operation.name, document, expectation, argument=argument)
