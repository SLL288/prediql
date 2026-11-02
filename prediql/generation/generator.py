"""Candidate query generation.

Two implementations behind one protocol:

* :class:`HeuristicGenerator` — schema-driven, no LLM. It is both the
  ``BASE`` ablation arm (GraphQLer-parity, reproducible, zero token cost) and
  what makes the pipeline runnable and testable offline.
* ``LLMGenerator`` (M1) — structured-output generation through the provider
  router, seeded by retrieval and the objects bucket.

The split matters for the paper: every LLM claim is measured against a real
non-LLM baseline that shares the same executor, so a coverage difference is
attributable to generation rather than to plumbing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from prediql.generation.bandit import Arm
from prediql.generation.query_builder import SelectionError, build_operation, default_argument
from prediql.model.bucket import ObjectsBucket
from prediql.model.schema import Operation, Schema


@dataclass(frozen=True, slots=True)
class Candidate:
    """One executable document proposed for an operation."""

    operation: str
    document: str
    arm: str
    source: str = "heuristic"
    rationale: str = ""
    args: dict[str, Any] = field(default_factory=dict)


class CandidateGenerator(Protocol):
    """Produces candidate documents for one operation under one arm."""

    name: str

    async def generate(
        self,
        *,
        schema: Schema,
        operation: Operation,
        arm: Arm,
        bucket: ObjectsBucket,
        context: dict[str, Any] | None = None,
    ) -> list[Candidate]:
        ...


class HeuristicGenerator:
    """Schema-driven generation with no model in the loop.

    Argument values come from the objects bucket first (a real identifier
    observed earlier), falling back to type-shaped placeholders. That ordering is
    the point: GraphQLer's paper names random scalar values as a root cause of
    unreachable operations, and reusing observed values is the cheap half of the
    fix.
    """

    name = "heuristic"

    async def generate(
        self,
        *,
        schema: Schema,
        operation: Operation,
        arm: Arm,
        bucket: ObjectsBucket,
        context: dict[str, Any] | None = None,
    ) -> list[Candidate]:
        required = frozenset((context or {}).get("required_args", ()))
        args = self._arguments(schema, operation, bucket, arm, required)
        cap = (context or {}).get("max_candidates", arm.n_candidates)
        styles = ("minimal", "maximal") if arm.n_candidates > 1 and cap > 1 else ("minimal",)
        candidates: list[Candidate] = []
        for style in styles[: max(1, arm.n_candidates)]:
            try:
                document = build_operation(
                    schema, operation, args=args, depth=max(1, arm.depth), style=style
                )
            except SelectionError:
                continue
            candidates.append(
                Candidate(
                    operation=operation.name,
                    document=document,
                    arm=arm.name,
                    source=self.name,
                    rationale=f"{style} selection at depth {arm.depth}",
                    args=args,
                )
            )
        return candidates

    @staticmethod
    def _arguments(
        schema: Schema, operation: Operation, bucket: ObjectsBucket, arm: Arm,
        required: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        """Resolve an operation's arguments.

        One rule, applied per argument:

        1. an **observed** value (from the objects bucket) is always preferred;
        2. otherwise a **required** argument gets the best type-correct
           placeholder that can be constructed. Required means non-null in the
           schema, or named by the server as missing on an earlier attempt
           (``required``) — a schema can declare optional what a resolver needs;
        3. otherwise the argument is **omitted**.

        Rule 3 is deliberate. A placeholder in an optional slot buys nothing —
        the server would have defaulted it anyway — while risking a validation
        rejection that fails the entire document. Minimally-valid payloads are
        the point, so an optional argument we cannot fill with a real value is
        simply left out.
        """
        args: dict[str, Any] = {}
        for name, ref in operation.args:
            observed = (
                HeuristicGenerator._observed_value(schema, operation, name, bucket)
                if arm.arg_mode in ("real", "known")
                else None
            )
            if observed is not None:
                args[name] = observed
            elif ref.non_null or name in required:
                args[name] = default_argument(ref, schema)
        return args

    @staticmethod
    def _observed_value(
        schema: Schema, operation: Operation, arg_name: str, bucket: ObjectsBucket
    ) -> Any | None:
        """Find a real value for ``arg_name`` among resources already observed.

        Two resolution rules, tried in order:

        1. **By argument name** — ``userId`` refers to a ``User``, so use a known
           ``User`` identifier (GraphQLer's ID-matching ladder).
        2. **By return type field** — an argument named ``X`` on an operation
           returning ``T`` is usually ``T.X``: ``continent(code:)`` returns a
           ``Continent``, which has a ``code`` field, so a ``Continent`` observed
           earlier supplies a real code.

        Rule 2 matters more than it looks. Without it every lookup-by-natural-key
        operation is unreachable, because the argument name resolves to no object
        type and the fallback placeholder never matches a real record — the
        "scalar materialization" gap GraphQLer's paper names as a cause of
        unreachable operations.
        """
        from prediql.model.graph import _candidate_object_name, resolve_object

        # Rule 2 runs first because it is *exact*: the operation's declared
        # return type genuinely has a field with this name, so an observed value
        # of that field is the right shape by construction. Rule 1 is a fuzzy
        # name match and must not preempt it — `code` on an operation returning
        # `Continent` is within edit distance of `Country`, and letting that win
        # feeds a country code to a continent lookup.
        return_type = schema.type(operation.type.name)
        if return_type is not None and return_type.field(arg_name) is not None:
            value = bucket.field_value(operation.type.name, arg_name)
            if value is not None:
                return value

        # Rule 1: the argument name points at an object type (`userId` -> User).
        target = resolve_object(_candidate_object_name(arg_name, operation), schema)
        if target:
            identifier = bucket.any_id(target)
            if identifier is not None:
                return identifier
        return None
