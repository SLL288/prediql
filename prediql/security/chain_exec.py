"""Chain execution and the disclosure oracle (doc 02 §4).

Runs a synthesized :class:`ChainPlan` step by step, carrying the created
resource's id forward, then judges the outcome. Confirmation is a **disclosure**:
the resource ends up somewhere it should not be — read by a second identity
(IDOR) or read after deletion (UAF). Like every oracle here it is deterministic
and differential, and it is picky: the chain must first *produce* a real private
resource, and the offending read must return *that specific resource*, not merely
succeed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from prediql.generation.query_builder import build_operation, default_argument
from prediql.model.bucket import ObjectsBucket
from prediql.model.schema import Operation, Schema
from prediql.oracle.witness import RequestRecord, Witness
from prediql.security.chains import ChainPlan, ChainStep
from prediql.targets.base import HttpResult, is_success

# Sends one document under a named identity; supplied by the step.
Sender = Callable[[str, str], Awaitable[HttpResult]]


@dataclass
class StepResult:
    """One executed chain step."""

    operation: str
    role: str
    identity: str
    document: str
    success: bool
    returned_id: Any = None
    post_delete: bool = False
    disclosed: bool = False
    """The response body actually referenced the tracked resource id — the
    difference between 'the read succeeded' and 'the read returned THIS resource',
    which is what stops a public listing from being mis-scored as disclosure."""
    marker_seen: bool = False
    """The stored-XSS marker planted at create time came back in this step's
    response — the read-back reflection that confirms stored XSS."""


@dataclass
class ChainResult:
    """An executed chain and the oracle's verdict."""

    chain_id: str
    strategy: str
    class_id: str
    operation: str          # the operation the finding is attributed to
    object_type: str
    verdict: str            # "confirmed" | "nothing" | "blocked" | "inconclusive"
    detail: str
    steps: list[StepResult] = field(default_factory=list)
    witness: dict[str, Any] | None = None
    identities: list[str] = field(default_factory=list)

    def to_probe_result(self) -> dict[str, Any]:
        """Render as a probe_result row, so adjudicate treats it uniformly."""
        return {
            "operation": self.operation,
            "class_id": self.class_id,
            "family": self.strategy,
            "stage": self.strategy,
            "argument": "",
            "document": " → ".join(s.document for s in self.steps),
            "identity": self.identities[-1] if self.identities else "",
            "verdict": "confirmed" if self.verdict == "confirmed" else
                       ("nothing" if self.verdict in ("nothing", "blocked") else "signal"),
            "evidence": "disclosure" if self.verdict == "confirmed" else None,
            "detail": self.detail,
            "witness": self.witness,
            "chain": [{"operation": s.operation, "identity": s.identity, "role": s.role}
                      for s in self.steps],
        }


async def execute_chain(
    plan: ChainPlan,
    schema: Schema,
    *,
    sender: Sender,
    identity_for_role: dict[str, str],
    bucket: ObjectsBucket,
) -> ChainResult:
    """Run one chain and judge it."""
    if plan.blocked:
        return ChainResult(
            plan.id, plan.strategy, plan.class_id, _target_op(plan), plan.object_type,
            verdict="blocked", detail=f"not executed: {plan.blocked}",
            identities=[],
        )

    result = ChainResult(plan.id, plan.strategy, plan.class_id, _target_op(plan),
                         plan.object_type, verdict="nothing", detail="")
    tracked_id: Any = None
    identities_used: list[str] = []
    marker = next((s.marker for s in plan.steps if s.marker), "")  # stored-XSS sentinel

    for step in plan.steps:
        operation = schema.operations.get(step.operation)
        if operation is None:
            result.verdict = "inconclusive"
            result.detail = f"operation {step.operation!r} not in schema"
            return result

        identity = identity_for_role.get(step.role, identity_for_role.get("primary", "anon"))
        identities_used.append(identity)
        document = _build_step_document(schema, operation, step, tracked_id, bucket)
        http = await sender(document, identity)
        success = is_success(http)

        returned_id = None
        if step.produces_object:
            returned_id = _harvest_id(http, plan.object_type, schema, operation)
            tracked_id = returned_id if returned_id is not None else tracked_id

        disclosed = success and tracked_id is not None and _body_references(http, tracked_id)
        marker_seen = bool(marker) and success and _body_contains(http, marker)
        result.steps.append(StepResult(
            operation=step.operation, role=step.role, identity=identity,
            document=document, success=success, returned_id=returned_id,
            post_delete=step.post_delete, disclosed=disclosed, marker_seen=marker_seen,
        ))

    result.identities = identities_used
    _judge(plan, result, tracked_id)
    return result


def _target_op(plan: ChainPlan) -> str:
    """The operation a chain finding is attributed to.

    Disclosure (IDOR/UAF) is attributed to the offending read (the last step);
    stored XSS is attributed to the *write* that planted the payload (the create),
    which is where the sink lives and how ground truth labels it.
    """
    if plan.strategy == "xss_stored":
        return next((s.operation for s in plan.steps if s.produces_object), plan.steps[0].operation)
    if plan.strategy in ("bola_delete", "bola_update"):
        # Attribute to the offending write (the secondary step), where truth labels it.
        return next((s.operation for s in plan.steps if s.role == "secondary"), plan.steps[-1].operation)
    return plan.steps[-1].operation


def _build_step_document(
    schema: Schema, operation: Operation, step: ChainStep, tracked_id: Any, bucket: ObjectsBucket
) -> str:
    args: dict[str, Any] = {}
    for name, ref in operation.args:
        if name == step.id_argument and tracked_id is not None:
            args[name] = tracked_id            # carry the created resource's id forward
        elif name == step.inject_argument and step.marker:
            args[name] = step.marker           # plant the stored-XSS marker
        elif ref.non_null or name == step.inject_argument:
            args[name] = default_argument(ref, schema)
    style = "maximal" if getattr(step, "select_all", False) else "minimal"
    return build_operation(schema, operation, args=args, depth=1, style=style)


def _harvest_id(http: HttpResult, object_type: str, schema: Schema, operation: Operation) -> Any:
    """Pull the created resource's id from a CREATE response."""
    scratch = ObjectsBucket()
    scratch.harvest(http.data, operation=operation.name, identity="",
                    schema=schema, root_type=operation.type.name)
    return scratch.any_id(object_type)


def _judge(plan: ChainPlan, result: ChainResult, tracked_id: Any) -> None:
    """Apply the disclosure oracle for this chain's strategy."""
    steps = result.steps
    create = next((s for s in steps if s.role == "primary" and s.returned_id is not None), None)
    final = steps[-1]

    # The chain must first have produced a real, identified private resource.
    if create is None or tracked_id is None:
        result.verdict = "inconclusive"
        result.detail = "chain did not produce an identified resource to test"
        return

    if plan.strategy == "idor":
        # Disclosure: the secondary read returned the primary-created resource.
        if final.role == "secondary" and final.success and _references(final, tracked_id):
            result.verdict = "confirmed"
            result.detail = (f"secondary identity {final.identity!r} read the "
                             f"{plan.object_type} (id {tracked_id!r}) created by the primary")
            result.witness = _witness(result, tracked_id)
        else:
            result.detail = "secondary read did not disclose the primary's resource"

    elif plan.strategy == "uaf":
        # Disclosure: the post-delete read still returned the deleted resource.
        if final.post_delete and final.success and _references(final, tracked_id):
            result.verdict = "confirmed"
            result.detail = (f"{plan.object_type} (id {tracked_id!r}) still readable after "
                             f"deletion — phantom resource")
            result.witness = _witness(result, tracked_id)
        else:
            result.detail = "post-delete read returned nothing (resource properly gone)"

    elif plan.strategy == "xss_stored":
        # The script marker planted at create time came back on read, unsanitised.
        if final.marker_seen:
            result.verdict = "confirmed"
            result.detail = (f"stored script marker reflected unsanitised on read-back via "
                             f"{final.operation}")
            result.witness = _witness(result, tracked_id)
        else:
            result.detail = "planted marker not reflected on read-back"

    elif plan.strategy == "bola_delete":
        # Sound write-side BOLA: the secondary identity deleted the primary's
        # resource, so the primary's own read no longer returns it. Confirmed only
        # when the delete succeeded AND the resource is now gone — a secure service
        # rejects the delete and the primary still reads its resource.
        secondary = next((s for s in steps if s.role == "secondary"), None)
        if secondary and secondary.success and final.role == "primary" \
                and final.post_delete and not final.success:
            result.verdict = "confirmed"
            result.detail = (f"secondary identity {secondary.identity!r} deleted the "
                             f"{plan.object_type} (id {tracked_id!r}) owned by the primary")
            result.witness = _witness(result, tracked_id)
        else:
            result.detail = "secondary delete did not remove the primary's resource"

    elif plan.strategy == "bola_update":
        # Sound write-side BOLA: the secondary planted a marker via update; the
        # primary reads it back -> the secondary modified the primary's resource.
        if final.marker_seen:
            result.verdict = "confirmed"
            result.detail = (f"secondary identity modified the {plan.object_type} "
                             f"(id {tracked_id!r}); marker visible to the primary")
            result.witness = _witness(result, tracked_id)
        else:
            result.detail = "secondary update did not take effect on the primary's resource"


def _references(step: StepResult, tracked_id: Any) -> bool:
    """Whether a step's *response* returned the specific tracked resource.

    Requiring the id to appear in the response — not just a 200 — is what keeps a
    public listing from being mis-scored as IDOR (the myNotes/myOrders false
    positives the paper flags): a public read succeeds too, but it does not
    return *this* privately-created resource.
    """
    return step.disclosed


def _body_references(http: HttpResult, tracked_id: Any) -> bool:
    """True when the response body contains the tracked resource id."""
    import json
    body = http.body
    if not isinstance(body, dict):
        return False
    if not is_success(http):
        return False
    return str(tracked_id) in json.dumps(body.get("data"), default=str)


def _body_contains(http: HttpResult, needle: str) -> bool:
    """True when the response data contains ``needle`` verbatim (stored-XSS marker)."""
    import json
    body = http.body
    if not isinstance(body, dict) or not is_success(http):
        return False
    return needle in json.dumps(body.get("data"), default=str)


def _witness(result: ChainResult, tracked_id: Any) -> dict[str, Any]:
    requests = tuple(
        RequestRecord(document=s.document, identity=s.identity) for s in result.steps
    )
    return Witness(
        requests=requests,
        matched=result.detail,
        differential={"resource_id": str(tracked_id),
                      "identities": [s.identity for s in result.steps]},
    ).to_dict()
