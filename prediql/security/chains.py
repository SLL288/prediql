"""Chain strategies: IDOR and UAF synthesis (doc 02 §4).

A *chain* is an ordered sequence of operations that a single request cannot
express — the whole class of vulnerability v1 could not reach. Both strategies
read PrediQL's own dependency graph and objects bucket (built and tested in the
model layer), then feed the synthesized chains into evidence-grounded execution.

* **IDOR** — CREATE under a primary identity, READ under a secondary one. A
  finding is a *disclosure*: the second, unprivileged identity receives the
  resource the first one created.
* **UAF** — the quadruple (create c, object o, delete d, read r): create a
  resource, delete it, then read it. A finding is the post-delete read returning
  the deleted resource. DELETE is gated behind ``--allow-destructive``.

Both are synthesis over graph edges, not label matching: a chain is only built
when the graph actually links a CREATE that produces an object to an operation
that consumes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from prediql.model.graph import Action, DependencyGraph
from prediql.model.schema import Schema

# Roles a chain step runs under.
ROLE_PRIMARY = "primary"
ROLE_SECONDARY = "secondary"


@dataclass(frozen=True, slots=True)
class ChainStep:
    """One operation in a chain, and how its arguments are sourced."""

    operation: str
    role: str
    produces_object: bool = False
    """True for the CREATE step whose returned id later steps consume."""
    id_argument: str = ""
    """The argument this step fills with the chain's tracked object id."""
    post_delete: bool = False
    """Marks the read that must happen *after* a delete (UAF)."""
    marker: str = ""
    """A sentinel to plant (stored-XSS create step) and look for on read-back."""
    inject_argument: str = ""
    """The string argument the marker is injected into (stored-XSS create step)."""
    select_all: bool = False
    """Select every scalar on the read-back (stored-XSS), so the field holding
    the planted marker is actually returned — a minimal `{ id }` selection would
    miss it and lose the finding."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "role": self.role,
            "produces_object": self.produces_object,
            "id_argument": self.id_argument,
            "post_delete": self.post_delete,
            "marker": self.marker,
            "inject_argument": self.inject_argument,
            "select_all": self.select_all,
        }


@dataclass(frozen=True, slots=True)
class ChainPlan:
    """A synthesized, not-yet-executed chain."""

    id: str
    strategy: str          # "idor" | "uaf"
    class_id: str          # canonical class this chain would confirm
    object_type: str       # the linking object o
    steps: tuple[ChainStep, ...]
    description: str = ""
    blocked: str = ""      # "" = runnable; else a reason ("needs_identities", ...)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "strategy": self.strategy,
            "class_id": self.class_id,
            "object_type": self.object_type,
            "steps": [s.to_dict() for s in self.steps],
            "description": self.description,
            "blocked": self.blocked,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ChainPlan":
        return cls(
            id=data["id"],
            strategy=data["strategy"],
            class_id=data["class_id"],
            object_type=data["object_type"],
            steps=tuple(
                ChainStep(
                    operation=s["operation"], role=s["role"],
                    produces_object=s.get("produces_object", False),
                    id_argument=s.get("id_argument", ""),
                    post_delete=s.get("post_delete", False),
                    marker=s.get("marker", ""),
                    inject_argument=s.get("inject_argument", ""),
                    select_all=s.get("select_all", False),
                )
                for s in data["steps"]
            ),
            description=data.get("description", ""),
            blocked=data.get("blocked", ""),
        )


def _id_argument(graph: DependencyGraph, operation: str, object_type: str) -> str:
    """The argument on ``operation`` that carries ``object_type``'s id.

    Recovered from the graph edge that linked them, so a chain fills the right
    argument rather than guessing.
    """
    for edge in graph.dependencies_of(operation):
        if edge.source == object_type:
            return edge.via
    return ""


def synthesize(
    graph: DependencyGraph,
    schema: Schema,
    *,
    usable_identities: list[str],
    allow_destructive: bool,
) -> list[ChainPlan]:
    """Build every IDOR and UAF chain the graph supports.

    Chains whose preconditions are unmet (too few identities for IDOR, no
    destructive permission for UAF) are still returned, marked ``blocked`` with
    the reason, so they surface as coverage gaps rather than vanishing.
    """
    plans: list[ChainPlan] = []
    has_two_identities = len(usable_identities) >= 2

    for object_type in sorted(graph.objects):
        creates = [op for op in graph.producers_of(object_type)
                   if graph.actions.get(op) is Action.CREATE]
        reads = [op for op in graph.consumers_of(object_type)
                 if graph.actions.get(op) is Action.READ]
        deletes = [op for op in graph.consumers_of(object_type)
                   if graph.actions.get(op) is Action.DELETE]

        # -- IDOR: create[primary] -> read[secondary] --------------------
        for create in creates:
            for read in reads:
                id_arg = _id_argument(graph, read, object_type)
                if not id_arg:
                    continue
                plans.append(ChainPlan(
                    id=f"idor__{create}__{read}",
                    strategy="idor",
                    class_id="idor",
                    object_type=object_type,
                    steps=(
                        ChainStep(create, ROLE_PRIMARY, produces_object=True),
                        ChainStep(read, ROLE_SECONDARY, id_argument=id_arg),
                    ),
                    description=(f"{create} under primary, then {read} under secondary "
                                 f"for the created {object_type}"),
                    blocked="" if has_two_identities else "needs_identities",
                ))

        # -- UAF: create[primary] -> delete[primary] -> read[post-delete] --
        for create in creates:
            for delete in deletes:
                for read in reads:
                    del_arg = _id_argument(graph, delete, object_type)
                    read_arg = _id_argument(graph, read, object_type)
                    if not del_arg or not read_arg:
                        continue
                    plans.append(ChainPlan(
                        id=f"uaf__{create}__{delete}__{read}",
                        strategy="uaf",
                        class_id="uaf",
                        object_type=object_type,
                        steps=(
                            ChainStep(create, ROLE_PRIMARY, produces_object=True),
                            ChainStep(delete, ROLE_PRIMARY, id_argument=del_arg),
                            ChainStep(read, ROLE_PRIMARY, id_argument=read_arg,
                                      post_delete=True),
                        ),
                        description=(f"create {object_type} via {create}, delete via {delete}, "
                                     f"then read via {read} after deletion"),
                        blocked="" if allow_destructive else "needs_destructive",
                    ))

        updates = [op for op in graph.consumers_of(object_type)
                   if graph.actions.get(op) is Action.UPDATE]

        # -- Write-side BOLA, confirmed by an effect-verification read (sound).
        #    The read under the PRIMARY is what proves the secondary's write took
        #    effect — never the mutation echoing the id back.
        for create in creates:
            for read in reads:
                read_arg = _id_argument(graph, read, object_type)
                if not read_arg:
                    continue
                # delete-BOLA: secondary deletes the primary's object; the primary
                # can then no longer read it -> B deleted A's resource.
                for delete in deletes:
                    del_arg = _id_argument(graph, delete, object_type)
                    if not del_arg:
                        continue
                    plans.append(ChainPlan(
                        id=f"bola_delete__{create}__{delete}__{read}",
                        strategy="bola_delete", class_id="idor", object_type=object_type,
                        steps=(
                            ChainStep(create, ROLE_PRIMARY, produces_object=True),
                            ChainStep(delete, ROLE_SECONDARY, id_argument=del_arg),
                            ChainStep(read, ROLE_PRIMARY, id_argument=read_arg, post_delete=True),
                        ),
                        description=(f"{create}[primary] -> {delete}[secondary] -> {read}[primary]: "
                                     f"secondary deletes the primary's {object_type}"),
                        blocked=("needs_identities" if not has_two_identities
                                 else "needs_destructive" if not allow_destructive else ""),
                    ))
                # update-BOLA: secondary updates the primary's object with a marker;
                # the primary then reads the marker back -> B modified A's resource.
                for update in updates:
                    upd_arg = _id_argument(graph, update, object_type)
                    inject = _injectable_text_arg(update, schema)
                    if not upd_arg or not inject:
                        continue
                    marker = _xss_marker()
                    plans.append(ChainPlan(
                        id=f"bola_update__{create}__{update}__{read}",
                        strategy="bola_update", class_id="idor", object_type=object_type,
                        steps=(
                            ChainStep(create, ROLE_PRIMARY, produces_object=True),
                            ChainStep(update, ROLE_SECONDARY, id_argument=upd_arg,
                                      marker=marker, inject_argument=inject),
                            ChainStep(read, ROLE_PRIMARY, id_argument=read_arg, select_all=True),
                        ),
                        description=(f"{create}[primary] -> {update}[secondary] plants a marker -> "
                                     f"{read}[primary] reflects it: secondary modified the primary's {object_type}"),
                        blocked="" if has_two_identities else "needs_identities",
                    ))

        # -- Stored XSS: create[primary] plants a marker -> read[primary] reflects it.
        for create in creates:
            inject_arg = _injectable_text_arg(create, schema)
            if not inject_arg:
                continue
            for read in reads:
                id_arg = _id_argument(graph, read, object_type)
                if not id_arg:
                    continue
                marker = _xss_marker()
                plans.append(ChainPlan(
                    id=f"xss_stored__{create}__{read}",
                    strategy="xss_stored",
                    class_id="xss_stored",
                    object_type=object_type,
                    steps=(
                        ChainStep(create, ROLE_PRIMARY, produces_object=True,
                                  marker=marker, inject_argument=inject_arg),
                        ChainStep(read, ROLE_PRIMARY, id_argument=id_arg, select_all=True),
                    ),
                    description=(f"{create} stores a script marker in {inject_arg}, "
                                 f"{read} reflects it unsanitised"),
                    blocked="",
                ))

    return plans


def _injectable_text_arg(operation_name: str, schema: Schema) -> str:
    """A String argument of a create op to plant the stored-XSS marker in."""
    op = schema.operations.get(operation_name)
    if op is None:
        return ""
    for name, ref in op.args:
        base = schema.type(ref.name)
        if ref.name == "String" or (base is not None and base.kind == "SCALAR"
                                     and ref.name not in ("ID", "Int", "Float", "Boolean")):
            return name
    return ""


def _xss_marker() -> str:
    import uuid
    return f"<script>pqlxss{uuid.uuid4().hex[:8]}</script>"
