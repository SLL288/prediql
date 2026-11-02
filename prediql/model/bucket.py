"""Objects bucket: typed resources returned by the API, reusable as inputs.

This is the runtime state that makes chains executable — v1 has no equivalent,
which is precisely why it cannot express IDOR or UAF. Entries record which
identity obtained them, since a cross-user chain must replay a resource created
by one identity against another.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

#: Field names that plausibly identify a resource, in priority order.
_ID_FIELDS = ("id", "ID", "_id", "uuid", "key", "code", "slug")


@dataclass(frozen=True, slots=True)
class ObjectRef:
    """One concrete resource observed in a response."""

    type_name: str
    identifier: Any
    fields: dict[str, Any] = field(default_factory=dict)
    origin_operation: str = ""
    identity: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type_name": self.type_name,
            "identifier": self.identifier,
            "fields": self.fields,
            "origin_operation": self.origin_operation,
            "identity": self.identity,
        }


class ObjectsBucket:
    """Thread-safe store of observed resources, keyed by schema type.

    The only shared mutable structure during fan-out, so writes are locked per
    instance; every other artifact a step touches is either read-only or
    step-owned.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_type: dict[str, list[ObjectRef]] = {}

    # -- access -----------------------------------------------------------

    def add(self, ref: ObjectRef) -> None:
        with self._lock:
            existing = self._by_type.setdefault(ref.type_name, [])
            if not any(
                e.identifier == ref.identifier and e.identity == ref.identity for e in existing
            ):
                existing.append(ref)

    def get(self, type_name: str, *, identity: str | None = None) -> list[ObjectRef]:
        with self._lock:
            refs = list(self._by_type.get(type_name, ()))
        if identity is None:
            return refs
        return [r for r in refs if r.identity == identity]

    def any_id(self, type_name: str, *, identity: str | None = None) -> Any | None:
        """First known identifier for a type — the common chain lookup."""
        refs = self.get(type_name, identity=identity)
        return refs[0].identifier if refs else None

    def field_value(self, type_name: str, field_name: str) -> Any | None:
        """First observed value of ``type_name.field_name``."""
        for ref in self.get(type_name):
            value = ref.fields.get(field_name)
            if value is not None:
                return value
        return None

    def types(self) -> list[str]:
        with self._lock:
            return sorted(self._by_type)

    def __len__(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._by_type.values())

    # -- population -------------------------------------------------------

    def harvest(
        self,
        data: Any,
        *,
        operation: str,
        identity: str,
        schema: Any = None,
        root_type: str | None = None,
    ) -> int:
        """Record every identifiable object in a response. Returns the count.

        The walk is **schema-guided**: each response key is resolved through the
        schema to its declared field type, so a resource is filed under its real
        type name (``Continent``) rather than the response key that carried it
        (``continents``). Without that, every type-keyed lookup misses — which
        breaks both argument reuse and, later, chain synthesis.

        Falls back to using the response key as the type hint when no schema is
        supplied, which keeps the method usable standalone and in tests.
        """
        found = 0

        def child_type(parent_type: str | None, field_name: str) -> str | None:
            """Declared type of ``parent_type.field_name``, if resolvable."""
            if schema is None:
                return field_name
            if parent_type is None:
                return None
            type_def = schema.type(parent_type)
            if type_def is None:
                return None
            declared = type_def.field(field_name)
            return declared.type.name if declared is not None else None

        def walk(node: Any, type_name: str | None) -> None:
            nonlocal found
            if isinstance(node, list):
                for item in node:
                    walk(item, type_name)
                return
            if not isinstance(node, dict):
                return

            if type_name:
                identifier = next(
                    (node[f] for f in _ID_FIELDS if f in node and node[f] is not None), None
                )
                if identifier is not None:
                    self.add(
                        ObjectRef(
                            type_name=str(node.get("__typename") or type_name),
                            identifier=identifier,
                            fields={
                                k: v for k, v in node.items() if not isinstance(v, (dict, list))
                            },
                            origin_operation=operation,
                            identity=identity,
                        )
                    )
                    found += 1

            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    walk(value, child_type(type_name, key))

        # The response envelope is ``{"<operation>": <payload>}``; the payload's
        # type is the operation's return type, not a field of anything.
        if isinstance(data, dict):
            for key, value in data.items():
                walk(value, root_type or key)
        return found

    # -- persistence ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {t: [r.to_dict() for r in refs] for t, refs in sorted(self._by_type.items())}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ObjectsBucket:
        bucket = cls()
        for type_name, refs in (data or {}).items():
            for raw in refs:
                bucket.add(
                    ObjectRef(
                        type_name=type_name,
                        identifier=raw.get("identifier"),
                        fields=raw.get("fields", {}),
                        origin_operation=raw.get("origin_operation", ""),
                        identity=raw.get("identity", ""),
                    )
                )
        return bucket
