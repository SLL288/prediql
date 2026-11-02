"""Ground-truth contract files: load, validate, certify (doc 03).

A target's ground truth is a versioned YAML file — a ``target:`` header plus one
``contract`` per operation the author has a labelled opinion about, vulnerable or
known-clean. This is the ``gtpov`` pattern ported to GraphQL: the file is checked
in, content-hashed so an edit after certification is detectable, and read by the
``score`` step. Nothing here is target-specific code; the DVGA labels live in a
data file, not in the engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from prediql.engine.fingerprint import fingerprint
from prediql.scoring.classes import normalize

ORIGINS = frozenset({"upstream", "source_audit", "post_hoc"})
"""Where a label came from — the disclosure the paper owes its reader.

- ``upstream``: the target's own authors document it (their tests, solutions,
  source comments, README).
- ``source_audit``: we derived it by reading the target's source *before* seeing
  any tool output.
- ``post_hoc``: added or changed *after* a tool's output was seen. Legitimate
  when verified in the source, but scored both with and without it, so a
  label can never quietly turn a false positive into a true positive.
"""

PLACEHOLDER_FINGERPRINTS = frozenset({"", "sha256:REPLACE", "sha256:REPLACE_AFTER_FIRST_INTROSPECT"})


@dataclass(frozen=True, slots=True)
class ClassContract:
    """One labelled vulnerability class on an operation."""

    id: str
    severity: str = ""
    evidence_kind: str = ""
    witness_hint: str = ""
    preconditions: tuple[str, ...] = ()
    second_order: dict[str, Any] = field(default_factory=dict)
    chain: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    """Citation for this label (upstream test, source file:line)."""
    origin: str = ""
    """One of :data:`ORIGINS`; empty means not yet declared."""

    @property
    def canonical_id(self) -> str | None:
        """The registry id this label resolves to, or ``None`` if unknown."""
        return normalize(self.id)


@dataclass(frozen=True, slots=True)
class Contract:
    """A per-operation ground-truth entry."""

    operation: str
    kind: str = "query"
    vulnerable: bool = True
    classes: tuple[ClassContract, ...] = ()
    source: str = ""

    def class_ids(self) -> set[str]:
        """Canonical ids of the classes this operation is labelled vulnerable to."""
        return {c.canonical_id for c in self.classes if c.canonical_id}


@dataclass
class GroundTruth:
    """A whole target's ground truth."""

    name: str
    slug: str
    contracts: tuple[Contract, ...]
    schema_fingerprint: str = ""
    certified: bool = False
    content_hash: str | None = None
    url_hint: str = ""
    source: str = ""
    path: Path | None = None

    def contract_for(self, operation: str) -> Contract | None:
        for contract in self.contracts:
            if contract.operation == operation:
                return contract
        return None

    def vulnerable_operations(self) -> set[str]:
        return {c.operation for c in self.contracts if c.vulnerable}

    def negative_operations(self) -> set[str]:
        return {c.operation for c in self.contracts if not c.vulnerable}

    def labelled_operations(self) -> set[str]:
        return {c.operation for c in self.contracts}

    def without_post_hoc(self) -> GroundTruth:
        """The truth as it stood before any post-hoc label was added.

        Post-hoc classes are dropped. A contract that was *entirely* post hoc
        is dropped too, because that operation was unlabelled before; a contract
        that keeps other classes stays labelled, so a finding on the removed
        class scores as it did originally (an FP), never as a TP.
        """
        contracts = []
        for c in self.contracts:
            if c.classes and all(cc.origin == "post_hoc" for cc in c.classes):
                continue
            kept = tuple(cc for cc in c.classes if cc.origin != "post_hoc")
            contracts.append(replace(c, classes=kept))
        return replace(self, contracts=tuple(contracts))

    def has_post_hoc(self) -> bool:
        return any(cc.origin == "post_hoc" for c in self.contracts for cc in c.classes)

    # -- certification ----------------------------------------------------

    def compute_content_hash(self) -> str:
        """Hash over the contracts (not the certification fields themselves).

        Editing any contract changes this, so a certified badge cannot silently
        outlive the labels it certified — the ``gtpov`` content-hash guarantee.
        """
        payload = [
            {
                "operation": c.operation,
                "kind": c.kind,
                "vulnerable": c.vulnerable,
                "classes": sorted(
                    {
                        "id": cc.id,
                        "evidence_kind": cc.evidence_kind,
                        "preconditions": list(cc.preconditions),
                        "origin": cc.origin,
                    }.items().__str__()
                    for cc in c.classes
                ),
            }
            for c in sorted(self.contracts, key=lambda x: x.operation)
        ]
        return fingerprint(payload)

    def certification_status(self) -> str:
        """``certified`` / ``unsealed`` / ``uncertified`` — never raises.

        ``unsealed`` means a content hash was recorded but no longer matches the
        contracts: the file was edited after certification and must be re-certified.
        """
        if not self.content_hash:
            return "uncertified"
        if self.content_hash != self.compute_content_hash():
            return "unsealed"
        return "certified" if self.certified else "uncertified"


class GroundTruthError(ValueError):
    """A ground-truth file is malformed or references unknown classes."""


def load(path: Path | str) -> GroundTruth:
    """Parse and validate a ground-truth YAML file."""
    path = Path(path)
    if not path.exists():
        raise GroundTruthError(f"ground-truth file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise GroundTruthError(f"invalid YAML in {path}: {exc}") from exc

    target = raw.get("target") or {}
    if not target.get("slug"):
        raise GroundTruthError(f"{path}: target.slug is required")

    contracts: list[Contract] = []
    for entry in raw.get("contracts", []) or []:
        contracts.append(_parse_contract(entry, path))

    for contract in contracts:
        for cc in contract.classes:
            if cc.origin and cc.origin not in ORIGINS:
                raise GroundTruthError(
                    f"{path}: operation {contract.operation!r} class {cc.id!r} has origin "
                    f"{cc.origin!r}; expected one of {sorted(ORIGINS)}"
                )

    # Fail loudly on an unknown class id: a typo in a label silently scores as a
    # miss otherwise, which is worse than a clear error.
    for contract in contracts:
        for cc in contract.classes:
            if cc.canonical_id is None:
                raise GroundTruthError(
                    f"{path}: operation {contract.operation!r} names unknown class "
                    f"{cc.id!r} (not in the class registry)"
                )

    return GroundTruth(
        name=target.get("name", target["slug"]),
        slug=target["slug"],
        contracts=tuple(contracts),
        schema_fingerprint=str(target.get("schema_fingerprint", "")),
        certified=bool(target.get("certified", False)),
        content_hash=target.get("content_hash"),
        url_hint=target.get("url_hint", ""),
        source=target.get("source", ""),
        path=path,
    )


def _parse_contract(entry: dict[str, Any], path: Path) -> Contract:
    if "operation" not in entry:
        raise GroundTruthError(f"{path}: a contract is missing 'operation'")
    classes = tuple(
        ClassContract(
            id=c["id"],
            severity=c.get("severity", ""),
            evidence_kind=c.get("evidence_kind", ""),
            witness_hint=c.get("witness_hint", ""),
            preconditions=tuple(c.get("preconditions", ()) or ()),
            second_order=dict(c.get("second_order", {}) or {}),
            chain=dict(c.get("chain", {}) or {}),
            source=str(c.get("source", "") or ""),
            origin=str(c.get("origin", "") or ""),
        )
        for c in (entry.get("classes", []) or [])
        if isinstance(c, dict) and c.get("id")
    )
    return Contract(
        operation=entry["operation"],
        kind=entry.get("kind", "query"),
        vulnerable=bool(entry.get("vulnerable", True)),
        classes=classes,
        source=entry.get("source", ""),
    )


def certify(path: Path | str, *, schema_fingerprint: str | None = None) -> GroundTruth:
    """Freeze a truth file: stamp its content hash and schema fingerprint.

    Refuses to certify labels that cannot be audited: a placeholder schema
    fingerprint (the labels must be pinned to the schema they describe), or a
    vulnerable label with no declared ``origin``. Only the three header fields
    are rewritten in place, so comments and citations in the file survive.
    """
    truth = load(path)
    fp = schema_fingerprint or truth.schema_fingerprint
    if fp in PLACEHOLDER_FINGERPRINTS:
        raise GroundTruthError(
            f"{path}: no schema fingerprint. Certify against the schema the labels "
            "describe: `predql truth certify --truth <file> --run <run_id>`"
        )
    undeclared = sorted(
        f"{c.operation}::{cc.id}" for c in truth.contracts if c.vulnerable
        for cc in c.classes if not cc.origin
    )
    if undeclared:
        raise GroundTruthError(
            f"{path}: labels without an origin ({', '.join(undeclared)}); declare "
            f"one of {sorted(ORIGINS)} on each"
        )
    text = Path(path).read_text(encoding="utf-8")
    text = _set_header_field(text, "schema_fingerprint", f'"{fp}"')
    text = _set_header_field(text, "certified", "true")
    text = _set_header_field(text, "content_hash", f'"{truth.compute_content_hash()}"')
    Path(path).write_text(text, encoding="utf-8")
    return load(path)


_HEADER = re.compile(r"^target:\s*(#.*)?$")


def _set_header_field(text: str, key: str, value: str) -> str:
    """Set ``target.<key>`` in a block-style header, keeping every other line."""
    lines = text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if _HEADER.match(line.rstrip("\n"))), None)
    if start is None:
        raise GroundTruthError("certify needs a block-style `target:` header (not a flow mapping)")
    indent, end, last = None, len(lines), start
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            end = j
            break
        indent = indent if indent is not None else len(line) - len(line.lstrip())
        last = j
    pad = " " * (indent or 2)
    field_re = re.compile(rf"^{pad}{re.escape(key)}:(?P<value>[^#\n]*?)(?P<comment>\s+#.*)?$")
    for j in range(start + 1, end):
        match = field_re.match(lines[j].rstrip("\n"))
        if match:
            lines[j] = f"{pad}{key}: {value}{match.group('comment') or ''}\n"
            return "".join(lines)
    lines.insert(last + 1, f"{pad}{key}: {value}\n")
    return "".join(lines)
