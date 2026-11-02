"""End-to-end IDOR/UAF detection against a stateful mock (M4 exit criteria).

A note service with a real access-control bug (any identity can read any note)
and a real phantom-resource bug (a deleted note stays readable). The chains must
confirm both with witnesses — and a *secure* variant must confirm neither.
"""

from __future__ import annotations

import re

import pytest

from prediql.engine.config import Identity, RunConfig, Strategy
from prediql.engine.context import RunContext
from prediql.runner import execute
from prediql.targets.base import HttpResult

INTROSPECTION = {"data": {"__schema": {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "getNote", "type": {"kind": "OBJECT", "name": "Note"},
             "args": [{"name": "noteId", "type": {"kind": "NON_NULL",
                                                  "ofType": {"kind": "SCALAR", "name": "ID"}}}]}]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "createNote", "type": {"kind": "OBJECT", "name": "Note"},
             "args": [{"name": "text", "type": {"kind": "SCALAR", "name": "String"}}]},
            {"name": "deleteNote", "type": {"kind": "OBJECT", "name": "Note"},
             "args": [{"name": "noteId", "type": {"kind": "NON_NULL",
                                                  "ofType": {"kind": "SCALAR", "name": "ID"}}}]}]},
        {"name": "Note", "kind": "OBJECT", "fields": [
            {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}, "args": []},
            {"name": "owner", "type": {"kind": "SCALAR", "name": "String"}, "args": []},
            {"name": "text", "type": {"kind": "SCALAR", "name": "String"}, "args": []}]},
    ]}}}


class NoteService:
    """A stateful GraphQL note service. `secure=True` fixes both bugs."""

    def __init__(self, *, secure: bool = False):
        self.introspection = INTROSPECTION
        self.secure = secure
        self.notes: dict[str, dict] = {}
        self.deleted: set[str] = set()
        self._next = 1
        self.sent: list[str] = []

    async def introspect(self, identity):
        return self.introspection

    async def send(self, document, identity, *, variables=None):
        self.sent.append(document)
        norm = " ".join(document.split())

        def ok(data, status=200):
            return HttpResult(document=document, identity=identity.name, status=status,
                              body={"data": data}, elapsed_ms=5.0)

        def err(msg):
            return HttpResult(document=document, identity=identity.name, status=200,
                              body={"errors": [{"message": msg}]}, elapsed_ms=5.0)

        if norm.startswith("mutation") and "createNote" in norm:
            nid = str(self._next); self._next += 1
            self.notes[nid] = {"id": nid, "owner": identity.name, "text": "secret"}
            return ok({"createNote": {"id": nid}})

        if norm.startswith("mutation") and "deleteNote" in norm:
            nid = _arg(norm, "noteId")
            if nid in self.notes:
                # Secure fixes write-side BOLA too: only the owner may delete.
                if self.secure and self.notes[nid]["owner"] != identity.name:
                    return err("forbidden")
                self.deleted.add(nid)              # soft delete
                return ok({"deleteNote": {"id": nid}})
            return err("no such note")

        if "getNote" in norm:
            nid = _arg(norm, "noteId")
            note = self.notes.get(nid)
            if note is None:
                return err("not found")
            # UAF bug: a soft-deleted note stays readable unless secure.
            if nid in self.deleted and not self.secure:
                return ok({"getNote": note})
            if nid in self.deleted and self.secure:
                return err("note deleted")
            # IDOR bug: any identity reads any note unless secure enforces owner.
            if self.secure and note["owner"] != identity.name:
                return err("forbidden")
            return ok({"getNote": note})

        return ok({"__typename": "Query"})

    async def aclose(self):
        pass


def _arg(norm: str, name: str):
    m = re.search(rf'{name}:\s*"?([^",)\s]+)"?', norm)
    return m.group(1) if m else None


def _config(secure=False, **kw):
    base = dict(
        target_url="https://notes.test/graphql",
        mode="chains",
        identities=(Identity("alice", role="user"), Identity("bob", role="user")),
        allow_destructive=True,
        strategy=Strategy(rounds=1, requests_per_operation=6, seed=3),
    )
    base.update(kw)
    return RunConfig(**base)


@pytest.fixture
def vulnerable():
    return NoteService(secure=False)


@pytest.fixture
def secure():
    return NoteService(secure=True)


async def test_chains_mode_runs_end_to_end(vulnerable):
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        report = await execute(_config(), runs_root=d, target=vulnerable)
        assert report.ok, [s.error for s in report.steps if s.error]
        names = [s.name for s in report.steps]
        assert "plan_chains" in names and "execute_chains" in names


async def test_idor_and_uaf_are_confirmed_on_the_vulnerable_service(tmp_path, vulnerable):
    config = _config()
    await execute(config, runs_root=tmp_path, target=vulnerable)
    findings = RunContext(config, runs_root=tmp_path).get("findings")

    confirmed = {f["class"] for f in findings["findings"] if f["state"] == "confirmed"}
    assert "idor" in confirmed, findings["findings"]
    assert "uaf" in confirmed, findings["findings"]

    idor = next(f for f in findings["findings"] if f["class"] == "idor")
    assert idor["chain"], "a chain finding must record its steps"
    assert idor["chain"][0]["identity"] == "alice"      # created by primary
    assert idor["chain"][-1]["identity"] == "bob"       # read by secondary
    assert idor["witness"]["requests"], "and a reproducible witness"


async def test_secure_service_confirms_neither(tmp_path, secure):
    """The differential: fix the bugs and the same chains find nothing."""
    config = _config()
    await execute(config, runs_root=tmp_path, target=secure)
    findings = RunContext(config, runs_root=tmp_path).get("findings")
    confirmed = {f["class"] for f in findings["findings"] if f["state"] == "confirmed"}
    assert "idor" not in confirmed, "owner enforcement blocks cross-user read"
    assert "uaf" not in confirmed, "a properly deleted note is not readable"


async def test_uaf_blocked_without_destructive_permission(tmp_path, vulnerable):
    config = _config(allow_destructive=False)
    await execute(config, runs_root=tmp_path, target=vulnerable)
    chains = RunContext(config, runs_root=tmp_path).get("chains")
    assert chains["blocked"].get("needs_destructive", 0) >= 1
    # No deleteNote should ever have been issued.
    assert not any("deleteNote" in d for d in vulnerable.sent), \
        "a blocked UAF chain must not issue the DELETE"


async def test_idor_blocked_with_a_single_identity(tmp_path):
    config = _config(identities=(Identity("solo", role="user"),))
    service = NoteService(secure=False)
    await execute(config, runs_root=tmp_path, target=service)
    chains = RunContext(config, runs_root=tmp_path).get("chains")
    assert chains["blocked"].get("needs_identities", 0) >= 1


class PublicNoteService(NoteService):
    """Reads succeed for everyone but return an UNRELATED public note.

    This is the myNotes/myOrders false-positive shape: a successful cross-user
    read that does not actually disclose the privately-created resource.
    """

    async def send(self, document, identity, *, variables=None):
        norm = " ".join(document.split())
        if "getNote" in norm and not norm.startswith("mutation"):
            # Always returns a fixed public note, never the requested private id.
            return HttpResult(document=document, identity=identity.name, status=200,
                              body={"data": {"getNote": {"id": "PUBLIC", "owner": "system",
                                                         "text": "public"}}}, elapsed_ms=5.0)
        return await super().send(document, identity, variables=variables)


async def test_public_read_is_not_mis_scored_as_idor(tmp_path):
    """A successful read that returns an unrelated resource is not disclosure."""
    config = _config()
    await execute(config, runs_root=tmp_path, target=PublicNoteService(secure=False))
    findings = RunContext(config, runs_root=tmp_path).get("findings")
    confirmed = {f["class"] for f in findings["findings"] if f["state"] == "confirmed"}
    assert "idor" not in confirmed, "the read succeeded but did not disclose the created note"
