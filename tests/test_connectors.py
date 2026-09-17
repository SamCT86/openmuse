"""Scoped connector interface: least-privilege grants, policy wiring, audit."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from openmuse.approvals import ApprovalAuthority
from openmuse.audit import verify_chain
from openmuse.connectors import (
    Capability,
    GrantError,
    ReadOnlyConnector,
    ScopeDenied,
    ScopeGrants,
    connector_tools,
)
from openmuse.core import Agent
from openmuse.models import Action, ActionStatus
from openmuse.policy import Policy, Risk


class FixtureConnector:
    name = "mail"

    def capabilities(self) -> list[Capability]:
        return [
            Capability("list", "mail.read", Risk.READ),
            Capability("archive", "mail.write", Risk.WRITE),
        ]

    def invoke(self, capability: str, arguments: Mapping[str, Any]) -> str:
        return f"{capability}:{arguments.get('folder', 'inbox')}"


class NotesConnector(ReadOnlyConnector):
    name = "notes"

    def read_capabilities(self) -> list[Capability]:
        return [Capability("search", "notes.read", Risk.READ)]

    def invoke(self, capability: str, arguments: Mapping[str, Any]) -> str:
        return "note-1"


class CachedNotesConnector(NotesConnector):
    def __init__(self, cache: Path, fail_delete: bool = False) -> None:
        self.cache = cache
        self.fail_delete = fail_delete

    def delete_cached_data(self) -> None:
        if self.fail_delete:
            raise OSError("cache unavailable")
        self.cache.unlink(missing_ok=True)


class RogueConnector(ReadOnlyConnector):
    name = "rogue"

    def read_capabilities(self) -> list[Capability]:
        return [Capability("post", "social.represent", Risk.REPRESENT)]

    def invoke(self, capability: str, arguments: Mapping[str, Any]) -> str:
        return ""


def test_grant_must_stay_within_declared_scopes():
    grants = ScopeGrants()
    with pytest.raises(GrantError):
        grants.grant(FixtureConnector(), {"mail.read", "mail.admin"})
    with pytest.raises(GrantError):
        grants.grant(FixtureConnector(), set())


def test_scope_enforcement_fail_closed():
    grants = ScopeGrants()
    grants.grant(FixtureConnector(), {"mail.read"})
    tools = {tool.name: tool for tool in connector_tools(FixtureConnector(), grants)}
    assert tools["mail:list"].run() == "list:inbox"
    with pytest.raises(ScopeDenied):
        tools["mail:archive"].run()
    grants.revoke("mail")
    with pytest.raises(ScopeDenied):
        tools["mail:list"].run()


def test_expired_grant_denies():
    grants = ScopeGrants()
    grants.grant(FixtureConnector(), {"mail.read"}, ttl_seconds=-1)
    with pytest.raises(ScopeDenied):
        connector_tools(FixtureConnector(), grants)[0].run()


def test_policy_wiring_requires_approval_for_write(tmp_path: Path):
    grants = ScopeGrants()
    grants.grant(FixtureConnector(), {"mail.read", "mail.write"})
    authority = ApprovalAuthority(b"host-secret")
    agent = Agent(connector_tools(FixtureConnector(), grants), Policy(approvals=authority), tmp_path / "audit.jsonl")

    read = agent.execute(Action("mail:list", {"folder": "inbox"}))
    assert read.status is ActionStatus.COMPLETED
    assert read.output == "list:inbox"

    write = Action("mail:archive", {"folder": "inbox"})
    assert agent.execute(write).status is ActionStatus.BLOCKED

    wrong_args = authority.issue(Action("mail:archive", {"folder": "trash"}))
    assert agent.execute(Action("mail:archive", {"folder": "inbox"}, approval_token=wrong_args)).status is (
        ActionStatus.BLOCKED
    )

    token = authority.issue(write)
    approved = Action("mail:archive", {"folder": "inbox"}, id=write.id, approval_token=token)
    assert agent.execute(approved).status is ActionStatus.COMPLETED
    assert agent.execute(approved).status is ActionStatus.BLOCKED, "approval is one-time"


def test_scope_denial_and_allowance_are_audited(tmp_path: Path):
    audit_path = tmp_path / "audit.jsonl"
    grants = ScopeGrants()
    agent = Agent(connector_tools(FixtureConnector(), grants), Policy(), audit_path)

    assert agent.execute(Action("mail:list")).status is ActionStatus.FAILED
    grants.grant(FixtureConnector(), {"mail.read"})
    assert agent.execute(Action("mail:list")).status is ActionStatus.COMPLETED

    ok, count, error = verify_chain(audit_path)
    assert ok, error
    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    assert count == 2
    assert records[0]["action"]["tool"] == "mail:list"
    assert records[0]["status"] == "failed"
    assert records[0]["error_code"] == "ScopeDenied"
    assert records[1]["status"] == "completed"


def test_read_only_connector_contract():
    tools = connector_tools(NotesConnector(), ScopeGrants())
    assert [tool.risk for tool in tools] == [Risk.READ]
    with pytest.raises(GrantError):
        connector_tools(RogueConnector(), ScopeGrants())


def test_revoke_and_delete_removes_cached_connector_data(tmp_path: Path):
    cache = tmp_path / "notes-cache.json"
    cache.write_text("private fixture data")
    connector = CachedNotesConnector(cache)
    grants = ScopeGrants()
    grants.grant(connector, {"notes.read"})

    grants.revoke_and_delete(connector)

    assert not cache.exists()
    assert not grants.allows("notes", "notes.read")


def test_failed_deletion_never_restores_revoked_access(tmp_path: Path):
    cache = tmp_path / "notes-cache.json"
    cache.write_text("private fixture data")
    connector = CachedNotesConnector(cache, fail_delete=True)
    grants = ScopeGrants()
    grants.grant(connector, {"notes.read"})

    with pytest.raises(OSError, match="cache unavailable"):
        grants.revoke_and_delete(connector)

    assert cache.exists(), "failed cleanup remains visible for a host retry"
    assert not grants.allows("notes", "notes.read"), "deletion failure must not reopen access"
