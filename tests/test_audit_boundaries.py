import json

import pytest

from openmuse.audit import AuditLog, verify_chain
from openmuse.core import Agent
from openmuse.models import Action, ActionStatus
from openmuse.policy import Policy, Risk
from openmuse.tools import ManifestMixin


class SensitiveTool(ManifestMixin):
    name = "secret_operation"
    description = "test"
    risk = Risk.WRITE
    calls = 0

    def __init__(self):
        self.schema = {"type": "object"}

    def run(self, **kwargs):
        self.calls += 1
        return "Bearer ghp-private-output"


def test_durable_intent_precedes_effect_and_no_plaintext(tmp_path):
    tool = SensitiveTool()
    path = tmp_path / "audit"
    agent = Agent([tool], Policy(allow_writes=True), path)
    secret = "ghp_private_token_123"
    result = agent.execute(Action(tool.name, {"content": {"ordinary_field": secret}}))
    assert result.status is ActionStatus.COMPLETED
    assert tool.calls == 1
    assert secret not in path.read_text()
    assert "ghp-private-output" not in path.read_text()
    assert [r["status"] for r in map(json.loads, path.read_text().splitlines())] == ["proposed", "completed"]
    assert verify_chain(path) == (True, 2, None)


def test_failed_pre_effect_append_prevents_execution(tmp_path, monkeypatch):
    tool = SensitiveTool()
    agent = Agent([tool], Policy(allow_writes=True), tmp_path / "audit")

    def fail(_record):
        raise OSError("disk full")

    monkeypatch.setattr(agent.audit, "append", fail)
    with pytest.raises(OSError, match="disk full"):
        agent.execute(Action(tool.name, {}))
    assert tool.calls == 0


def test_unknown_tool_is_audited_without_untrusted_name(tmp_path):
    agent = Agent([], Policy(), tmp_path / "audit")
    result = agent.execute(Action("Bearer private tool", {"content": "secret"}))
    assert result.error_code == "unknown_tool"
    log = (tmp_path / "audit").read_text()
    assert "Bearer private tool" not in log and "secret" not in log
    assert verify_chain(tmp_path / "audit") == (True, 1, None)


def test_append_rejects_incomplete_tail(tmp_path):
    path = tmp_path / "audit"
    path.write_text('{"incomplete":true}')
    with pytest.raises(ValueError, match="incomplete"):
        AuditLog(path).append({"event": "next"})
    assert path.read_text() == '{"incomplete":true}'


def test_failed_outcome_audit_returns_unknown_without_reexecution(tmp_path, monkeypatch):
    tool = SensitiveTool()
    agent = Agent([tool], Policy(allow_writes=True), tmp_path / "audit")
    append = agent.audit.append
    calls = 0

    def fail_after_effect(record):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("disk full")
        append(record)

    monkeypatch.setattr(agent.audit, "append", fail_after_effect)
    result = agent.execute(Action(tool.name, {}))
    assert tool.calls == 1
    assert result.error_code == "audit_outcome_unknown" and not result.retryable
    assert [r["status"] for r in map(json.loads, (tmp_path / "audit").read_text().splitlines())] == ["proposed"]
