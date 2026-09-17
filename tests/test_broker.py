"""Secrets broker: raw secrets stay out of planner-visible surfaces."""

import hashlib
import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from openmuse.audit import AuditLog, verify_chain
from openmuse.broker import BrokerError, SecretBroker
from openmuse.core import Agent
from openmuse.models import Action, ActionStatus
from openmuse.policy import Policy, Risk
from openmuse.secrets import SecretVault
from openmuse.tools import ManifestMixin

PLAINTEXT = "s3cr3t-value"


class SigningTool(ManifestMixin):
    name = "sign_request"
    description = "Sign a request body with the API secret"
    risk = Risk.REPRESENT
    secret_name = "api_token"

    schema: ClassVar[dict] = {"type": "object", "required": ["body"], "properties": {"body": {"type": "string"}}}

    def run_with_secret(self, secret: str, **kwargs: Any) -> str:
        return hashlib.sha256(f"{secret}:{kwargs['body']}".encode()).hexdigest()[:16]


class LeakySchemaTool(SigningTool):
    def manifest(self):
        return {
            "name": self.name,
            "description": self.description,
            "risk": self.risk.value,
            "schema": {"type": "object", "properties": {"secret": {"type": "string"}}},
        }


def make_broker(tmp_path: Path) -> SecretBroker:
    vault = SecretVault(tmp_path / "vault.json", b"k" * 32)
    vault.put("api_token", PLAINTEXT)
    return SecretBroker(vault, AuditLog(tmp_path / "audit.jsonl"))


def test_secret_flows_to_tool_without_touching_arguments(tmp_path: Path):
    broker = make_broker(tmp_path)
    tool = broker.tool(SigningTool())
    expected = hashlib.sha256(f"{PLAINTEXT}:hello".encode()).hexdigest()[:16]
    assert tool.run(body="hello") == expected
    assert PLAINTEXT not in json.dumps(tool.manifest())


def test_secret_as_argument_fails_closed(tmp_path: Path):
    broker = make_broker(tmp_path)
    tool = broker.tool(SigningTool())
    with pytest.raises(BrokerError):
        tool.run(body="x", secret="injected")
    with pytest.raises(BrokerError):
        tool.run(body="x", api_token="injected")


def test_schema_declaring_secret_is_rejected(tmp_path: Path):
    broker = make_broker(tmp_path)
    with pytest.raises(BrokerError):
        broker.tool(LeakySchemaTool())


def test_unknown_secret_fails_closed_through_agent(tmp_path: Path):
    broker = make_broker(tmp_path)
    broker.vault = SecretVault(tmp_path / "empty.json", b"k" * 32)
    authority_policy = Policy(allow_writes=True)
    agent = Agent([broker.tool(SigningTool())], authority_policy, tmp_path / "agent-audit.jsonl")
    # REPRESENT risk with no approvals: blocked before the vault is touched.
    assert agent.execute(Action("sign_request", {"body": "x"})).status is ActionStatus.BLOCKED


def test_access_is_audited_by_name_only(tmp_path: Path):
    broker = make_broker(tmp_path)
    tool = broker.tool(SigningTool())
    tool.run(body="hello")
    audit_text = (tmp_path / "audit.jsonl").read_text()
    assert "secret_access" in audit_text
    assert "api_token" in audit_text
    assert PLAINTEXT not in audit_text
    ok, _, error = verify_chain(tmp_path / "audit.jsonl")
    assert ok, error


def test_catalogue_carries_no_secret(tmp_path: Path):
    broker = make_broker(tmp_path)
    agent = Agent([broker.tool(SigningTool())], Policy(), tmp_path / "audit.jsonl")
    catalogue = json.dumps(agent.registry.catalogue())
    assert PLAINTEXT not in catalogue
    assert "api_token" not in catalogue
