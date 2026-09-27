"""In-process code remains trusted; descriptor drift must not change policy."""
from copy import deepcopy

import pytest

from openmuse.core import Agent
from openmuse.models import Action, ActionStatus
from openmuse.policy import Policy, Risk
from openmuse.registry import ToolRegistry
from openmuse.worker_tool import WorkerTool


class MutableTool:
    name = "mutation"
    description = "host code"
    risk = Risk.WRITE
    def __init__(self):
        self.schema = {"type": "object", "additionalProperties": False}

    def manifest(self):
        return {"name": self.name, "description": self.description, "risk": self.risk.value, "schema": self.schema}

    def run(self, **kwargs):
        return "ran"


def test_registered_risk_and_manifest_cannot_be_mutated(tmp_path):
    tool = MutableTool()
    agent = Agent([tool], Policy(), tmp_path / "audit")
    tool.risk = Risk.READ
    tool.schema = {"type": "object"}
    catalogue = agent.registry.catalogue()
    catalogue[0]["risk"] = "read"
    catalogue[0]["schema"]["additionalProperties"] = True
    assert agent.execute(Action("mutation", {})).status is ActionStatus.BLOCKED
    assert agent.execute(Action("mutation", {"x": "unexpected"})).error_code == "invalid_arguments"


def test_invalid_identity_or_risk_rejected():
    tool = MutableTool()
    tool.risk = "read"
    with pytest.raises(ValueError):
        ToolRegistry([tool])


def test_worker_adapter_has_host_owned_read_only_contract():
    class FakeWorker:
        def run(self, request):
            assert request == {"arguments": {"x": 2}}
            return type("Result", (), {"output": {"value": 4}})()

    schema = {"type": "object", "properties": {"x": {"type": "integer"}}, "additionalProperties": False}
    original = deepcopy(schema)
    tool = WorkerTool(FakeWorker(), "square", "compute", schema)
    schema["additionalProperties"] = True
    assert tool.manifest()["schema"] == original
    assert tool.run(x=2) == '{"value": 4}'
    assert tool.risk is Risk.READ
