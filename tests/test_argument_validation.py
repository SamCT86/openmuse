from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from openmuse.core import Agent
from openmuse.models import Action, ActionStatus
from openmuse.policy import Policy, Risk
from openmuse.tools import ManifestMixin, WriteFile


@dataclass
class CountTool(ManifestMixin):
    name: str = "count"
    description: str = "Accept a count"
    risk: Risk = Risk.READ
    schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "required": ["count"],
        "properties": {"count": {"type": "integer"}},
        "additionalProperties": False,
    }

    def run(self, count: int) -> str:
        return str(count)


def agent(tmp_path: Path, tool) -> Agent:
    return Agent([tool], Policy(allow_writes=True), tmp_path / "audit.jsonl")


def test_missing_required_argument_fails_before_tool_call(tmp_path):
    result = agent(tmp_path, WriteFile(tmp_path)).execute(Action("write_file", {"path": "x"}))
    assert result.status is ActionStatus.FAILED
    assert result.error_code == "invalid_arguments"
    assert not (tmp_path / "x").exists()


def test_wrong_type_and_unknown_argument_fail_closed(tmp_path):
    runtime = agent(tmp_path, CountTool())
    assert runtime.execute(Action("count", {"count": "1"})).error_code == "invalid_arguments"
    assert runtime.execute(Action("count", {"count": 1, "extra": True})).error_code == "invalid_arguments"


def test_valid_arguments_execute(tmp_path):
    result = agent(tmp_path, CountTool()).execute(Action("count", {"count": 2}))
    assert result.status is ActionStatus.COMPLETED
    assert result.output == "2"


def test_unsupported_schema_keyword_fails_closed(tmp_path):
    tool = CountTool()
    tool.schema = {"type": "object", "properties": {}, "oneOf": []}
    result = agent(tmp_path, tool).execute(Action("count", {}))
    assert result.error_code == "invalid_arguments"
