import io
import json

from openmuse.models import ActionStatus, ToolResult
from openmuse.providers.openai_compatible import OpenAICompatiblePlanner


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_provider_returns_typed_action(monkeypatch):
    payload = {"choices": [{"message": {"content": json.dumps({"tool": "read_file", "arguments": {"path": "README.md"}})}}]}
    monkeypatch.setattr("openmuse.providers.openai_compatible.urlopen", lambda request, timeout: Response(json.dumps(payload).encode()))
    planner = OpenAICompatiblePlanner(api_key="test")
    action = planner.plan("read", [], [ToolResult("1", ActionStatus.COMPLETED, "ok")])
    assert action is not None
    assert action.tool == "read_file"
    assert action.arguments == {"path": "README.md"}


def test_provider_done(monkeypatch):
    payload = {"choices": [{"message": {"content": json.dumps({"done": True})}}]}
    monkeypatch.setattr("openmuse.providers.openai_compatible.urlopen", lambda request, timeout: Response(json.dumps(payload).encode()))
    assert OpenAICompatiblePlanner(api_key="test").plan("done", [], []) is None

def test_provider_requires_key():
    import pytest
    with pytest.raises(ValueError,match="API key"): OpenAICompatiblePlanner(api_key="")

def test_provider_rejects_oversized_response(monkeypatch):
    import pytest
    monkeypatch.setattr("openmuse.providers.openai_compatible.urlopen",lambda request,timeout: Response(b"x"*11))
    with pytest.raises(Exception,match="too large"): OpenAICompatiblePlanner(api_key="x",max_response_bytes=10).plan("x",[],[])
