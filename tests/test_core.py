from pathlib import Path

from openmuse.core import Action, Agent
from openmuse.policy import Policy
from openmuse.tools import ReadFile, WriteFile


def test_read_allowed_and_audited(tmp_path: Path) -> None:
    (tmp_path / "note.txt").write_text("hello", encoding="utf-8")
    agent = Agent([ReadFile(workspace=tmp_path)], Policy(), tmp_path / "audit.jsonl")
    assert agent.execute(Action("read_file", '{"path":"note.txt"}')) == "hello"
    assert '"status": "completed"' in (tmp_path / "audit.jsonl").read_text()


def test_write_blocked_by_default(tmp_path: Path) -> None:
    agent = Agent([WriteFile(workspace=tmp_path)], Policy(), tmp_path / "audit.jsonl")
    result = agent.execute(Action("write_file", '{"path":"x","content":"y"}'))
    assert result.startswith("BLOCKED:")
    assert not (tmp_path / "x").exists()


def test_write_stays_in_workspace(tmp_path: Path) -> None:
    agent = Agent([WriteFile(workspace=tmp_path)], Policy(allow_writes=True), tmp_path / "audit.jsonl")
    agent.execute(Action("write_file", '{"path":"notes/x","content":"y"}'))
    assert (tmp_path / "notes/x").read_text() == "y"
