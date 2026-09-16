import pytest

from openmuse.approvals import ApprovalAuthority
from openmuse.core import Agent
from openmuse.models import Action, ActionStatus
from openmuse.policy import Policy
from openmuse.registry import ToolRegistry
from openmuse.tools import ReadFile, WriteFile


def runtime(p, allow=False, auth=None):
    return Agent([ReadFile(p), WriteFile(p)], Policy(allow, auth), p / "audit")


def test_read(tmp_path):
    (tmp_path / "x").write_text("ok")
    assert runtime(tmp_path).execute(Action("read_file", {"path": "x"})).output == "ok"


def test_write_blocked(tmp_path):
    assert runtime(tmp_path).execute(Action("write_file", {"path": "x", "content": "y"})).status is ActionStatus.BLOCKED


def test_approval_bound_one_time(tmp_path):
    auth = ApprovalAuthority(b"x" * 32)
    a = Action("write_file", {"path": "x", "content": "y"})
    token = auth.issue(a)
    approved = Action(a.tool, a.arguments, a.id, token)
    r = runtime(tmp_path, auth=auth)
    assert r.execute(approved).status is ActionStatus.COMPLETED
    assert r.execute(approved).status is ActionStatus.BLOCKED


def test_traversal(tmp_path):
    assert (
        runtime(tmp_path, True).execute(Action("write_file", {"path": "../x", "content": "y"})).status
        is ActionStatus.FAILED
    )


def test_duplicate(tmp_path):
    with pytest.raises(ValueError):
        ToolRegistry([ReadFile(tmp_path), ReadFile(tmp_path)])
