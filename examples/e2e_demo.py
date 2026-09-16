"""One simple, deterministic OpenMuse safety story. No API key required."""

import argparse
import shutil
from pathlib import Path

from openmuse.approvals import ApprovalAuthority
from openmuse.channels import WebChannel
from openmuse.core import Agent
from openmuse.models import Action
from openmuse.policy import Policy
from openmuse.tasks import TaskStore
from openmuse.tools import ReadFile, WriteFile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--auto-approve", action="store_true", help="type yes for recordings/Codespaces")
    parser.add_argument("--workspace", default=".openmuse-demo")
    args = parser.parse_args()
    workspace = Path(args.workspace)
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir()
    (workspace / "inbox.txt").write_text("Prepare the Show HN launch", encoding="utf-8")

    channel = WebChannel()
    channel.submit("demo", "user", "Turn my inbox note into a launch plan and save it")
    message = channel.receive()
    tasks = TaskStore(workspace / "tasks.db")
    task = tasks.create(message.text, max_steps=3)
    print("1  Agent runs task: read inbox and draft launch plan")

    authority = ApprovalAuthority(b"demo-host-key")
    agent = Agent(
        [ReadFile(workspace), WriteFile(workspace)],
        Policy(approvals=authority),
        workspace / "audit.jsonl",
    )
    source = agent.execute(Action("read_file", {"path": "inbox.txt"})).output.strip()
    sensitive = Action("write_file", {"path": "plan.md", "content": f"# Plan\n\n- {source}\n"})
    blocked = agent.execute(sensitive)
    assert blocked.error_code == "approval_required"
    print("2  PAUSED before sensitive action: write plan.md")
    approved = "yes" if args.auto_approve else input("   Approve this one action? [y/N] ").strip().lower()
    if approved not in {"y", "yes"}:
        print("   Denied. Nothing was written.")
        return
    print("3  User approves exactly this write, once")
    approved_action = Action(sensitive.tool, sensitive.arguments, sensitive.id, authority.issue(sensitive))
    result = agent.execute(approved_action)
    assert result.output.startswith("wrote")

    tasks.checkpoint(task.id, 2, {"result": result.output}, "completed")
    response = (workspace / "plan.md").read_text(encoding="utf-8").strip()
    channel.send(message.conversation_id, response)
    print("4  Action runs; task completes")
    print("5  Audit proof saved: .openmuse-demo/audit.jsonl")
    print("   Verify it: python examples/verify_audit.py")


if __name__ == "__main__":
    main()
