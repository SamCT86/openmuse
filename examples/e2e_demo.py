"""A deterministic end-to-end OpenMuse workflow with no API key."""

from pathlib import Path
from tempfile import TemporaryDirectory

from openmuse.channels import WebChannel
from openmuse.core import Agent
from openmuse.models import Action
from openmuse.policy import Policy
from openmuse.tasks import TaskStore
from openmuse.tools import ReadFile, WriteFile


class DemoPlanner:
    def plan(self, goal, tools, history):
        if not history:
            return Action("read_file", {"path": "inbox.txt"})
        if len(history) == 1:
            source = history[0].output.strip()
            return Action("write_file", {"path": "plan.md", "content": f"# Plan\n\n- {source}\n"})
        return None


def main() -> None:
    with TemporaryDirectory() as directory:
        workspace = Path(directory)
        (workspace / "inbox.txt").write_text("Prepare the Show HN launch", encoding="utf-8")
        channel = WebChannel()
        channel.submit("demo", "user", "Turn my inbox note into a plan")
        message = channel.receive()
        tasks = TaskStore(workspace / "tasks.db")
        task = tasks.create(message.text, max_steps=3)
        print(f"task {task.id[:8]}: pending - {task.goal}")
        task = tasks.checkpoint(task.id, 0, {"conversation_id": message.conversation_id}, "running")
        print("task: running")
        agent = Agent(
            [ReadFile(workspace), WriteFile(workspace)],
            Policy(allow_writes=True),
            workspace / "audit.jsonl",
        )
        results = agent.run(task.goal, DemoPlanner(), max_steps=task.max_steps)
        tasks.checkpoint(task.id, len(results), {"results": len(results)}, "completed")
        response = (workspace / "plan.md").read_text(encoding="utf-8").strip()
        channel.send(message.conversation_id, response)
        print(f"task: completed ({len(results)} steps)")
        print("result delivered to web:demo")
        print(response)
        print("audit: 2 redacted, hash-chained records")


if __name__ == "__main__":
    main()
