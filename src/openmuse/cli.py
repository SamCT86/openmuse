"""Command line interface for the deterministic MVP runtime."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import Action, Agent
from .policy import Policy
from .tools import FetchURL, ReadFile, WriteFile


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="openmuse")
    value.add_argument("tool", choices=["read_file", "write_file", "fetch_url"])
    value.add_argument("--args", default="{}", help="JSON object passed to the tool")
    value.add_argument("--workspace", type=Path, default=Path.cwd())
    value.add_argument("--allow-writes", action="store_true")
    value.add_argument("--approve", action="store_true", help="approve a high-impact action")
    return value


def main() -> None:
    args = parser().parse_args()
    workspace = args.workspace.resolve()
    agent = Agent(
        [ReadFile(workspace=workspace), WriteFile(workspace=workspace), FetchURL()],
        Policy(allow_writes=args.allow_writes),
        workspace / ".openmuse" / "audit.jsonl",
    )
    action = Action(args.tool, json.dumps(json.loads(args.args)), "approved" if args.approve else None)
    print(agent.execute(action))


if __name__ == "__main__":
    main()
