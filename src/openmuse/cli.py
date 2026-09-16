import argparse
import json
from pathlib import Path

from .core import Agent
from .models import Action
from .policy import Policy
from .tools import FetchURL, ReadFile, WriteFile


def main():
    p = argparse.ArgumentParser(prog="openmuse")
    p.add_argument("tool", choices=["read_file", "write_file", "fetch_url"])
    p.add_argument("--args", default="{}")
    p.add_argument("--workspace", type=Path, default=Path.cwd())
    p.add_argument("--allow-writes", action="store_true")
    a = p.parse_args()
    w = a.workspace.resolve()
    r = Agent([ReadFile(w), WriteFile(w), FetchURL()], Policy(a.allow_writes), w / ".openmuse/audit.jsonl").execute(
        Action(a.tool, json.loads(a.args))
    )
    print(r.output)
    raise SystemExit(0 if r.status.value == "completed" else 2)


if __name__ == "__main__":
    main()
