"""Credential-free typed tool example executed through the OpenMuse Agent path."""

from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, ClassVar

from openmuse.core import Agent
from openmuse.models import Action, ToolResult
from openmuse.policy import Policy, Risk
from openmuse.tools import ManifestMixin


@dataclass
class CountWords(ManifestMixin):
    name: str = "count_words"
    description: str = "Count words in supplied text"
    risk: Risk = Risk.READ
    schema: ClassVar[dict[str, Any]] = {
        "type": "object",
        "required": ["text"],
        "properties": {"text": {"type": "string", "maxLength": 1000}},
        "additionalProperties": False,
    }

    def run(self, text: str) -> str:
        return str(len(text.split()))


def run_demo(audit_log: Path) -> ToolResult:
    agent = Agent([CountWords()], Policy(), audit_log)
    return agent.execute(Action("count_words", {"text": "small tools stay auditable"}))


def main() -> int:
    with TemporaryDirectory() as tmp:
        result = run_demo(Path(tmp) / "audit.jsonl")
    print(f"{result.status.value}: {result.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
