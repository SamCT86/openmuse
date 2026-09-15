"""Built-in tools. Add integrations by implementing the Tool protocol."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.request import Request, urlopen

from .policy import Risk


class Tool(Protocol):
    name: str
    description: str
    risk: Risk

    def run(self, **kwargs: Any) -> str: ...


@dataclass
class ReadFile:
    name: str = "read_file"
    description: str = "Read a UTF-8 text file inside the workspace"
    risk: Risk = Risk.READ
    workspace: Path = Path.cwd()

    def run(self, path: str, **_: Any) -> str:
        root = self.workspace.resolve()
        target = (root / path).resolve()
        if root not in target.parents and target != root:
            raise ValueError("path escapes workspace")
        return target.read_text(encoding="utf-8")


@dataclass
class WriteFile:
    name: str = "write_file"
    description: str = "Write a UTF-8 text file inside the workspace"
    risk: Risk = Risk.WRITE
    workspace: Path = Path.cwd()

    def run(self, path: str, content: str, **_: Any) -> str:
        root = self.workspace.resolve()
        target = (root / path).resolve()
        if root not in target.parents and target != root:
            raise ValueError("path escapes workspace")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"wrote {target.relative_to(root)}"


@dataclass
class FetchURL:
    name: str = "fetch_url"
    description: str = "Fetch a public HTTP(S) URL"
    risk: Risk = Risk.READ

    def run(self, url: str, **_: Any) -> str:
        if not url.startswith(("https://", "http://")):
            raise ValueError("only HTTP(S) URLs are supported")
        request = Request(url, headers={"User-Agent": "OpenMuse/0.1"})
        with urlopen(request, timeout=15) as response:
            return response.read(200_000).decode("utf-8", errors="replace")


def describe(tool: Tool) -> dict[str, str]:
    return {"name": tool.name, "description": tool.description, "risk": tool.risk.value}


def parse_args(raw: str) -> dict[str, Any]:
    value = json.loads(raw or "{}")
    if not isinstance(value, dict):
        raise ValueError("tool arguments must be a JSON object")
    return value
