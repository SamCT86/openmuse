"""Host registry for trusted Python tools and explicitly sandboxed worker tools.

Python objects execute with host authority. Registration never makes third-party
Python safe: only trusted host code belongs in this registry. Descriptors are
snapshotted so a tool cannot change its advertised risk after registration.
"""

from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from .policy import Risk
from .tools import Tool


@dataclass(frozen=True)
class RegisteredTool:
    tool: Tool
    risk: Risk
    descriptor: dict[str, Any]


class ToolRegistry:
    def __init__(self, tools: Iterable[Tool] = ()) -> None:
        self._tools: dict[str, RegisteredTool] = {}
        for tool in tools:
            self.add(tool)

    def add(self, tool: Tool) -> None:
        # This validates shape, not provenance. The embedding host must vet all
        # in-process Python; untrusted code belongs in a separately deployed worker.
        name = getattr(tool, "name", None)
        risk = getattr(tool, "risk", None)
        if not isinstance(name, str) or not name or not isinstance(risk, Risk):
            raise ValueError("tool requires a name and valid risk")
        manifest = deepcopy(tool.manifest())
        if manifest.get("name") != name or manifest.get("risk") != risk.value:
            raise ValueError("tool manifest does not match its declared identity")
        schema = manifest.get("schema")
        if schema is not None and not isinstance(schema, dict):
            raise ValueError("tool schema must be an object")
        if name in self._tools:
            raise ValueError(f"duplicate tool: {name}")
        self._tools[name] = RegisteredTool(tool, risk, manifest)

    def get(self, name: str) -> Tool | None:
        registered = self._tools.get(name)
        return registered.tool if registered else None

    def descriptor(self, name: str) -> RegisteredTool | None:
        return self._tools.get(name)

    def catalogue(self) -> list[dict[str, Any]]:
        return [deepcopy(entry.descriptor) for entry in self._tools.values()]
