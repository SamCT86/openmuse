"""Provider-neutral agent loop with an append-only audit log."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .policy import Policy
from .tools import Tool, parse_args


@dataclass(frozen=True)
class Action:
    tool: str
    arguments: str = "{}"
    approval: str | None = None


class Agent:
    def __init__(self, tools: Iterable[Tool], policy: Policy, audit_log: Path) -> None:
        self.tools = {tool.name: tool for tool in tools}
        self.policy = policy
        self.audit_log = audit_log

    def execute(self, action: Action) -> str:
        tool = self.tools.get(action.tool)
        if tool is None:
            raise KeyError(f"unknown tool: {action.tool}")
        decision = self.policy.check(tool.risk, action.approval)
        if not decision.allowed:
            self._audit(action, "blocked", decision.reason)
            return f"BLOCKED: {decision.reason}"
        try:
            result = tool.run(**parse_args(action.arguments))
        except Exception as exc:
            self._audit(action, "error", f"{type(exc).__name__}: {exc}")
            raise
        self._audit(action, "completed", result[:500])
        return result

    def run(self, goal: str, planner: Callable[[str, list[dict[str, str]]], Action]) -> str:
        """Ask a model-backed planner for one action, then execute it safely."""
        catalogue = [
            {"name": t.name, "description": t.description, "risk": t.risk.value}
            for t in self.tools.values()
        ]
        return self.execute(planner(goal, catalogue))

    def _audit(self, action: Action, status: str, detail: str) -> None:
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "at": datetime.now(timezone.utc).isoformat(),
            "action": asdict(action),
            "status": status,
            "detail": detail,
        }
        with self.audit_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
