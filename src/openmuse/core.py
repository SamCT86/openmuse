import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .audit import AuditLog
from .models import Action, ActionStatus, ToolResult
from .policy import Policy
from .registry import ToolRegistry


class Planner(Protocol):
    def plan(self, goal: str, tools: list[dict], history: list[ToolResult]) -> Action | None: ...


class Agent:
    def __init__(self, tools, policy: Policy, audit_log: Path):
        self.registry = ToolRegistry(tools)
        self.policy = policy
        self.audit = AuditLog(audit_log)

    def execute(self, action: Action) -> ToolResult:
        tool = self.registry.get(action.tool)
        if not tool:
            return ToolResult(action.id, ActionStatus.FAILED, error_code="unknown_tool")
        d = self.policy.check(tool.risk, action)
        if not d.allowed:
            r = ToolResult(action.id, ActionStatus.BLOCKED, d.reason, "approval_required")
        else:
            try:
                r = ToolResult(action.id, ActionStatus.COMPLETED, str(tool.run(**dict(action.arguments))))
            except (OSError, ValueError, TypeError, KeyError) as e:
                r = ToolResult(action.id, ActionStatus.FAILED, str(e), type(e).__name__, False)
        self.audit.append(
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "action": {"id": action.id, "tool": action.tool, "arguments": action.arguments},
                "status": r.status.value,
                "error_code": r.error_code,
                "output_sha256": hashlib.sha256(r.output.encode()).hexdigest(),
            }
        )
        return r

    def run(self, goal: str, planner: Planner, max_steps=8):
        history = []
        for _ in range(max_steps):
            action = planner.plan(goal, self.registry.catalogue(), history)
            if action is None:
                break
            result = self.execute(action)
            history.append(result)
            if result.status in {ActionStatus.BLOCKED, ActionStatus.FAILED}:
                break
        return history
