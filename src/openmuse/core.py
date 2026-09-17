import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .audit import AuditLog
from .models import Action, ActionStatus, ToolResult
from .policy import Policy
from .registry import ToolRegistry
from .validation import SchemaValidationError, validate_arguments


class Planner(Protocol):
    def plan(self, goal: str, tools: list[dict], history: list[ToolResult]) -> Action | None: ...


class Agent:
    def __init__(self, tools, policy: Policy, audit_log: Path) -> None:
        self.registry = ToolRegistry(tools)
        self.policy = policy
        self.audit = AuditLog(audit_log)

    def execute(self, action: Action) -> ToolResult:
        tool = self.registry.get(action.tool)
        if not tool:
            return ToolResult(action.id, ActionStatus.FAILED, error_code="unknown_tool")
        try:
            validate_arguments(action.arguments, tool.manifest().get("schema"))
        except SchemaValidationError as exc:
            r = ToolResult(action.id, ActionStatus.FAILED, str(exc), "invalid_arguments")
            self._audit(action, r)
            return r
        d = self.policy.check(tool.risk, action)
        if not d.allowed:
            r = ToolResult(action.id, ActionStatus.BLOCKED, d.reason, "approval_required")
        else:
            try:
                r = ToolResult(action.id, ActionStatus.COMPLETED, str(tool.run(**dict(action.arguments))))
            except (OSError, ValueError, TypeError, KeyError) as e:
                r = ToolResult(action.id, ActionStatus.FAILED, str(e), type(e).__name__, False)
        self._audit(action, r)
        return r

    def _audit(self, action: Action, result: ToolResult) -> None:
        self.audit.append(
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "action": {"id": action.id, "tool": action.tool, "arguments": action.arguments},
                "status": result.status.value,
                "error_code": result.error_code,
                "output_sha256": hashlib.sha256(result.output.encode()).hexdigest(),
            }
        )

    def run(self, goal: str, planner: Planner, max_steps: int = 8) -> list[ToolResult]:
        history: list[ToolResult] = []
        for _ in range(max_steps):
            action = planner.plan(goal, self.registry.catalogue(), history)
            if action is None:
                break
            result = self.execute(action)
            history.append(result)
            if result.status in {ActionStatus.BLOCKED, ActionStatus.FAILED}:
                break
        return history
