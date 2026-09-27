import hashlib
import json
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
        registered = self.registry.descriptor(action.tool)
        tool = registered.tool if registered else None
        if registered is None or tool is None:
            result = ToolResult(action.id, ActionStatus.FAILED, error_code="unknown_tool")
            self._audit(action, result)
            return result
        try:
            validate_arguments(action.arguments, registered.descriptor.get("schema"))
        except SchemaValidationError:
            result = ToolResult(action.id, ActionStatus.FAILED, error_code="invalid_arguments")
            self._audit(action, result)
            return result
        decision = self.policy.check(registered.risk, action)
        if not decision.allowed:
            result = ToolResult(action.id, ActionStatus.BLOCKED, decision.reason, "approval_required")
            self._audit(action, result)
            return result
        # This durable intent must succeed before an effect is allowed to start.
        self._audit(action, ToolResult(action.id, ActionStatus.PROPOSED), event="intent")
        try:
            result = ToolResult(action.id, ActionStatus.COMPLETED, str(tool.run(**dict(action.arguments))))
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, TimeoutError) as exc:
            result = ToolResult(action.id, ActionStatus.FAILED, str(exc), type(exc).__name__, False)
        try:
            self._audit(action, result, event="outcome")
        except (OSError, ValueError):
            # An effect could already have occurred. Never suggest a safe retry.
            return ToolResult(action.id, ActionStatus.FAILED, error_code="audit_outcome_unknown", retryable=False)
        return result

    def _audit(self, action: Action, result: ToolResult, event: str = "decision") -> None:
        # A default-deny projection. Never persist raw arguments, outputs or
        # exception strings, regardless of key names or nested shape.
        raw = json.dumps(action.arguments, sort_keys=True, separators=(",", ":"), default=str)
        self.audit.append(
            {
                "at": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "action": {
                    "id": action.id,
                    "tool": action.tool if self.registry.get(action.tool) else "[unknown]",
                    "arguments_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                },
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
