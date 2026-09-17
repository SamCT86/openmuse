"""Subagent authority: delegated approvals that can only narrow, never widen.

A parent holds the root ApprovalAuthority. It hands a subagent a
DelegatedAuthority bounded by a Grant; the subagent may verify tokens only
inside that grant and may further delegate only strictly narrower grants.
Narrowing is enforced at construction, so privilege cannot grow down the tree.
"""

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .approvals import ApprovalAuthority
from .audit import AuditLog
from .models import Action


@dataclass(frozen=True)
class Grant:
    tools: frozenset[str]
    max_uses: int | None = None
    expires_at: float | None = None
    constraints: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def is_subset_of(self, parent: "Grant") -> bool:
        if not self.tools <= parent.tools:
            return False
        if parent.max_uses is not None and (self.max_uses is None or self.max_uses > parent.max_uses):
            return False
        if parent.expires_at is not None and (self.expires_at is None or self.expires_at > parent.expires_at):
            return False
        for tool, required in parent.constraints.items():
            if tool in self.tools:
                mine = self.constraints.get(tool, {})
                if not all(mine.get(key) == value for key, value in required.items()):
                    return False
        return True

    def is_strictly_narrower_than(self, parent: "Grant") -> bool:
        if not self.is_subset_of(parent):
            return False
        if self.tools < parent.tools:
            return True
        if self.max_uses is not None and self.max_uses != parent.max_uses:
            return True
        if self.expires_at is not None and self.expires_at != parent.expires_at:
            return True
        return any(
            set(self.constraints.get(tool, {}).items()) > set(parent.constraints.get(tool, {}).items())
            for tool in self.tools
        )


class GrantError(ValueError):
    pass


class DelegatedAuthority:
    def __init__(
        self,
        root: ApprovalAuthority,
        grant: Grant,
        audit: AuditLog | None = None,
        parent_grant: Grant | None = None,
    ) -> None:
        if parent_grant is not None and not grant.is_strictly_narrower_than(parent_grant):
            raise GrantError("a delegated grant must be strictly narrower than its parent")
        self.root = root
        self.grant = grant
        self.audit = audit
        self.uses = 0
        if audit is not None:
            audit.append(
                {
                    "event": "delegate",
                    "tools": sorted(grant.tools),
                    "max_uses": grant.max_uses,
                    "expires_at": grant.expires_at,
                    "constraints": {k: dict(v) for k, v in grant.constraints.items()},
                }
            )

    def verify(self, action: Action, token: str | None) -> bool:
        if not self._within_grant(action):
            return False
        if not self.root.verify(action, token):
            return False
        self.uses += 1
        return True

    def narrow(self, grant: Grant, audit: AuditLog | None = None) -> "DelegatedAuthority":
        return DelegatedAuthority(self.root, grant, audit or self.audit, parent_grant=self.grant)

    def _within_grant(self, action: Action) -> bool:
        if action.tool not in self.grant.tools:
            return False
        if self.grant.max_uses is not None and self.uses >= self.grant.max_uses:
            return False
        if self.grant.expires_at is not None and time.time() >= self.grant.expires_at:
            return False
        return all(
            action.arguments.get(key) == value
            for key, value in self.grant.constraints.get(action.tool, {}).items()
        )
