"""Subagent authority: delegated approvals that can only narrow, never widen.

A parent holds the root ApprovalAuthority. It hands a subagent a
DelegatedAuthority bounded by a Grant; the subagent may verify tokens only
inside that grant and may further delegate only strictly narrower grants.
Narrowing is enforced at construction, so privilege cannot grow down the tree.
"""

import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

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


class GrantLedger:
    """Host-owned durable quota ledger shared by descendants and sibling workers."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS quota(grant_id TEXT PRIMARY KEY, used INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS redemptions(token_digest TEXT PRIMARY KEY)")

    def consume(self, budgets: tuple[tuple[str, int], ...], token: str) -> bool:
        import hashlib

        digest = hashlib.sha256(token.encode()).hexdigest()
        with sqlite3.connect(self.path, timeout=10, isolation_level=None) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                if db.execute("SELECT 1 FROM redemptions WHERE token_digest=?", (digest,)).fetchone():
                    db.rollback()
                    return False
                for grant_id, limit in budgets:
                    count = db.execute("SELECT used FROM quota WHERE grant_id=?", (grant_id,)).fetchone()
                    if count is not None and count[0] >= limit:
                        db.rollback()
                        return False
                for grant_id, _ in budgets:
                    db.execute(
                        "INSERT INTO quota(grant_id,used) VALUES(?,1) "
                        "ON CONFLICT(grant_id) DO UPDATE SET used=used+1", (grant_id,)
                    )
                db.execute("INSERT INTO redemptions(token_digest) VALUES(?)", (digest,))
                db.commit()
                return True
            except BaseException:
                db.rollback()
                raise


class DelegatedAuthority:
    def __init__(
        self,
        root: ApprovalAuthority,
        grant: Grant,
        audit: AuditLog | None = None,
        parent_grant: Grant | None = None,
        ledger: GrantLedger | None = None,
        ancestor_budgets: tuple[tuple[str, int], ...] = (),
    ) -> None:
        if parent_grant is not None and not grant.is_strictly_narrower_than(parent_grant):
            raise GrantError("a delegated grant must be strictly narrower than its parent")
        self.root = root
        self.grant = grant
        self.audit = audit
        self.ledger = ledger
        self.grant_id = uuid4().hex
        if grant.max_uses is not None and ledger is None:
            raise GrantError("quota requires a host-owned durable grant ledger")
        self.budgets = ancestor_budgets + (((self.grant_id, grant.max_uses),) if grant.max_uses is not None else ())
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
        return not self.budgets or (
            token is not None and self.ledger is not None and self.ledger.consume(self.budgets, token)
        )

    def narrow(self, grant: Grant, audit: AuditLog | None = None) -> "DelegatedAuthority":
        return DelegatedAuthority(
            self.root, grant, audit or self.audit, parent_grant=self.grant,
            ledger=self.ledger, ancestor_budgets=self.budgets,
        )

    def _within_grant(self, action: Action) -> bool:
        if action.tool not in self.grant.tools:
            return False
        if self.grant.expires_at is not None and time.time() >= self.grant.expires_at:
            return False
        return all(
            action.arguments.get(key) == value
            for key, value in self.grant.constraints.get(action.tool, {}).items()
        )
