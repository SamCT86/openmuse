"""Secrets broker: tools receive secrets through a side channel.

The planner proposes actions with ordinary arguments only. A tool that needs a
secret declares `secret_name`; the broker resolves it from the vault at
execution time and injects the plaintext into the tool's `run_with_secret`
callback, which the vault wipes after use. Secret values therefore never appear
in action arguments, tool manifests, planner context, or the audit log - only
the access itself is audited, by name.
"""

from datetime import datetime, timezone
from typing import Any, Protocol

from .audit import AuditLog
from .policy import Risk
from .secrets import SecretVault
from .tools import ManifestMixin


class SecretConsumingTool(Protocol):
    name: str
    description: str
    risk: Risk
    secret_name: str

    def manifest(self) -> dict[str, Any]: ...
    def run_with_secret(self, secret: str, **kwargs: Any) -> str: ...


class BrokerError(ValueError):
    pass


class _BrokeredTool(ManifestMixin):
    def __init__(self, inner: SecretConsumingTool, vault: SecretVault, audit: AuditLog | None) -> None:
        schema = dict(inner.manifest().get("schema") or {})
        properties = schema.get("properties") or {}
        if "secret" in properties or inner.secret_name in properties:
            raise BrokerError("secret arguments are forbidden in tool schemas")
        self.inner = inner
        self.vault = vault
        self.audit = audit
        self.name = inner.name
        self.description = inner.description
        self.risk = inner.risk
        self.schema = schema

    def run(self, **kwargs: Any) -> str:
        if "secret" in kwargs or self.inner.secret_name in kwargs:
            raise BrokerError("secrets never arrive as action arguments")
        box: dict[str, str] = {}

        def consume(plaintext: str) -> None:
            box["output"] = self.inner.run_with_secret(plaintext, **kwargs)

        self.vault.use(self.inner.secret_name, consume)
        if self.audit is not None:
            self.audit.append(
                {
                    "event": "secret_access",
                    "tool": self.name,
                    "secret_name": self.inner.secret_name,
                    "at": datetime.now(timezone.utc).isoformat(),
                }
            )
        return box["output"]


class SecretBroker:
    """Wraps secret-consuming tools so the planner never sees raw secrets."""

    def __init__(self, vault: SecretVault, audit: AuditLog | None = None) -> None:
        self.vault = vault
        self.audit = audit

    def tool(self, inner: SecretConsumingTool) -> _BrokeredTool:
        return _BrokeredTool(inner, self.vault, self.audit)
