"""Scoped connectors: least-privilege declarations enforced at the boundary.

A connector declares capabilities; each capability carries a scope string and a
risk tier. The runtime only routes a call when the host has granted that exact
scope to that connector, the grant is unexpired and unrevoked, and the action
passes the policy layer like any other exact action. Grants can never exceed
the connector's declared scopes.
"""

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .policy import Risk
from .tools import ManifestMixin


@dataclass(frozen=True)
class Capability:
    name: str
    scope: str
    risk: Risk
    schema: dict[str, Any] = field(default_factory=lambda: {"type": "object"})


class Connector(Protocol):
    name: str

    def capabilities(self) -> list[Capability]: ...
    def invoke(self, capability: str, arguments: Mapping[str, Any]) -> str: ...


@dataclass(frozen=True)
class Grant:
    scopes: frozenset[str]
    expires_at: float | None = None


class GrantError(ValueError):
    pass


class ScopeGrants:
    """Host-owned grant ledger; the only writer of scope permissions."""

    def __init__(self) -> None:
        self._grants: dict[str, Grant] = {}

    def grant(self, connector: Connector, scopes: set[str], ttl_seconds: int | None = None) -> Grant:
        declared = {capability.scope for capability in connector.capabilities()}
        if not scopes or not set(scopes) <= declared:
            raise GrantError("grant exceeds the connector's declared scopes")
        grant = Grant(
            frozenset(scopes),
            None if ttl_seconds is None else time.time() + ttl_seconds,
        )
        self._grants[connector.name] = grant
        return grant

    def revoke(self, connector_name: str) -> None:
        self._grants.pop(connector_name, None)

    def allows(self, connector_name: str, scope: str) -> bool:
        grant = self._grants.get(connector_name)
        if grant is None or scope not in grant.scopes:
            return False
        return grant.expires_at is None or time.time() < grant.expires_at


class ScopeDenied(ValueError):
    pass


class ConnectorTool(ManifestMixin):
    """Expose one connector capability as a policy-checked tool."""

    def __init__(self, connector: Connector, capability: Capability, grants: ScopeGrants) -> None:
        self.connector = connector
        self.capability = capability
        self.grants = grants
        self.name = f"{connector.name}:{capability.name}"
        self.description = f"Connector {connector.name} capability {capability.name} (scope {capability.scope})"
        self.risk = capability.risk
        self.schema = capability.schema

    def run(self, **kwargs: Any) -> str:
        if not self.grants.allows(self.connector.name, self.capability.scope):
            raise ScopeDenied(f"scope not granted: {self.connector.name}/{self.capability.scope}")
        return self.connector.invoke(self.capability.name, kwargs)


def connector_tools(connector: Connector, grants: ScopeGrants) -> list[ConnectorTool]:
    return [ConnectorTool(connector, capability, grants) for capability in connector.capabilities()]


class ReadOnlyConnector:
    """Base for read-only connectors: write and representation are undeclarable."""

    name = "readonly"

    def capabilities(self) -> list[Capability]:
        declared = self.read_capabilities()
        for capability in declared:
            if capability.risk is not Risk.READ or not capability.scope.endswith(".read"):
                raise GrantError("read-only connectors may only declare read capabilities")
        return declared

    def read_capabilities(self) -> list[Capability]:
        raise NotImplementedError

    def invoke(self, capability: str, arguments: Mapping[str, Any]) -> str:
        raise NotImplementedError
