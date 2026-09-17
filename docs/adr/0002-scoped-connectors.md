# ADR 0002: Scoped connector interface

## Status
Accepted (2026-09-17)

## Context
Connectors to mail, calendar, and similar services widen the trust boundary.
Muse-style stacks advertise least privilege but rarely bind it to an
enforceable mechanism. OpenMuse already has exact-action, one-time approvals;
connectors must ride on that instead of gaining ambient access.

## Decision
- A connector declares `Capability` entries, each with a scope string and a
  risk tier. Declaration is the ceiling: no grant can exceed it.
- `ScopeGrants` is host-owned and the only writer of permissions. Grants are
  per-connector, optionally expiring, and revocable. Plain `revoke()` removes
  authority immediately. Connectors that retain local data expose the optional
  `ConnectorLifecycle.delete_cached_data()` hook; `revoke_and_delete()` removes
  authority before calling it. If cleanup fails, the error is surfaced while
  access stays revoked, so the host can retry without reopening the boundary.
- Every capability is exposed as a `ConnectorTool`, so calls flow through the
  existing policy check as exact actions (tool name `connector:capability`
  plus exact arguments) and land in the redacted hash-chained audit log,
  including denials.
- `ReadOnlyConnector` is the default shape for first integrations (#4): it
  rejects any declared capability that is not risk `read` with a `.read`
  scope, so write and representation actions are undeclarable, not merely
  disallowed at call time.
- Simulation fixtures carry no live credentials; production OAuth apps are
  out of scope here.

## Consequences
- New connectors enumerate their access up front, reviewable in code.
- Approval UX stays uniform: approving `mail:archive` with exact arguments
  uses the same one-time token as `write_file`.
- Denials are observable in the audit trail, which is the debugging and
  incident-review path.
- Revocation and local-data deletion are separate, ordered lifecycle events:
  revocation is always first and cannot be rolled back by a cleanup failure.
