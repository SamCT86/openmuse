# Changelog

## 0.4.0a0 (2026-09-30)

Changes since the 0.3.0a0 distribution and v0.3.0-alpha tag.

### First run
- Local browser chat with an offline planner, host-rendered exact-action approval cards, CSRF checks, and localhost-only binding.
- An installed `openmuse-chat` startup smoke test using an ephemeral port and a temporary workspace, with bounded readiness and teardown.
- A Windows CI trial exposed POSIX-only audit locking and workspace file APIs. Native Windows remains unsupported; issue #30 stays open. No weaker compatibility fallback was added.
- A fresh Docker rehearsal measures provisioning, README installation, first approved action, audit verification, and chat startup against a 15-minute limit.
- README activation commands and audit record count match the current demo.

### Runtime and safety boundaries
- Full JSON Schema 2020-12 argument validation and host-registered tool descriptors; mutable extensions cannot silently change registered risk or schema.
- Audit intent persisted before tool effects, digest-only action matching, bounded append/stream verification, and fail-closed audit regressions.
- Persistent single-use approval service and restart invalidation of orphaned web-chat approval cards.
- Shared durable delegation quotas and tests for sibling contention.
- Scheduler lease tokens, explicit unknown crash states, and UTC-instant iteration across DST gaps and folds.
- Anchored, no-follow workspace file operations and symlink-swap regressions on supported POSIX systems.
- Kernel-bounded subprocess capture and timeouts for isolated workers and the default container runner.
- Restricted read-only container worker adapter, container conformance suite, and reference image.
- Signed audit checkpoints and an immutable HTTPS checkpoint publisher adapter.
- Google OAuth revocation before local deletion and a disposable-account lifecycle harness.

### Extension and maintenance
- Supported trusted extension protocol, stable exports, extension cookbook, and runnable typed-tool example.
- Public API and scheduling semantics, deployment guidance, independent review evidence generator, and documentation link checks.
- Python-version-specific pinned CI dependencies and safety-boundary regression jobs.
- README architecture diagram, comparison table, first-contribution path, and project status refresh.

### Limits
This is an alpha runtime, not an independently audited production assistant. Python extensions remain trusted host code. The shared-key secret-service protocol returns plaintext to an authorized caller and is an experimental demonstration, not an isolation guarantee. POSIX descriptor protections do not imply equivalent Windows file-tool isolation. Container/VM deployment, OAuth callback operation, independent checkpoint storage, and external security review remain operator responsibilities.

## v0.3.0-alpha - 2026-09-19

### Added

- Managed Google OAuth with authorization-code exchange, automatic refresh, encrypted token storage, and OS-keyring-backed master keys.
- Read-only Gmail and Google Calendar connectors built on scoped, least-privilege grants, plus credential-free local simulation connectors.
- Searchable and editable working/curated memory with hash-chained remember, promote, edit, and forget events, plus state verification against the audit chain.
- Five-field cron scheduling with atomic job claims across workers, and subagent grants that can only narrow tools, budgets, expiry, and argument constraints.
- A secrets broker that passes named secrets to tools through a scoped execution side channel without exposing plaintext to planner context, manifests, action arguments, or audit logs.
- A fresh-process isolated worker with bounded runtime, memory, file descriptors, output, environment, and workspace.
- An independent security-review packet with a reviewer brief and checklist.

### Changed

- The approval demo now shows the exact tool, path, content preview, and SHA-256 being approved, then verifies that the approved action is the action executed.
- Connector revocation now clears cached clients and fails closed if cleanup does not complete.
- Tool arguments are validated before approval, policy checks, and execution.
- `FetchURL` now resolves once and pins connections to validated public addresses to prevent DNS-rebinding bypasses.
- Project metadata and runtime version are aligned for this prerelease.

### Fixed

- Approval tokens are consumed atomically, preventing concurrent verification from using one approval twice.
- Approval expiry now rejects tokens at the exact expiry boundary (`now >= exp`).
- Scheduled jobs are claimed transactionally so parallel workers cannot run the same job twice.

### Known limitations

- OpenMuse remains alpha software for test accounts and non-sensitive data. Documentation drift in the security limits is being cleaned up separately.
