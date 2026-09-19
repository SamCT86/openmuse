# Changelog

All notable changes are recorded here. OpenMuse follows semantic versioning while using prerelease tags for alpha builds.

## Unreleased

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
