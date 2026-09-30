# Changelog

## 0.4.0a0 (2026-09-30)

Changes since the 0.3.0a0 distribution and v0.3.0-alpha tag.

### First run
- Local browser chat with an offline planner, host-rendered exact-action approval cards, CSRF checks, and localhost-only binding.
- An installed `openmuse-chat` startup smoke test using an ephemeral port and a temporary workspace, with bounded readiness and teardown.
- Windows PowerShell CI exercises the README install, approval demo, audit verifier, and browser-chat entrypoint.
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

## 0.3.0a0 (2026-09-19)

First PyPI release. Read-only Gmail and Google Calendar connectors, managed OAuth, OS keyring master-key support, process-worker boundary, approval and audit demos, and deployment documentation. See the v0.3.0-alpha tag for the exact source baseline.
