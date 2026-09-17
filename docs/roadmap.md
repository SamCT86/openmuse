# Roadmap
- v0.2 secure local runtime: typed actions, bound approvals, SSRF/path tests, CI.
- v0.3 planner and jobs: provider adapters, checkpoints, cancellation, budgets.
- v0.4 memory: provenance, retention, inspect/edit/forget; searchable tiered memory with hash-chained, verifiable writes and edits (done).
- v0.5 connectors: read-only mail/calendar first, simulation mode, scoped OAuth; scoped connector interface with least-privilege grants plus credential-free mail/calendar simulations landed (ADR 0002).
- v0.6 isolated workers and approval UI; secrets broker and narrowing subagent grants landed; cron scheduler landed.
Production gate: third-party security review, threat-suite pass, encrypted secrets, sandboxing, and connector revocation tests.
