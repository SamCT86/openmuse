# Roadmap
- v0.2 secure local runtime: typed actions, bound approvals, SSRF/path tests, CI.
- v0.3 planner and jobs: provider adapters, checkpoints, cancellation, budgets.
- v0.4 memory: provenance, retention, inspect/edit/forget; searchable tiered memory with hash-chained, verifiable writes and edits (done).
- v0.5 connectors: read-only mail/calendar first, simulation mode, scoped OAuth; scoped connector interface with least-privilege grants plus credential-free mail/calendar simulations and a production-capable read-only Google Calendar API connector landed (ADR 0002); managed Google OAuth refresh/storage and a read-only Gmail connector have now landed; an independently deployed callback and non-Google providers remain.
- v0.6 isolated workers and approval UI; secrets broker and narrowing subagent grants landed; cron scheduler with atomic multi-worker claims landed.
Production gate: independent security review (brief/checklist prepared), threat-suite pass, encrypted secrets with OS-keyring master key, sandboxing, and connector revocation tests.
