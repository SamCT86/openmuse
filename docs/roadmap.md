# Roadmap
- v0.2 secure local runtime: typed actions, bound approvals, SSRF/path tests, CI (done).
- v0.3 planner and jobs: provider adapters (OpenAI-compatible planner), SQLite checkpoints, cancellation, and bounded budgets (done).
- v0.4 memory: provenance, retention, inspect/edit/forget; searchable tiered memory with hash-chained, verifiable writes and edits (done).
- v0.5 connectors: read-only mail/calendar first, simulation mode, scoped OAuth; scoped connector interface with least-privilege grants plus credential-free mail/calendar simulations and production-capable read-only Google Calendar and Gmail connectors landed (ADR 0002) with managed OAuth code exchange, refresh, and encrypted token storage; an independently deployed callback and non-Google providers remain.
- v0.6 isolated workers and approval UI; secrets broker and narrowing subagent grants landed; cron scheduler with atomic multi-worker claims landed; resource-limited OS process worker landed. A mount-free container worker profile with no network and a read-only root landed; VM isolation, deployment validation, and a production approval UI remain.
Production gate: independent security review (brief/checklist prepared), threat-suite pass, OS-keyring master-key storage (landed, fails closed without a backend), kernel/network sandboxing, and connector revocation coverage.
