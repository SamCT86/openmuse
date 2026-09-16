# OpenMuse

[![CI](https://github.com/tahodev/openmuse/actions/workflows/ci.yml/badge.svg)](https://github.com/tahodev/openmuse/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A local-first, auditable personal AI agent runtime. OpenMuse is independent and is not affiliated with or endorsed by Meta. It uses no Meta code, branding, or assets.

## What works now
- provider-neutral, budgeted multi-step planner loop
- typed actions and results with duplicate-safe tool registry
- read/write/represent/money risk classes
- host-issued, expiring, one-time approvals bound to exact action arguments
- hash-chained, redacted, permission-restricted audit log
- workspace-contained file tools and public-network-only HTTP fetch
- OpenAI-compatible planner adapter

## 60-second demo
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
openmuse read_file --args '{"path":"README.md"}'
openmuse write_file --args '{"path":"plan.md","content":"hello"}' # blocked
openmuse write_file --allow-writes --args '{"path":"plan.md","content":"hello"}'
pytest
```
Actions are recorded in `.openmuse/audit.jsonl`. Run `PYTHONPATH=src python examples/local_planner.py` for a complete planner-to-tool example.

## Architecture
`Goal -> Planner -> typed Action -> Policy/Approval -> Tool -> typed Result`, with redacted audit metadata at the trusted executor boundary. See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [roadmap](docs/roadmap.md).

## Direction
OpenMuse starts with a narrow privacy-first wedge: local files, then read-only mail and calendar. Durable jobs, provenance-aware memory, least-privilege connectors, isolated workers, and an out-of-model approval UI are planned before broad autonomy. Connector manifests will be versioned and may expose MCP compatibility without weakening OpenMuse risk metadata.

## Safety
The runtime is alpha software, not safe for sensitive unattended work. Webpages, messages, documents, and tool output are untrusted. Do not give it broad credentials. See [SECURITY.md](SECURITY.md).

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md), [governance](GOVERNANCE.md), and the [code of conduct](CODE_OF_CONDUCT.md).

## License
MIT.

## Product foundation (v0.3 preview)
OpenMuse now includes a minimal web-channel adapter, restart-safe SQLite task checkpoints, an envelope-encrypted secret vault, browser-worker domain/read-only policy, and escaped approval-page rendering. See [product foundation](docs/product-foundation.md). These pieces are deliberately separate so a model cannot directly read secrets or approve its own actions.
