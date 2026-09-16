# OpenMuse

[![CI](https://github.com/tahodev/openmuse/actions/workflows/ci.yml/badge.svg)](https://github.com/tahodev/openmuse/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A local-first, auditable personal AI agent runtime. OpenMuse separates untrusted planners from typed tools, host-issued approvals, durable tasks, encrypted secrets, and redacted audit history.

> Independent project. Not affiliated with or endorsed by Meta. No Meta code, branding, or assets are used.

## Try it in under 5 minutes

Requires Python 3.11+ and Git.

```bash
git clone https://github.com/tahodev/openmuse.git
cd openmuse
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
python examples/e2e_demo.py
```

The deterministic demo needs no API key and exercises a web-channel message, durable SQLite task, two-step planner, workspace tools, result delivery, and hash-chained audit log.

![OpenMuse end-to-end demo](docs/assets/demo.svg)

## Status

| Capability | Status |
|---|---|
| Typed, budgeted agent loop | Working |
| Exact-action, expiring, one-time approvals | Working |
| Workspace file tools + SSRF-resistant public fetch | Working |
| Redacted hash-chained audit | Working |
| SQLite task checkpoints/cancel/restart | Working |
| In-process web channel adapter | Experimental |
| Envelope-encrypted local secret vault | Experimental |
| Browser-worker policy envelope | Experimental |
| Hosted chat/approval UI | Not yet |
| Production browser sandbox and connectors | Not yet |
| OTP broker and exact-total purchase flow | Not yet |
| Provenance-aware memory + forget | Not yet |

Do not use OpenMuse with sensitive production accounts yet. “Working” means covered by the current test suite, not externally audited.

## How it works

`Channel -> durable Task -> Planner -> typed Action -> Policy/Approval -> Tool -> typed Result`

The model cannot mint approval tokens. Secret decryption happens through a host callback, not planner context. See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [product foundation](docs/product-foundation.md), and [roadmap](docs/roadmap.md).

## Use a real model

`OpenAICompatiblePlanner` supports OpenAI-compatible chat-completions endpoints. Set `OPENAI_API_KEY` and provide the planner to `Agent.run()`. The deterministic demo remains the recommended first run because it is free and reproducible.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [governance](GOVERNANCE.md), and the [code of conduct](CODE_OF_CONDUCT.md).

## License

MIT.
