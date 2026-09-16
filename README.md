# OpenMuse

[![CI](https://github.com/tahodev/openmuse/actions/workflows/ci.yml/badge.svg)](https://github.com/tahodev/openmuse/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tahodev/openmuse?quickstart=1)

A local-first, auditable personal AI agent runtime. OpenMuse separates untrusted planners from typed tools, host-issued approvals, durable tasks, encrypted secrets, and redacted audit history.

> Independent project. Not affiliated with or endorsed by Meta. No Meta code, branding, or assets are used.

## See the safety boundary in 30 seconds

One simple story: the agent starts a task, pauses before one write, the user approves exactly that action, it runs, and the audit chain proves what happened.

[![Play the real terminal recording](https://asciinema.org/a/Chk900SOWiRk0YwJ.svg)](https://asciinema.org/a/Chk900SOWiRk0YwJ)

This is a real terminal capture. Its raw, replayable cast is also [checked into the repository](docs/assets/openmuse-demo.cast).

## Run it

The quickest path opens a ready Python environment and runs the demo automatically:

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tahodev/openmuse?quickstart=1)

Or run locally with Python 3.11+ and Git:

```bash
git clone https://github.com/tahodev/openmuse.git
cd openmuse
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
python examples/e2e_demo.py
```

The deterministic demo needs no API key. It keeps the existing web-channel and durable-task flow, but makes the one sensitive write and its host-issued approval visible.

## Verify, don't trust

After the demo, independently recompute every audit hash and link:

```bash
python examples/verify_audit.py
```

Expected result:

```text
VERIFIED: 3 records form an intact hash chain
```

Change any audited byte and verification fails. The verifier is intentionally small: [examples/verify_audit.py](examples/verify_audit.py) calls the public [`verify_chain`](src/openmuse/audit.py) function. The audit contains a blocked attempt, the approved action, and its execution result.

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
| Persistent task thread + approval primitives | Experimental |
| Production browser sandbox and connectors | Not yet |
| Ephemeral OTP grants + exact-total validation | Working |
| Provenance-aware memory + forget | Working |

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
