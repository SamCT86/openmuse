# OpenMuse

An independent, open-source personal AI agent runtime that keeps tools,
permissions and audit history explicit.

> **Project status:** early MVP. OpenMuse is not affiliated with or endorsed by
> Meta. "Muse" and related product names may be trademarks of their owners.
> This repository uses no Meta code, branding or assets.

## Why

Personal agents should be inspectable. OpenMuse provides a small foundation for
turning a goal into a tool call without hiding the important boundaries:

- **Local-first runtime:** files and audit logs stay in a workspace you choose.
- **Provider-neutral core:** connect any model by implementing the `planner`
  callback. No model SDK is required by the runtime.
- **Capability-based tools:** each tool declares its name, purpose and risk.
- **Approval gates:** reads run by default; writes require opt-in; representation
  and money actions require explicit, per-action approval.
- **Append-only audit log:** completed, blocked and failed actions are recorded
  as JSON Lines.
- **Safe starter tools:** workspace-scoped file read/write and bounded HTTP(S)
  fetch.

## Quick start

```bash
git clone https://github.com/tahodev/openmuse.git
cd openmuse
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

openmuse read_file --args '{"path":"README.md"}'
openmuse write_file --args '{"path":"notes/idea.md","content":"hello"}'
# BLOCKED until writes are enabled for this run:
openmuse write_file --allow-writes \
  --args '{"path":"notes/idea.md","content":"hello"}'

pytest
```

Actions are written to `.openmuse/audit.jsonl` in the selected workspace.

## Use with a model

A planner receives the goal and the available tool catalogue, then returns one
`Action`. This keeps model integration outside the trusted execution core.

```python
from pathlib import Path
from openmuse.core import Action, Agent
from openmuse.policy import Policy
from openmuse.tools import ReadFile

agent = Agent([ReadFile()], Policy(), Path(".openmuse/audit.jsonl"))

def planner(goal, tools):
    # Replace with your model call and validate its structured output.
    return Action("read_file", '{"path":"README.md"}')

print(agent.run("Summarize the README", planner))
```

## Architecture

```text
Goal -> planner adapter -> typed Action -> Policy -> Tool -> Result
                                  |           |
                                  +---- audit-+
```

The core does not receive credentials. Future connectors should use narrowly
scoped tokens and secret stores, never model-visible plaintext.

## MVP scope

Included now:

- synchronous one-action execution
- tool registry and provider-neutral planner interface
- four risk classes: `read`, `write`, `represent`, `money`
- workspace path containment
- JSONL audit trail
- dependency-free CLI and tests

Planned next:

1. multi-step plans with budgets, cancellation and resumable jobs
2. encrypted connector credentials and OAuth adapters
3. isolated tool workers with network allowlists
4. human approval UI with action diffs
5. memory with provenance, retention controls and a forget command
6. connectors for mail, calendar and browser automation
7. threat-model document and prompt-injection test suite

## Security model

OpenMuse treats tool output, webpages and messages as untrusted data. The MVP
blocks writes by default and confines file tools to one workspace. It is not yet
safe for unattended production use. Do not give it broad account credentials.
See [SECURITY.md](SECURITY.md) for reporting and current limits.

## Contributing

Small, testable changes are welcome. Open an issue before adding a connector or
changing the permission model. Run `pytest` before submitting a pull request.

## License

MIT. See [LICENSE](LICENSE).
