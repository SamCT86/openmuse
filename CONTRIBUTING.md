# Contributing

## Set up

1. Fork the repository and branch from `main`.
2. Use Python 3.11 or newer.
3. Run `python -m venv .venv`, activate it, then `pip install -e '.[dev]'`.
4. Before opening a pull request, run:

```bash
ruff check src tests
mypy src/openmuse
pytest --cov=openmuse --cov-fail-under=85
python examples/e2e_demo.py --auto-approve
python examples/verify_audit.py
python -m build
```

## A first contribution

Start with an unassigned [`good first issue`](https://github.com/tahodev/openmuse/labels/good%20first%20issue). Read its acceptance criteria and say you're taking it before starting, so another volunteer doesn't duplicate your work. If it involves code, add or update a test; for docs, test the command on the platform you document. Keep unrelated cleanups out of the PR.

You can run a focused check while iterating (for example, `pytest tests/test_web_chat.py -q`); run the full set above before asking for review. In the PR, link the issue, give exact reproduction or verification commands, and call out whether your change touches a trust boundary. If an issue is unclear, ask on that issue rather than guessing at permission behavior.

## Changes to trust boundaries

Open an issue before changing the permission model, approvals, audit format, connector scopes, data retention, or secret handling. Describe assets, attackers, failure modes, revocation, simulation behavior, and the tests that prove fail-closed behavior. Changes to these boundaries need an ADR in `docs/adr/`, threat-model updates, tests, and maintainer approval.

## Connectors

Start read-only, request the smallest scopes, document data flow and deletion/revocation, support simulation where possible, and never put credentials or private payloads in fixtures, logs, or issues.

## Pull requests

Keep changes small. Explain the user-visible behavior, trust-boundary impact, compatibility risk, and test evidence. Update docs with behavior changes and complete the pull-request checklist.

## Releases

Maintainers use semantic versioning with prerelease tags for alpha work. A release must pass CI, build from a clean checkout, match `openmuse.__version__`, include release notes, and be checked on TestPyPI before PyPI.
