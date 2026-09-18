# Security review readiness checklist

Use this before asking an independent reviewer to assess a release. Record evidence links, not only yes/no answers.

## Trust boundaries
- [ ] Planner input and external content are treated as untrusted data.
- [ ] Every tool publishes an accurate risk tier and fail-closed argument schema.
- [ ] Write, representation, and money actions require an exact, expiring, one-time host approval.
- [ ] Concurrent approval and scheduled-job claims have deterministic race tests.

## Files and network
- [ ] Workspace traversal and symlink escapes are blocked and tested.
- [ ] Public fetch resolves once, rejects mixed/private answers, pins the peer, blocks redirects, and bounds output.
- [ ] Worker deployment adds a network namespace/egress policy and restricted mounts; process limits alone are not called a sandbox.

## Connectors and secrets
- [ ] Connector scopes are a declared ceiling; revocation is tested before cached-data deletion.
- [ ] OAuth tokens enter through host callbacks, never planner arguments/manifests/audit payloads.
- [ ] Token refresh, revocation and provider deletion have integration tests with a disposable account.
- [ ] Master keys come from an OS-backed store and are not colocated with tool processes.

## Audit and memory
- [ ] Audit redaction, hash linking and independent verification cover all mutations.
- [ ] Memory writes/edits/forget operations reconcile to the audit chain.
- [ ] Out-of-band memory insertion and provenance drift fail verification.

## Release evidence
- [ ] Ruff, mypy, full tests, coverage floor, build, installed-wheel smoke test, CodeQL and dependency checks pass.
- [ ] Threat model known gaps match the implementation and deployment.
- [ ] No live credentials, private data, internal email addresses or generated state are in history/artifacts.
- [ ] Reviewer findings have owners, severity, reproduction steps and a public remediation record when safe.
