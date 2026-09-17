# Threat model
## Assets
Credentials, private files, connector data, approvals, and user reputation or money.
## Attackers
Malicious webpages/messages, compromised connectors, prompt injection, a confused model, and local unprivileged processes.
## Controls
Least privilege, one-time action-bound approvals, path containment, SSRF checks, output limits, redacted audit metadata, and fail-closed policy.
## Known gaps
No OS sandbox, OS-backed master-key storage, DNS pinning, full JSON Schema validation, or production-ready human approval UI yet. The local vault encrypts values at rest, but tools and key material still share the Python process. Use test data only.
