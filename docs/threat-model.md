# Threat model
## Assets
Credentials, private files, connector data, approvals, and user reputation or money.
## Attackers
Malicious webpages/messages, compromised connectors, prompt injection, a confused model, and local unprivileged processes.
## Controls
Least privilege, one-time action-bound approvals, path containment, single-resolution DNS pinning, SSRF checks, redirect blocking, output limits, redacted audit metadata, and fail-closed policy.
## Known gaps
No kernel-enforced network/filesystem sandbox, OS-backed master-key storage, full JSON Schema implementation, or production-ready human approval UI yet. Tool arguments are validated against a deliberately small object/required/properties/type subset; unsupported schema keywords fail closed. The local vault encrypts values at rest, but tools and key material still share the Python process. Use test data only.

## FetchURL network boundary
`FetchURL` resolves a destination once, rejects the entire DNS answer set if any address is non-public, and pins the connection to a validated address while preserving TLS hostname verification. Redirects are blocked rather than followed. These in-process controls reduce DNS rebinding and redirect SSRF risk, but they do not replace an OS-level network sandbox or egress proxy.


## Worker boundary
The built-in worker provides process separation, a scrubbed environment, dedicated working directory, and resource/output/time limits. It does not claim network or mount isolation. Production browser deployments must add a container, seccomp profile or VM plus an egress policy; tests must treat the child as hostile.
