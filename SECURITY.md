# Security

OpenMuse is alpha software with no production-supported release. Report vulnerabilities using a [private GitHub security advisory](https://github.com/tahodev/openmuse/security/advisories/new), never a public issue.

## Current limits

The local vault encrypts secret values with per-secret AES-256-GCM data keys wrapped by an AES-256-GCM master key. OpenMuse does not yet integrate that master key with an OS keychain or hardware-backed store, and tools still share the Python process. URL filtering does not pin DNS across the connection, the hash-chained audit is not externally anchored, and the approval UI is experimental. Use test accounts and non-sensitive data.

See the [threat model](docs/threat-model.md) and [production gate](docs/roadmap.md).
