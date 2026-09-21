# Security

OpenMuse is alpha software with no production-supported release. Report vulnerabilities using a [private GitHub security advisory](https://github.com/tahodev/openmuse/security/advisories/new) or email [kexim.pnh@gmail.com](mailto:kexim.pnh@gmail.com), never a public issue.

Vulnerabilities can also be disclosed through [huntr](https://huntr.com/bounties/disclose), an AI/ML bug bounty platform.

## Current limits

The local vault encrypts secret values with per-secret AES-256-GCM data keys wrapped by an AES-256-GCM master key. The master key can be stored in the OS keyring through `KeyringMasterKey`, which fails closed when no usable system credential backend exists; hardware-backed storage is not yet integrated, and tools still share the Python process. `FetchURL` resolves a destination once, rejects the entire DNS answer set if any address is non-public, and pins the connection to a validated address while preserving TLS hostname verification; redirects are blocked rather than followed. The hash-chained audit is not externally anchored, and the approval UI is experimental. Use test accounts and non-sensitive data.

See the [threat model](docs/threat-model.md) and [production gate](docs/roadmap.md).
