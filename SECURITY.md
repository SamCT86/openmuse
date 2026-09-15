# Security

## Supported versions

OpenMuse is an early MVP and has no production-supported release yet.

## Reporting a vulnerability

Please open a private security advisory in this GitHub repository. Do not open a
public issue for a vulnerability that could expose credentials or user data.

## Current limits

- Tools run in the same Python process; there is no OS sandbox yet.
- HTTP fetch has a byte limit but no network allowlist or SSRF protection.
- The audit log is local plaintext and is not tamper-evident.
- The sample approval token is an integration hook, not an authentication
  system.

Use only test accounts and non-sensitive data until these limits are addressed.
