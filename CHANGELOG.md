# Changelog

All notable changes are recorded here. OpenMuse follows semantic versioning while using prerelease tags for alpha builds.

## Unreleased

- Add the verifiable memory layer: memory gains working/curated tiers, and every remember, promote, and forget is mirrored into the hash-chained audit log; `verify_memory` reconciles state against the chain to detect out-of-band insertions, tampered facts, and unlogged tombstones (#9).

- Add the scoped connector interface: capabilities declare least-privilege scopes, host-owned grants can never exceed declarations, revocation and expiry fail closed, and every call flows through exact-action policy and the audit chain (#8, closes the #4 read-only connector contract groundwork via ADR 0002).

- Fix approval verification race: one-time token consumption is now atomic under a lock, so concurrent `verify` calls cannot consume one approval twice (#7).
- Define the approval expiry boundary: a token is expired when `now >= exp`; the exact expiry second is rejected, with boundary tests (#7).

- Align project metadata and runtime version.
- Tighten onboarding, security limits, CI, packaging, and contribution guidance.
