# Changelog

All notable changes are recorded here. OpenMuse follows semantic versioning while using prerelease tags for alpha builds.

## Unreleased

- Fix approval verification race: one-time token consumption is now atomic under a lock, so concurrent `verify` calls cannot consume one approval twice (#7).
- Define the approval expiry boundary: a token is expired when `now >= exp`; the exact expiry second is rejected, with boundary tests (#7).

- Align project metadata and runtime version.
- Tighten onboarding, security limits, CI, packaging, and contribution guidance.
