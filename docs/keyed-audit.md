# Keyed audit chain (HMAC-SHA256)

Audit records are chained with HMAC-SHA256 instead of plain SHA-256. Each record
carries `chain: "hmac-sha256"` and a `key_id`, and its `hash` is
`HMAC(key, canonical JSON of the record without "hash")`, which also covers
`previous_hash`. Forging, editing, or extending a keyed chain requires the key,
not just write access to the audit file.

## Key storage

The key never lives in the workspace or the repository. `KeyringAuditKeys`
stores it in the OS credential store through the `keyring` package: macOS
Keychain, Windows Credential Manager, or libsecret on Linux. Only those OS
stores are accepted - the backend is checked against an allowlist, because
plaintext-file and in-memory keyring backends report a positive priority and
a priority check alone would wave them through.

Each key is its own credential *target* (service
`openmuse-agent.audit-hmac-key.<key id>`) and a small pointer credential
(service `openmuse-agent.audit-hmac-key`) names the current key id. A key id
is the first 16 hex characters of the key's SHA-256, which identifies a key
without exposing it. One target per key serves two purposes:

- **Size.** Windows Credential Manager caps a credential at 2560 UTF-16
  bytes; a single growing JSON document hits that cap after roughly 18
  rotations. Every credential here stays far below the limit, so rotation
  has no practical count bound beyond the store's entry capacity.
- **Concurrency.** OS stores offer no compare-and-swap, so a shared
  read-modify-write document loses keys when two rotations race (the loser's
  overwrite drops the winner's key, orphaning the records it covers). The
  Windows adapter additionally keeps one credential per service name and
  read-modify-writes that target non-atomically (a displaced value is moved
  to a compound `{username}@{service}` target), so even distinct accounts
  under one shared service can lose a value when writes race. With one
  target per key, writers never share mutable state: each rotation writes a
  fresh, disjoint credential, moves the pointer, then re-reads it and
  converges on the winner. Every key ever handed out stays resolvable.

`FileAuditKeys` serializes its document read-modify-write with a sibling
`.lock` file (an OS-held lock, released automatically if a writer dies).

Stores written by the pre-split format (one JSON document under the
`audit-hmac-keys` account of service `openmuse-agent`) keep working: the
first `current()` migrates every key into its own target and deletes the
document (best effort), and `resolve` falls back to the legacy document so
existing keyed history verifies even before migration runs.

The runtime fails closed when no credential store is available: append raises
`AuditKeyError` before the audit file is even created, and verification reports
failure. There is no silent fallback to unkeyed chains.

`OPENMUSE_AUDIT_KEY_FILE` selects an explicit key file (`FileAuditKeys`) for
disposable containers, demos, and CI where no OS credential service exists. The
file must be owner-only (`0600`); loose permissions fail closed on POSIX. A key
file next to the audit log is **not** a security boundary - anyone who can write
the log can usually read the file - so it is strictly an operator's explicit
choice, never a fallback.

## Backward compatibility and migration

Chains written before keying (plain SHA-256 links, no `chain` field) still
verify without a key. No rewrite is needed: keep appending, and the chain
switches to keyed records at the next write. A mixed chain may contain legacy
records only before the first keyed record; the first keyed record's HMAC covers
the legacy head hash, so the legacy prefix can no longer be altered without the
key. Keyed records can never be followed by legacy ones - that downgrade fails
verification.

Verification of a migrated chain therefore keeps its old assurance for the
legacy prefix (a wholesale replacement of an all-legacy file was never
detectable locally) and keyed assurance from the boundary onward. For full
strength, publish a signed checkpoint at upgrade time (see
[audit-anchoring](audit-anchoring.md)) or start a fresh keyed audit file.
Deployments that know their chain must be entirely keyed can call
`verify_chain(path, store, require_keyed=True)`, which rejects any unkeyed
record.

## Rotation

`store.rotate()` retires the current key and generates a fresh one; new records
use the new key id. Retired keys stay in the store so existing history remains
verifiable. Deleting a retired key makes the records it covers unverifiable
("unknown audit key id"), so rotation never prunes. Rotation has no count
limit: each key is a separate credential, so the Windows Credential Manager
credential-size cap does not apply to the store as a whole.

Records are caller data plus chain fields; the chain fields (`hash`,
`previous_hash`, `chain`, `key_id`) are reserved. `append` rejects a record
that sets any of them rather than overwriting or trusting the caller's value.

## Residual limits

- A process running as the same OS user with access to the credential store can
  still read the key and forge history. The keyed chain defends the workspace
  boundary (tools, sandboxed workers, other users); it is not a boundary against
  the user's own unsandboxed processes.
- Truncating or wholesale replacing the audit file is only detectable through
  externally anchored signed checkpoints, exactly as before.
- Verifying a keyed chain requires key access. An independent reviewer verifies
  either a legacy chain, or a keyed chain on a machine holding the key (or an
  exported key file the operator chooses to provide).
