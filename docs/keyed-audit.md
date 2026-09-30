# Keyed audit chain (HMAC-SHA256)

Audit records are chained with HMAC-SHA256 instead of plain SHA-256. Each record
carries `chain: "hmac-sha256"` and a `key_id`, and its `hash` is
`HMAC(key, canonical JSON of the record without "hash")`, which also covers
`previous_hash`. Forging, editing, or extending a keyed chain requires the key,
not just write access to the audit file.

## Key storage

The key never lives in the workspace or the repository. `KeyringAuditKeys`
stores it in the OS credential store through the `keyring` package: macOS
Keychain, Windows Credential Manager, or libsecret on Linux. The store holds a
small JSON document (`{"current": key_id, "keys": {key_id: base64 key}}`); a key
id is the first 16 hex characters of the key's SHA-256, which identifies a key
without exposing it.

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
("unknown audit key id"), so rotation never prunes.

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
