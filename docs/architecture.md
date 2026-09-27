# Architecture
A planner proposes typed actions. The registry publishes tool manifests. Policy evaluates risk, and the executor runs one tool only after policy allows it. The audit sink records redacted metadata and hash-links entries. The model never receives host approval secrets.

Trust boundaries: planner output and all external content are untrusted; policy, approval authority, secret store, and tool sandbox belong to the trusted host. Connectors should run out of process in future releases.


## Isolated workers
`IsolatedWorker` runs an explicit JSON request in a fresh Python process with a dedicated working directory, scrubbed environment, wall-clock timeout, address-space/open-file/core limits, and bounded output. This is a real process boundary, not a full sandbox: network namespace, seccomp, filesystem mounts, and browser containment remain deployment responsibilities.


## Production connector boundary
`GoogleCalendarConnector` and `GoogleMailConnector` are read-only Google API adapters with exact grants, bounded results, fixed provider origins, runtime-only OAuth token callbacks, audit/policy wiring through `ConnectorTool`, and fail-closed revocation. `GoogleOAuthManager` builds the consent URL, exchanges authorization codes, refreshes expiring access tokens, validates scopes, and stores tokens in the encrypted vault. The embedding host still owns the loopback/web callback that verifies OAuth state and supplies the returned code.


The production composition is `SecretVault.open(path, KeyringMasterKey())`, then one `GoogleOAuthManager` per Google account/provider-scope set. Pass `manager.access_token` to a Google connector. The master key stays in the platform credential store; the vault file contains only envelope-encrypted records and is written with owner-only permissions. A missing system credential backend is an error, never a plaintext fallback. OAuth `state` verification and the redirect listener remain embedding-host responsibilities.

## Extension trust boundary (alpha)

`Agent` accepts **trusted host Python code**. Its tools and connectors run in the
host process with its filesystem, network, and credentials. Registration checks
manifest shape and freezes the host's risk/schema view against later drift, but
it cannot stop a malicious Python object from bypassing `run` or lying at
registration. Do not load unreviewed Python skills or connectors into the host.
A skill artifact (data/instructions) has no executable authority of its own.

`WorkerTool` is a narrow, read-only adapter for a host-configured
`ContainerWorker` pinned by digest. The host owns its descriptor; the worker
receives validated JSON arguments and has no host effect RPC. The container
profile requests no network or host mounts, but the deploying host must verify
those controls on its runtime. Untrusted extensions needing reads from host
services, writes, representation, or money are **not supported** by this alpha
adapter. Do not describe `IsolatedWorker` as a sandbox; its process and resource
limits do not isolate network or mounts. Web chat only registers built-in
trusted tools. Connector declarations/grants are useful for honest connectors,
not a security boundary against malicious in-process connector code.

## Audit crash semantics

The host fsyncs a default-deny intent record (action ID, registered tool name,
argument digest, no argument/output text) before calling a tool, then writes a
completion or failure record. A pending intent without an outcome after a crash
is **unknown**, not safe to retry: inspect the external effect before deciding
what happened. If the outcome write fails after the tool call, the result is
`audit_outcome_unknown` and `retryable=False`. The audit chain is tamper-evident
only relative to a trusted checkpoint; it is not independently anchored by
being stored locally. Audit records can show a tool was attempted but cannot
prove a third-party side effect completed.

## Local web approval restart policy

The web chat's pending action/card map and approval-token authority are
in-memory. This alpha flow is deliberately **ephemeral**, not restart-safe:
`ApprovalService` marks pending database rows interrupted on startup, so stale
approval links cannot run after a restart. The database stores the canonical
action ID with tool/arguments and checks it against the pending card. In-flight
external effects are not replayed or retried automatically; a production host
needs durable request recovery, authenticated identity, and reconciliation.

## Delegation quotas

A finite `Grant.max_uses` requires a host-owned `GrantLedger` backed by SQLite.
A descendant carries all ancestor budget IDs, and every redemption consumes
all applicable budgets in one immediate transaction. Siblings therefore cannot
reset a parent's quota by creating new child objects. Reusing the same token
is rejected by the durable redemption digest. The host must retain its ledger
file for the grant lifetime; deleting or replacing the file discards quota
history, so never treat it as disposable cache. The root token authority's
in-memory replay set is still ephemeral; ledger redemption digests persist.
