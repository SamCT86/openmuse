# Architecture
A planner proposes typed actions. The registry publishes tool manifests. Policy evaluates risk, and the executor runs one tool only after policy allows it. The audit sink records redacted metadata and hash-links entries. The model never receives host approval secrets.

Trust boundaries: planner output and all external content are untrusted; policy, approval authority, secret store, and tool sandbox belong to the trusted host. Connectors should run out of process in future releases.


## Isolated workers
`IsolatedWorker` runs an explicit JSON request in a fresh Python process with a dedicated working directory, scrubbed environment, wall-clock timeout, address-space/open-file/core limits, and bounded output. This is a real process boundary, not a full sandbox: network namespace, seccomp, filesystem mounts, and browser containment remain deployment responsibilities.


## Production connector boundary
`GoogleCalendarConnector` is the first live-service connector: a read-only Calendar API v3 adapter with an exact `calendar.read` grant, bounded event results, fixed Google API origin, runtime-only OAuth token callback, audit/policy wiring through `ConnectorTool`, and fail-closed revocation. The host still owns browser OAuth login, refresh, and durable token storage.
