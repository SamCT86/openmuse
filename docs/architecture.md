# Architecture
A planner proposes typed actions. The registry publishes tool manifests. Policy evaluates risk, and the executor runs one tool only after policy allows it. The audit sink records redacted metadata and hash-links entries. The model never receives host approval secrets.

Trust boundaries: planner output and all external content are untrusted; policy, approval authority, secret store, and tool sandbox belong to the trusted host. Connectors should run out of process in future releases.


## Isolated workers
`IsolatedWorker` runs an explicit JSON request in a fresh Python process with a dedicated working directory, scrubbed environment, wall-clock timeout, address-space/open-file/core limits, and bounded output. This is a real process boundary, not a full sandbox: network namespace, seccomp, filesystem mounts, and browser containment remain deployment responsibilities.


## Production connector boundary
`GoogleCalendarConnector` and `GoogleMailConnector` are read-only Google API adapters with exact grants, bounded results, fixed provider origins, runtime-only OAuth token callbacks, audit/policy wiring through `ConnectorTool`, and fail-closed revocation. `GoogleOAuthManager` builds the consent URL, exchanges authorization codes, refreshes expiring access tokens, validates scopes, and stores tokens in the encrypted vault. The embedding host still owns the loopback/web callback that verifies OAuth state and supplies the returned code.


The production composition is `SecretVault.open(path, KeyringMasterKey())`, then one `GoogleOAuthManager` per Google account/provider-scope set. Pass `manager.access_token` to a Google connector. The master key stays in the platform credential store; the vault file contains only envelope-encrypted records and is written with owner-only permissions. A missing system credential backend is an error, never a plaintext fallback. OAuth `state` verification and the redirect listener remain embedding-host responsibilities.
