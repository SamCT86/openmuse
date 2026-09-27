# Experimental secret-service protocol

`SecretService` is a local Unix-socket demonstration, **not a secret-isolation
boundary**. Its `use(name, consumer)` operation returns the plaintext secret to
the caller process. A caller with the shared HMAC key can request **any** name;
there are no caller-specific grants, per-operation scopes, or revocation. The
service does not confine the consumer, and its `recv(65_536)` request/response
is a single-frame demo protocol, not production framing. It also does not
spawn a dedicated host process by itself: the embedding host decides where to
run `serve_once`.

Do not give this client or the shared HMAC key to untrusted extensions. The
in-process `SecretBroker` likewise invokes trusted Python callbacks with
plaintext and is not process isolation. Use test secrets only. For a real
boundary, move specific secret-consuming operations inside a separately
isolated service, issue caller-scoped authority for named operations, return
only operation results (never plaintext), bound/framed requests, and test
revocation and compromised callers before connecting real accounts. The OS
keyring and vault protect secrets at rest, not against a host process that is
already authorized to decrypt them.
