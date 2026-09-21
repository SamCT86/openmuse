# Extension cookbook

OpenMuse extensions begin with the smallest authority that solves the problem. Keep simulation and fail-closed tests beside every live boundary.

## Add a typed tool

A tool declares a stable name, human-readable description, risk, JSON Schema, and `run` method. Reject unknown fields so approval covers the complete action shape.

```python
from dataclasses import dataclass
from typing import Any

from openmuse.policy import Risk
from openmuse.tools import ManifestMixin

@dataclass
class CountWords(ManifestMixin):
    name: str = "count_words"
    description: str = "Count words in supplied text"
    risk: Risk = Risk.READ
    schema = {
        "type": "object",
        "required": ["text"],
        "properties": {"text": {"type": "string", "maxLength": 10000}},
        "additionalProperties": False,
    }

    def run(self, text: str, **_: Any) -> str:
        return str(len(text.split()))
```

Register the instance with `Agent`. Add tests for valid input, every rejection boundary, risk classification, and the manifest. A write or external side effect must use `Risk.WRITE` and exact-action approval.

## Add a simulation-first connector

Start with credential-free behavior. `JSONFixtureConnector` already supplies read-only `list` and `search` capabilities:

```python
from pathlib import Path
from openmuse.simulated_connectors import JSONFixtureConnector

class SimulatedTickets(JSONFixtureConnector):
    def __init__(self, fixture: Path) -> None:
        super().__init__(fixture, "tickets", "tickets.read")
```

For a live connector, subclass `ReadOnlyConnector`, declare the narrow provider scope, validate capability arguments, and implement `delete_cached_data`. Keep tokens out of fixtures, logs, errors, and planner-visible results. Revocation must call the provider first, clear cached clients, delete local credentials only after provider success, and fail closed on uncertainty. Test both the simulator and provider boundary with recorded fake responses before using a disposable account.

## Add a master-key provider

Implement the `CredentialStore` protocol and inject it into `KeyringMasterKey`:

```python
class HardwareCredentialStore:
    def get_password(self, service: str, account: str) -> str | None:
        ...
    def set_password(self, service: str, account: str, password: str) -> None:
        ...

key = KeyringMasterKey(backend=HardwareCredentialStore()).load_or_create()
```

The backend must return the same persisted 256-bit key after a write. Never fall back to a plaintext file or generate a new key when retrieval is ambiguous.

## Publish signed audit checkpoints

Create and verify a checkpoint locally, then publish its canonical JSON to an independent append-only administrative domain:

```python
from openmuse.audit_anchor import create_checkpoint, verify_checkpoint, write_checkpoint

checkpoint = create_checkpoint(audit_path, signing_key)
assert verify_checkpoint(checkpoint, signing_key)
write_checkpoint(checkpoint, output_path)
```

A publisher must use a unique immutable key, require a success response, retain the returned object version or receipt, and reject overwrite. Local signing detects changed content; only the independent store establishes an external publication time.

## Review checklist

- Is the authority narrower than the use case?
- Are schemas closed and bounded?
- Can untrusted text select a secret, identity, destination, or policy?
- Does revocation and cleanup fail closed?
- Is there a credential-free simulator?
- Do tests cover expiry, replay, concurrency, malformed input, and provider failure?
- Does the threat model or an ADR need updating?
