"""One-time ephemeral values for OTP and credential-use grants."""

import time
from dataclasses import dataclass, field
from uuid import uuid4


@dataclass
class EphemeralBroker:
    values: dict[str, tuple[str, float, str]] = field(default_factory=dict)

    def issue(self, value: str, purpose: str, ttl_seconds: int = 120) -> str:
        handle = uuid4().hex
        self.values[handle] = (value, time.time() + ttl_seconds, purpose)
        return handle

    def consume(self, handle: str, purpose: str) -> str:
        value, expires, bound = self.values.pop(handle)
        if bound != purpose or expires < time.time():
            raise ValueError("ephemeral grant invalid or expired")
        return value
