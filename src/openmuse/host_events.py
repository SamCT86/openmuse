"""Authenticated host decision events, isolated from planner and page text."""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field


@dataclass
class HostEventVerifier:
    secret: bytes
    maximum_age_seconds: int = 60
    seen: set[str] = field(default_factory=set)

    def sign(self, event_id: str, timestamp: int, payload: dict[str, object]) -> str:
        message = self._message(event_id, timestamp, payload)
        return hmac.new(self.secret, message, hashlib.sha256).hexdigest()

    def verify(self, event_id: str, timestamp: int, payload: dict[str, object], signature: str) -> None:
        if abs(int(time.time()) - timestamp) > self.maximum_age_seconds:
            raise ValueError("stale host event")
        if event_id in self.seen:
            raise ValueError("replayed host event")
        expected = self.sign(event_id, timestamp, payload)
        if not hmac.compare_digest(expected, signature):
            raise ValueError("invalid host signature")
        self.seen.add(event_id)

    @staticmethod
    def _message(event_id: str, timestamp: int, payload: dict[str, object]) -> bytes:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return f"{event_id}.{timestamp}.{canonical}".encode()
