"""Host-issued, action-bound, expiring, one-time approvals."""

import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field

from .models import Action


@dataclass
class ApprovalAuthority:
    """Issues and verifies one-time approval tokens.

    Expiry contract: a token is expired when ``now >= exp``; the exact
    boundary second is already invalid. Consumption is atomic: no
    interleaving of concurrent ``verify`` calls can consume one token twice.
    """

    secret: bytes
    used: set[str] = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def issue(self, action: Action, ttl_seconds: int = 300) -> str:
        payload = {
            "id": action.id,
            "tool": action.tool,
            "arguments": action.arguments,
            "exp": int(time.time()) + ttl_seconds,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return raw.hex() + "." + hmac.new(self.secret, raw, hashlib.sha256).hexdigest()

    def verify(self, action: Action, token: str | None) -> bool:
        if not token:
            return False
        try:
            raw_hex, sig = token.split(".", 1)
            raw = bytes.fromhex(raw_hex)
            p = json.loads(raw)
        except (ValueError, TypeError, json.JSONDecodeError):
            return False
        if not isinstance(p, dict):
            return False
        expected = {"id": action.id, "tool": action.tool, "arguments": action.arguments, "exp": p.get("exp")}
        try:
            expired = int(p["exp"]) <= int(time.time())
        except (KeyError, TypeError, ValueError):
            return False
        if expired or p != expected:
            return False
        if not hmac.compare_digest(sig, hmac.new(self.secret, raw, hashlib.sha256).hexdigest()):
            return False
        with self._lock:
            if token in self.used:
                return False
            self.used.add(token)
        return True
