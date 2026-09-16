"""Host-issued, action-bound, expiring, one-time approvals."""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

from .models import Action


@dataclass
class ApprovalAuthority:
    secret: bytes
    used: set[str] = field(default_factory=set)

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
        if not token or token in self.used:
            return False
        try:
            raw_hex, sig = token.split(".", 1)
            raw = bytes.fromhex(raw_hex)
            p = json.loads(raw)
        except (ValueError, TypeError, json.JSONDecodeError):
            return False
        expected = {"id": action.id, "tool": action.tool, "arguments": action.arguments, "exp": p.get("exp")}
        if (
            not hmac.compare_digest(sig, hmac.new(self.secret, raw, hashlib.sha256).hexdigest())
            or p != expected
            or int(p["exp"]) < int(time.time())
        ):
            return False
        self.used.add(token)
        return True
