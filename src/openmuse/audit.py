"""Redacted, hash-chained JSONL audit trail."""

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SENSITIVE = {"password", "token", "secret", "authorization", "api_key", "cookie"}


def redact(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {k: ("[REDACTED]" if k.lower() in SENSITIVE else redact(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [redact(x) for x in v]
    return v


class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    def append(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        previous = "0" * 64
        if self.path.exists():
            lines = self.path.read_text(encoding="utf-8").splitlines()
            previous = json.loads(lines[-1]).get("hash", previous) if lines else previous
        clean = redact(record)
        clean["previous_hash"] = previous
        raw = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        clean["hash"] = hashlib.sha256(raw.encode()).hexdigest()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as h:
            h.write(json.dumps(clean, ensure_ascii=False) + "\n")


def verify_chain(path: Path) -> tuple[bool, int, str | None]:
    """Independently recompute every link in an audit JSONL chain."""
    previous = "0" * 64
    count = 0
    try:
        for count, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            record = json.loads(line)
            claimed = record.pop("hash")
            if record.get("previous_hash") != previous:
                return False, count, "previous hash does not match"
            raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            actual = hashlib.sha256(raw.encode()).hexdigest()
            if not hmac_compare(actual, claimed):
                return False, count, "record hash does not match"
            previous = claimed
    except (OSError, KeyError, json.JSONDecodeError, TypeError) as exc:
        return False, count, str(exc)
    return True, count, None


def hmac_compare(left: str, right: str) -> bool:
    """Constant-time compare without expanding the public API surface."""
    import hmac

    return hmac.compare_digest(left, right)
