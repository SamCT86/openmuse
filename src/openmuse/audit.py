"""Hash-chained audit with bounded append and independent streaming verification."""

import fcntl
import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SENSITIVE = {"password", "token", "secret", "authorization", "api_key", "cookie"}
ZERO = "0" * 64


def redact(v: Any) -> Any:
    """Compatibility for host-owned metadata, not a safe projection of tool data."""
    if isinstance(v, Mapping):
        return {k: ("[REDACTED]" if k.lower() in SENSITIVE else redact(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [redact(x) for x in v]
    return v


def _last_record(handle: Any) -> dict[str, Any] | None:
    """Seek only the final line, even for a large audit file."""
    handle.seek(0, os.SEEK_END)
    end = handle.tell()
    if end == 0:
        return None
    handle.seek(end - 1)
    if handle.read(1) != b"\n":
        raise ValueError("audit log ends with incomplete record")
    position = end - 2
    while position >= 0:
        handle.seek(position)
        if handle.read(1) == b"\n":
            break
        position -= 1
    handle.seek(position + 1)
    record = json.loads(handle.read(end - position - 2))
    if not isinstance(record, dict) or not isinstance(record.get("hash"), str):
        raise TypeError("invalid audit tail")
    return record


class AuditLog:
    def __init__(self, path: Path):
        self.path = path

    def append(self, record: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "r+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            last = _last_record(handle)
            clean = redact(record)
            clean["previous_hash"] = last["hash"] if last else ZERO
            raw = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            clean["hash"] = hashlib.sha256(raw.encode()).hexdigest()
            handle.seek(0, os.SEEK_END)
            handle.write((json.dumps(clean, ensure_ascii=False) + "\n").encode())
            handle.flush()
            os.fsync(handle.fileno())


def verify_chain(path: Path) -> tuple[bool, int, str | None]:
    """Independently stream every link; memory usage is bounded by a record."""
    previous = ZERO
    count = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for count, line in enumerate(handle, start=1):
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
    return hmac.compare_digest(left, right)
