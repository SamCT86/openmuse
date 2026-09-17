"""Provenance-aware tiered memory with hash-chained, verifiable writes.

Every mutation through MemoryStore can be mirrored into the audit chain, so a
fact that appears in memory without a matching chained write - or with content
that no longer matches its write record - is detectable. That is the defense
against memory poisoning by out-of-band edits: memory state is not trusted
unless it reconciles with the chain.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4

from .audit import AuditLog, verify_chain


class MemoryTier(str, Enum):
    WORKING = "working"
    CURATED = "curated"


@dataclass
class Memory:
    id: str
    fact: str
    source: str
    observed_at: str
    confidence: float
    retention: str
    tier: str = MemoryTier.WORKING.value
    deleted: bool = False


class MemoryStore:
    def __init__(self, path: Path, audit: AuditLog | None = None):
        self.path = path
        self.audit = audit

    def remember(self, fact, source, observed_at, confidence=1.0, retention="user-controlled", tier=MemoryTier.WORKING):
        item = Memory(uuid4().hex, fact, source, observed_at, confidence, retention, MemoryTier(tier).value)
        items = self._load()
        items.append(item)
        self._save(items)
        self._log(
            {
                "event": "memory_write",
                "memory_id": item.id,
                "tier": item.tier,
                "source": item.source,
                "observed_at": item.observed_at,
                "fact_sha256": _hash(item.fact),
            }
        )
        return item

    def promote(self, memory_id, tier=MemoryTier.CURATED):
        items = self._load()
        item = next(x for x in items if x.id == memory_id)
        item.tier = MemoryTier(tier).value
        self._save(items)
        self._log({"event": "memory_promote", "memory_id": item.id, "tier": item.tier})
        return item

    def explain(self, memory_id):
        return next(x for x in self._load() if x.id == memory_id)

    def search(self, query: str, limit: int = 10, tiers: set[MemoryTier] | None = None) -> list[Memory]:
        """Rank non-deleted memories with a small, deterministic local text index."""
        terms = _terms(query)
        if not terms or limit < 1:
            return []
        allowed = {tier.value for tier in tiers} if tiers else None
        ranked: list[tuple[int, float, str, Memory]] = []
        for item in self._load():
            if item.deleted or (allowed is not None and item.tier not in allowed):
                continue
            fact_terms = _terms(item.fact)
            source_terms = _terms(item.source)
            score = sum(3 for term in terms if term in fact_terms) + sum(1 for term in terms if term in source_terms)
            if score:
                ranked.append((score, item.confidence, item.observed_at, item))
        ranked.sort(key=lambda row: (row[0], row[1], row[2], row[3].id), reverse=True)
        return [row[3] for row in ranked[:limit]]

    def update(self, memory_id: str, fact: str, source: str, observed_at: str, confidence: float = 1.0) -> Memory:
        """Replace a memory with new provenance and chain the new content digest."""
        items = self._load()
        item = next(x for x in items if x.id == memory_id)
        if item.deleted:
            raise ValueError("deleted memory cannot be updated")
        item.fact, item.source = fact, source
        item.observed_at, item.confidence = observed_at, confidence
        self._save(items)
        self._log(
            {
                "event": "memory_update",
                "memory_id": item.id,
                "tier": item.tier,
                "source": item.source,
                "observed_at": item.observed_at,
                "fact_sha256": _hash(item.fact),
            }
        )
        return item

    def forget(self, memory_id):
        items = self._load()
        item = next(x for x in items if x.id == memory_id)
        item.fact = "[DELETED]"
        item.source = "[DELETED]"
        item.deleted = True
        self._save(items)
        self._log({"event": "memory_forget", "memory_id": item.id})
        return item

    def _log(self, record: dict) -> None:
        if self.audit is not None:
            self.audit.append({**record, "at": datetime.now(timezone.utc).isoformat()})

    def _load(self):
        return [Memory(**x) for x in json.loads(self.path.read_text())] if self.path.exists() else []

    def _save(self, items):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([asdict(x) for x in items]))


def _terms(text: str) -> set[str]:
    return set(re.findall(r"[\w-]+", text.casefold()))


def _hash(fact: str) -> str:
    return hashlib.sha256(fact.encode()).hexdigest()


def verify_memory(memory_path: Path, audit_path: Path) -> tuple[bool, list[str]]:
    """Reconcile memory state against the chained write history.

    Fails when the chain itself is broken, when an item has no chained write
    (out-of-band insertion), when content or tier drifted from its write
    record (tampering), or when a tombstone has no chained forget.
    """
    violations: list[str] = []
    ok, _, error = verify_chain(audit_path)
    if not ok:
        return False, [f"audit chain broken: {error}"]
    writes: dict[str, dict] = {}
    forgets: set[str] = set()
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        event = record.get("event")
        if event == "memory_write":
            writes[record["memory_id"]] = record
        elif event == "memory_update":
            if record["memory_id"] in writes:
                writes[record["memory_id"]].update(
                    fact_sha256=record["fact_sha256"],
                    source=record["source"],
                    observed_at=record["observed_at"],
                    tier=record["tier"],
                )
        elif event == "memory_promote":
            if record["memory_id"] in writes:
                writes[record["memory_id"]]["tier"] = record["tier"]
        elif event == "memory_forget":
            forgets.add(record["memory_id"])
    if not memory_path.exists():
        return (not writes, ["memory file missing but chained writes exist"] if writes else [])
    items = {item.id: item for item in (Memory(**x) for x in json.loads(memory_path.read_text()))}
    for memory_id, item in items.items():
        write = writes.get(memory_id)
        if write is None:
            violations.append(f"{memory_id}: no chained write (out-of-band insertion)")
            continue
        if item.deleted:
            if memory_id not in forgets:
                violations.append(f"{memory_id}: tombstone without chained forget")
        elif (
            _hash(item.fact) != write["fact_sha256"]
            or item.tier != write["tier"]
            or item.source != write["source"]
            or item.observed_at != write["observed_at"]
        ):
            violations.append(f"{memory_id}: content or provenance drifted from chained write")
    for memory_id in forgets - set(items):
        violations.append(f"{memory_id}: chained forget but item is gone")
    return (not violations, violations)
