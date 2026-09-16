"""Provenance-aware memory with inspectable tombstone deletion."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import uuid4


@dataclass
class Memory:
    id: str
    fact: str
    source: str
    observed_at: str
    confidence: float
    retention: str
    deleted: bool = False


class MemoryStore:
    def __init__(self, path: Path):
        self.path = path

    def remember(self, fact, source, observed_at, confidence=1.0, retention="user-controlled"):
        item = Memory(uuid4().hex, fact, source, observed_at, confidence, retention)
        items = self._load()
        items.append(item)
        self._save(items)
        return item

    def explain(self, memory_id):
        return next(x for x in self._load() if x.id == memory_id)

    def forget(self, memory_id):
        items = self._load()
        item = next(x for x in items if x.id == memory_id)
        item.fact = "[DELETED]"
        item.source = "[DELETED]"
        item.deleted = True
        self._save(items)
        return item

    def _load(self):
        return [Memory(**x) for x in json.loads(self.path.read_text())] if self.path.exists() else []

    def _save(self, items):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([asdict(x) for x in items]))
