"""Verifiable memory lifecycle with no model or credentials."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from openmuse.audit import AuditLog
from openmuse.memory import MemoryStore, MemoryTier, verify_memory

with tempfile.TemporaryDirectory(prefix="openmuse-memory-") as directory:
    root = Path(directory)
    memory_path, audit_path = root / "memory.json", root / "audit.jsonl"
    store = MemoryStore(memory_path, AuditLog(audit_path))
    observed = datetime.now(timezone.utc).isoformat()
    item = store.remember("Prefers quiet cafés", "user statement", observed, tier=MemoryTier.CURATED)
    hit = store.search("quiet café")[0]
    verified, violations = verify_memory(memory_path, audit_path)
    print(f"found={hit.fact!r} source={hit.source!r}")
    print(f"verified={verified} violations={violations}")
    store.update(item.id, "Prefers quiet cafés with outdoor seating", "user correction", observed)
    store.forget(item.id)
    verified, violations = verify_memory(memory_path, audit_path)
    print(f"forgotten={store.explain(item.id).deleted} verified={verified} violations={violations}")
