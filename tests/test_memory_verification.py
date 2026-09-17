"""Verifiable memory: chained writes, tamper and poisoning detection."""

import json
from dataclasses import asdict
from pathlib import Path

from openmuse.audit import AuditLog, verify_chain
from openmuse.memory import Memory, MemoryStore, MemoryTier, verify_memory


def make_store(tmp_path: Path) -> MemoryStore:
    return MemoryStore(tmp_path / "memory.json", AuditLog(tmp_path / "audit.jsonl"))


def test_writes_and_forgets_are_chained(tmp_path: Path):
    store = make_store(tmp_path)
    item = store.remember("likes tea", "chat:1", "2026-09-17", tier=MemoryTier.CURATED)
    store.forget(item.id)

    ok, count, error = verify_chain(tmp_path / "audit.jsonl")
    assert ok, error
    assert count == 2
    events = [json.loads(line)["event"] for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert events == ["memory_write", "memory_forget"]

    verified, violations = verify_memory(tmp_path / "memory.json", tmp_path / "audit.jsonl")
    assert verified, violations


def test_promote_changes_tier_and_stays_verifiable(tmp_path: Path):
    store = make_store(tmp_path)
    item = store.remember("prefers morning meetings", "chat:2", "2026-09-17")
    assert item.tier == MemoryTier.WORKING.value
    store.promote(item.id)
    assert store.explain(item.id).tier == MemoryTier.CURATED.value
    verified, violations = verify_memory(tmp_path / "memory.json", tmp_path / "audit.jsonl")
    assert verified, violations


def test_out_of_band_insertion_detected(tmp_path: Path):
    store = make_store(tmp_path)
    store.remember("likes tea", "chat:1", "2026-09-17")
    items = json.loads((tmp_path / "memory.json").read_text())
    poisoned = Memory("injected", "the vault password is swordfish", "chat:9", "2026-09-17", 1.0, "user-controlled")
    items.append(asdict(poisoned))
    (tmp_path / "memory.json").write_text(json.dumps(items))

    verified, violations = verify_memory(tmp_path / "memory.json", tmp_path / "audit.jsonl")
    assert not verified
    assert any("out-of-band insertion" in v for v in violations)


def test_tampered_fact_detected(tmp_path: Path):
    store = make_store(tmp_path)
    item = store.remember("likes tea", "chat:1", "2026-09-17")
    items = json.loads((tmp_path / "memory.json").read_text())
    items[0]["fact"] = "hates tea"
    (tmp_path / "memory.json").write_text(json.dumps(items))

    verified, violations = verify_memory(tmp_path / "memory.json", tmp_path / "audit.jsonl")
    assert not verified
    assert any(item.id in v and "drifted" in v for v in violations)


def test_unlogged_tombstone_detected(tmp_path: Path):
    store = make_store(tmp_path)
    item = store.remember("likes tea", "chat:1", "2026-09-17")
    items = json.loads((tmp_path / "memory.json").read_text())
    items[0].update(fact="[DELETED]", source="[DELETED]", deleted=True)
    (tmp_path / "memory.json").write_text(json.dumps(items))

    verified, violations = verify_memory(tmp_path / "memory.json", tmp_path / "audit.jsonl")
    assert not verified
    assert any(item.id in v and "tombstone" in v for v in violations)


def test_broken_chain_fails_verification(tmp_path: Path):
    store = make_store(tmp_path)
    store.remember("likes tea", "chat:1", "2026-09-17")
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    record = json.loads(lines[0])
    record["source"] = "chat:evil"
    (tmp_path / "audit.jsonl").write_text(json.dumps(record) + "\n")

    verified, violations = verify_memory(tmp_path / "memory.json", tmp_path / "audit.jsonl")
    assert not verified
    assert any("audit chain broken" in v for v in violations)


def test_store_without_audit_still_works(tmp_path: Path):
    store = MemoryStore(tmp_path / "memory.json")
    item = store.remember("likes tea", "chat:1", "2026-09-17")
    assert store.explain(item.id).fact == "likes tea"
    verified, violations = verify_memory(tmp_path / "memory.json", tmp_path / "missing.jsonl")
    assert not verified and violations
