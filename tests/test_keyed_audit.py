"""Keyed HMAC audit chain: forgery resistance, rotation, fail-closed, back-compat."""

import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest

from openmuse.audit import (
    KEY_FILE_ENV,
    AuditKeyError,
    AuditLog,
    FileAuditKeys,
    KeyringAuditKeys,
    verify_chain,
)
from openmuse.keyring_keys import MasterKeyError


class MemoryAuditKeys:
    def __init__(self):
        self.keys = {}
        self.current_id = None

    def current(self):
        if self.current_id is None:
            self.current_id = self.rotate()[0]
        return self.current_id, self.keys[self.current_id]

    def rotate(self):
        import secrets

        key = secrets.token_bytes(32)
        key_id = hashlib.sha256(key).hexdigest()[:16]
        self.keys[key_id] = key
        self.current_id = key_id
        return key_id, key

    def resolve(self, key_id):
        return self.keys.get(key_id)


def read_records(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def forge_append(path: Path, record: dict):
    """Attacker with file write but no key recomputes a plain SHA-256 link."""
    lines = path.read_text().splitlines()
    last = json.loads(lines[-1])
    record["previous_hash"] = last["hash"]
    record["hash"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    with path.open("a") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def test_keyed_records_verify_and_carry_key_id(tmp_path):
    store = MemoryAuditKeys()
    log = AuditLog(tmp_path / "audit", key_store=store)
    log.append({"event": "one"})
    log.append({"event": "two"})
    assert verify_chain(tmp_path / "audit", key_store=store) == (True, 2, None)
    first, _ = read_records(tmp_path / "audit")
    assert first["chain"] == "hmac-sha256" and first["key_id"] in store.keys


def test_forgery_without_key_fails(tmp_path):
    store = MemoryAuditKeys()
    log = AuditLog(tmp_path / "audit", key_store=store)
    log.append({"event": "one"})
    # Tamper and recompute an unkeyed hash over the changed record.
    lines = tmp_path.joinpath("audit").read_text().splitlines()
    record = json.loads(lines[0])
    record["event"] = "forged"
    lines[0] = json.dumps(record)
    tmp_path.joinpath("audit").write_text("\n".join(lines) + "\n")
    ok, count, error = verify_chain(tmp_path / "audit", key_store=store)
    assert not ok and count == 1 and error == "record hash does not match"


def test_attacker_appending_unkeyed_link_fails(tmp_path):
    store = MemoryAuditKeys()
    log = AuditLog(tmp_path / "audit", key_store=store)
    log.append({"event": "one"})
    forge_append(tmp_path / "audit", {"event": "attacker"})
    ok, count, error = verify_chain(tmp_path / "audit", key_store=store)
    assert not ok and count == 2 and error == "unkeyed record after keyed records"


def test_attacker_forging_hmac_with_wrong_key_fails(tmp_path):
    store = MemoryAuditKeys()
    log = AuditLog(tmp_path / "audit", key_store=store)
    log.append({"event": "one"})
    lines = tmp_path.joinpath("audit").read_text().splitlines()
    record = json.loads(lines[0])
    record["event"] = "forged"
    claimed = record.pop("hash")
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    record["hash"] = hmac.new(b"\x00" * 32, raw, hashlib.sha256).hexdigest()
    assert record["hash"] != claimed
    tmp_path.joinpath("audit").write_text(json.dumps(record) + "\n")
    assert verify_chain(tmp_path / "audit", key_store=store)[0] is False


def test_key_rotation_keeps_history_verifiable(tmp_path):
    store = MemoryAuditKeys()
    log = AuditLog(tmp_path / "audit", key_store=store)
    log.append({"event": "before-rotation"})
    old_id, old_key = store.current()
    new_id, new_key = store.rotate()
    assert new_id != old_id and new_key != old_key
    log.append({"event": "after-rotation"})
    assert verify_chain(tmp_path / "audit", key_store=store) == (True, 2, None)
    first, second = read_records(tmp_path / "audit")
    assert first["key_id"] == old_id and second["key_id"] == new_id


def test_unknown_key_id_fails_verification(tmp_path):
    store = MemoryAuditKeys()
    AuditLog(tmp_path / "audit", key_store=store).append({"event": "one"})
    other = MemoryAuditKeys()  # a different store without the key
    ok, count, error = verify_chain(tmp_path / "audit", key_store=other)
    assert not ok and count == 1 and error == "unknown audit key id"


def test_missing_credential_store_refuses_to_append(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY_FILE_ENV)
    monkeypatch.setattr(
        "openmuse.audit.system_credential_store",
        lambda: (_ for _ in ()).throw(MasterKeyError("no usable OS credential-store backend is available")),
    )
    with pytest.raises(AuditKeyError):
        AuditLog(tmp_path / "audit").append({"event": "must-not-land"})
    assert not (tmp_path / "audit").exists()


def test_missing_store_fails_verification_closed(tmp_path, monkeypatch):
    store = MemoryAuditKeys()
    AuditLog(tmp_path / "audit", key_store=store).append({"event": "one"})
    monkeypatch.delenv(KEY_FILE_ENV)
    monkeypatch.setattr(
        "openmuse.audit.default_key_store",
        lambda: (_ for _ in ()).throw(AuditKeyError("no store")),
    )
    ok, _, error = verify_chain(tmp_path / "audit")
    assert not ok and error == "no store"


def test_legacy_chain_still_verifies_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY_FILE_ENV)
    log = AuditLog.legacy(tmp_path / "audit")
    log.append({"event": "old-one"})
    log.append({"event": "old-two"})
    assert verify_chain(tmp_path / "audit") == (True, 2, None)
    assert "chain" not in read_records(tmp_path / "audit")[0]


def test_mixed_legacy_then_keyed_chain_verifies(tmp_path):
    path = tmp_path / "audit"
    legacy = AuditLog.legacy(path)
    legacy.append({"event": "legacy-one"})
    legacy.append({"event": "legacy-two"})
    store = MemoryAuditKeys()
    keyed = AuditLog(path, key_store=store)
    keyed.append({"event": "keyed-one"})
    assert verify_chain(path, key_store=store) == (True, 3, None)
    # The keyed record anchors the legacy head: editing legacy history now fails.
    lines = path.read_text().splitlines()
    record = json.loads(lines[0])
    record["event"] = "edited"
    record["hash"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    lines[0] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n")
    assert verify_chain(path, key_store=store)[0] is False


def test_require_keyed_rejects_legacy_and_mixed(tmp_path):
    AuditLog.legacy(tmp_path / "audit").append({"event": "old"})
    ok, _, error = verify_chain(tmp_path / "audit", require_keyed=True)
    assert not ok and error == "record is not keyed"


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits do not apply to Windows ACLs")
def test_default_resolution_uses_env_key_file(tmp_path, monkeypatch):
    key_file = tmp_path / "keys.json"
    monkeypatch.setenv(KEY_FILE_ENV, str(key_file))
    AuditLog(tmp_path / "audit").append({"event": "env-keyed"})
    assert verify_chain(tmp_path / "audit") == (True, 1, None)
    assert key_file.exists()
    assert oct(os.stat(key_file).st_mode & 0o777) == "0o600"


def test_keyring_store_roundtrip_and_rotation():
    class FakeKeyring:
        def __init__(self):
            self.values = {}

        def get_password(self, service, account):
            return self.values.get((service, account))

        def set_password(self, service, account, value):
            self.values[(service, account)] = value

    backend = FakeKeyring()
    store = KeyringAuditKeys(backend=backend)
    key_id, key = store.current()
    assert store.current() == (key_id, key)
    new_id, _ = store.rotate()
    assert store.resolve(key_id) == key and store.current()[0] == new_id
    assert store.resolve("0" * 16) is None


def test_keyring_store_unavailable_fails_closed(monkeypatch):
    monkeypatch.setattr(
        "openmuse.audit.system_credential_store",
        lambda: (_ for _ in ()).throw(MasterKeyError("no backend")),
    )
    with pytest.raises(AuditKeyError):
        KeyringAuditKeys()


@pytest.mark.skipif(os.name == "nt", reason="owner-only enforcement is POSIX-only by design")
def test_file_key_store_refuses_group_readable_key(tmp_path):
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"current": None, "keys": {}}))
    key_file.chmod(0o644)
    with pytest.raises(AuditKeyError, match="owner-only"):
        FileAuditKeys(key_file).current()


def test_concurrent_keyed_appends_remain_one_chain(tmp_path):
    import threading

    store = MemoryAuditKeys()
    path = tmp_path / "audit"
    log = AuditLog(path, key_store=store)
    threads = [threading.Thread(target=log.append, args=({"n": i},)) for i in range(32)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert verify_chain(path, key_store=store) == (True, 32, None)


def test_corrupt_key_store_fails_closed(tmp_path):
    key_file = tmp_path / "keys.json"
    key_file.write_text("not-json{")
    key_file.chmod(0o600)
    with pytest.raises(AuditKeyError, match="corrupt"):
        FileAuditKeys(key_file).current()


def test_store_with_missing_current_key_fails_closed(tmp_path):
    import base64

    key_file = tmp_path / "keys.json"
    good = base64.urlsafe_b64encode(b"k" * 32).decode()
    key_file.write_text(json.dumps({"current": "absent", "keys": {"other": good}}))
    key_file.chmod(0o600)
    with pytest.raises(AuditKeyError, match="current key is missing"):
        FileAuditKeys(key_file).current()


def test_store_with_wrong_sized_key_fails_closed(tmp_path):
    import base64

    key_file = tmp_path / "keys.json"
    short = base64.urlsafe_b64encode(b"tiny").decode()
    key_file.write_text(json.dumps({"current": None, "keys": {"kid": short}}))
    key_file.chmod(0o600)
    with pytest.raises(AuditKeyError, match="corrupt"):
        FileAuditKeys(key_file).resolve("kid")


def test_keyring_persist_check_fails_closed():
    class FlakyKeyring:
        def get_password(self, service, account):
            return None

        def set_password(self, service, account, value):
            pass

    with pytest.raises(AuditKeyError, match="did not persist"):
        KeyringAuditKeys(backend=FlakyKeyring()).current()


def test_keyed_record_without_key_id_fails(tmp_path):
    store = MemoryAuditKeys()
    AuditLog(tmp_path / "audit", key_store=store).append({"event": "one"})
    record = read_records(tmp_path / "audit")[0]
    del record["key_id"]
    tmp_path.joinpath("audit").write_text(json.dumps(record) + "\n")
    ok, _, error = verify_chain(tmp_path / "audit", key_store=store)
    assert not ok and error == "keyed record is missing its key id"


def test_unknown_chain_algorithm_fails(tmp_path):
    record = {"event": "x", "previous_hash": "0" * 64, "chain": "md5", "hash": "0" * 64}
    tmp_path.joinpath("audit").write_text(json.dumps(record) + "\n")
    ok, _, error = verify_chain(tmp_path / "audit")
    assert not ok and error.startswith("unknown chain algorithm")
