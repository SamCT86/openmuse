"""Keyed HMAC audit chain: forgery resistance, rotation, fail-closed, back-compat."""

import hashlib
import hmac
import json
import os
import secrets
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


# --- Finding: caller-supplied chain fields must never reach a record -------


@pytest.mark.parametrize("field", ["hash", "previous_hash", "chain", "key_id"])
def test_append_rejects_reserved_fields(tmp_path, field):
    log = AuditLog(tmp_path / "audit", key_store=MemoryAuditKeys())
    with pytest.raises(ValueError, match="reserved field"):
        log.append({"event": "x", field: "injected"})
    assert not (tmp_path / "audit").exists()


def test_legacy_writer_also_rejects_reserved_fields(tmp_path):
    # The pre-keying SHA writer shared the hole: an injected chain/key_id made
    # a legacy record verify as keyed and fail. The reject covers both writers.
    log = AuditLog.legacy(tmp_path / "audit")
    with pytest.raises(ValueError, match="reserved field"):
        log.append({"event": "x", "chain": "hmac-sha256", "key_id": "0" * 16})
    log.append({"event": "clean"})
    assert verify_chain(tmp_path / "audit") == (True, 1, None)


# --- Finding: WinError 32 retry is limited to handle acquisition -----------


class _FlakyHandle:
    """Write lands; flush then fails as a post-write sharing violation."""

    def __init__(self, handle):
        self._handle = handle

    def __getattr__(self, name):
        return getattr(self._handle, name)

    def flush(self):
        self._handle.flush()
        error = PermissionError(13, "being used by another process")
        error.winerror = 32
        raise error


def _enter_failing_stream(error_factory, real_stream, failures):
    import contextlib

    state = {"calls": 0}

    @contextlib.contextmanager
    def fake_stream(path):
        state["calls"] += 1
        if state["calls"] <= failures:
            raise error_factory()
        with real_stream(path) as handle:
            yield handle

    return fake_stream, state


def _sharing_violation():
    error = PermissionError(13, "being used by another process")
    error.winerror = 32
    return error


def test_sharing_violation_at_open_is_retried(tmp_path, monkeypatch):
    from openmuse import audit

    fake, state = _enter_failing_stream(_sharing_violation, audit._append_stream, 2)
    monkeypatch.setattr(audit, "_append_stream", fake)
    AuditLog(tmp_path / "audit", key_store=MemoryAuditKeys()).append({"event": "one"})
    assert state["calls"] == 3
    assert len(read_records(tmp_path / "audit")) == 1


def test_sharing_violation_gives_up_after_four_attempts(tmp_path, monkeypatch):
    from openmuse import audit

    fake, state = _enter_failing_stream(_sharing_violation, audit._append_stream, 99)
    monkeypatch.setattr(audit, "_append_stream", fake)
    with pytest.raises(PermissionError):
        AuditLog(tmp_path / "audit", key_store=MemoryAuditKeys()).append({"event": "one"})
    assert state["calls"] == 4
    assert not (tmp_path / "audit").exists()


def test_other_open_errors_are_not_retried(tmp_path, monkeypatch):
    from openmuse import audit

    def plain_permission_error():
        return PermissionError(13, "access denied")  # no winerror

    fake, state = _enter_failing_stream(plain_permission_error, audit._append_stream, 1)
    monkeypatch.setattr(audit, "_append_stream", fake)
    with pytest.raises(PermissionError, match="access denied"):
        AuditLog(tmp_path / "audit", key_store=MemoryAuditKeys()).append({"event": "one"})
    assert state["calls"] == 1


def test_post_write_error_fails_without_retry_or_duplicate(tmp_path, monkeypatch):
    import contextlib

    from openmuse import audit

    real_stream = audit._append_stream
    state = {"calls": 0}

    @contextlib.contextmanager
    def fake_stream(path):
        state["calls"] += 1
        with real_stream(path) as handle:
            yield _FlakyHandle(handle)

    monkeypatch.setattr(audit, "_append_stream", fake_stream)
    with pytest.raises(PermissionError):
        AuditLog(tmp_path / "audit", key_store=MemoryAuditKeys()).append({"event": "one"})
    # One attempt only: the record may already be on disk, so retrying would
    # duplicate it. The single record written before the failure stays.
    assert state["calls"] == 1
    assert len(read_records(tmp_path / "audit")) == 1


# --- Finding: key stores must not lose keys under concurrency --------------


def test_concurrent_file_store_rotations_never_lose_a_key(tmp_path):
    import threading

    store = FileAuditKeys(tmp_path / "keys.json")
    ids, lock = [], threading.Lock()

    def worker():
        key_id, _ = store.rotate()
        with lock:
            ids.append(key_id)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(set(ids)) == 16
    for key_id in ids:
        assert store.resolve(key_id) is not None


class _SharedFakeKeyring:
    """Thread-safe in-memory credential store."""

    def __init__(self):
        import threading

        self.values = {}
        self.lock = threading.Lock()

    def get_password(self, service, account):
        with self.lock:
            return self.values.get((service, account))

    def set_password(self, service, account, value):
        with self.lock:
            self.values[(service, account)] = value

    def delete_password(self, service, account):
        with self.lock:
            self.values.pop((service, account), None)


def test_keyring_store_uses_one_credential_target_per_key_plus_pointer():
    backend = _SharedFakeKeyring()
    store = KeyringAuditKeys(backend=backend)
    key_id, _key = store.current()
    new_id, _ = store.rotate()
    services = {service for (service, _account) in backend.values}
    assert services == {
        "openmuse-agent.audit-hmac-key",
        f"openmuse-agent.audit-hmac-key.{key_id}",
        f"openmuse-agent.audit-hmac-key.{new_id}",
    }
    # One credential target (service) per key: the Windows adapter keeps a
    # single credential per service name, so sharing a service would put
    # concurrent key writes on a collision course.
    assert backend.values[("openmuse-agent.audit-hmac-key", "current")] == new_id


def test_keyring_store_stays_small_after_many_rotations():
    # Windows Credential Manager caps a credential at 2560 UTF-16 bytes; the
    # old single-document layout exceeded it after ~18 rotations. Per-key
    # credentials keep every stored value tiny regardless of rotation count.
    backend = _SharedFakeKeyring()
    store = KeyringAuditKeys(backend=backend)
    ids = [store.rotate()[0] for _ in range(40)]
    assert max(len(value) for value in backend.values.values()) < 100
    for key_id in ids:
        assert store.resolve(key_id) is not None


def test_concurrent_keyring_rotations_never_lose_a_key():
    import threading

    store = KeyringAuditKeys(backend=_SharedFakeKeyring())
    ids, lock = [], threading.Lock()

    def worker():
        key_id, _ = store.rotate()
        with lock:
            ids.append(key_id)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    for key_id in ids:
        assert store.resolve(key_id) is not None
    pointer, key = store.current()
    assert store.resolve(pointer) == key


def test_keyring_pointer_to_missing_key_fails_closed():
    backend = _SharedFakeKeyring()
    store = KeyringAuditKeys(backend=backend)
    store.current()
    backend.values[("openmuse-agent.audit-hmac-key", "current")] = "f" * 16
    with pytest.raises(AuditKeyError, match="current key is missing"):
        store.current()


def test_malformed_key_id_is_a_plain_miss():
    store = KeyringAuditKeys(backend=_SharedFakeKeyring())
    store.current()
    assert store.resolve("../escape") is None
    assert store.resolve("Z" * 16) is None


def test_keyring_store_rejects_corrupt_key_credential():
    import base64

    backend = _SharedFakeKeyring()
    store = KeyringAuditKeys(backend=backend)
    key_id, _ = store.current()
    backend.values[(f"openmuse-agent.audit-hmac-key.{key_id}", "key")] = base64.urlsafe_b64encode(b"tiny").decode()
    with pytest.raises(AuditKeyError, match="corrupt"):
        store.resolve(key_id)


# --- WinVault adapter semantics: one credential per service target ---------


class WinVaultEmulator:
    """Faithful model of keyring.backends.Windows.WinVaultKeyring (25.7).

    One credential target per service name. set_password read-modify-writes
    the target non-atomically: a displaced value is first moved to a compound
    "{username}@{service}" target, then the new value overwrites the target.
    get_password falls back to the compound name on a username mismatch.
    """

    def __init__(self, hook=None):
        self.targets = {}
        self.hook = hook or (lambda: None)

    def get_password(self, service, username):
        cred = self.targets.get(service)
        if cred is None or (username and cred[0] != username):
            cred = self.targets.get(f"{username}@{service}")
        return cred[1] if cred else None

    def set_password(self, service, username, password):
        existing = self.targets.get(service)
        self.hook()  # the real adapter is not atomic between read and write
        if existing is not None:
            self.targets[f"{existing[0]}@{service}"] = existing
        self.targets[service] = (username, password)

    def delete_password(self, service, username):
        self.targets.pop(service, None)


def test_winvault_emulator_matches_adapter_semantics():
    backend = WinVaultEmulator()
    backend.set_password("svc", "alice", "p1")
    backend.set_password("svc", "bob", "p2")
    # Sequential writes survive via the compound-name move.
    assert backend.get_password("svc", "alice") == "p1"
    assert backend.get_password("svc", "bob") == "p2"


def test_winvault_emulator_concurrent_writes_under_one_service_lose_one():
    # Pins why keys never share a service target: two writers that both read
    # before either writes each see nothing to move, and one value vanishes.
    import threading

    barrier = threading.Barrier(2, timeout=10)
    backend = WinVaultEmulator(hook=barrier.wait)

    def write(username, password):
        backend.set_password("svc", username, password)

    threads = [
        threading.Thread(target=write, args=("alice", "p1")),
        threading.Thread(target=write, args=("bob", "p2")),
    ]
    [t.start() for t in threads]
    [t.join() for t in threads]
    survivors = [backend.get_password("svc", name) for name in ("alice", "bob")]
    assert survivors.count(None) == 1  # one writer's value is gone


def test_concurrent_rotations_on_winvault_semantics_lose_no_key():
    # Same interleaving as above: both rotations' first writes rendezvous
    # mid-set_password. Unique per-key targets keep every key resolvable.
    import threading

    barrier = threading.Barrier(2, timeout=10)
    store = KeyringAuditKeys(backend=WinVaultEmulator(hook=barrier.wait))
    ids, lock = [], threading.Lock()

    def worker():
        key_id, _ = store.rotate()
        with lock:
            ids.append(key_id)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(set(ids)) == 2
    for key_id in ids:
        assert store.resolve(key_id) is not None
    pointer, key = store.current()
    assert store.resolve(pointer) == key


def test_pointer_readback_tolerates_a_normal_race():
    # A concurrent writer legitimately moves the pointer between our write
    # and our re-read; convergence must win over strict equality.
    backend = _SharedFakeKeyring()
    store = KeyringAuditKeys(backend=backend)
    original_write_pointer = store._write_pointer

    def racing_write_pointer(key_id):
        original_write_pointer(key_id)
        other = secrets.token_bytes(32)
        store._write_key(hashlib.sha256(other).hexdigest()[:16], other)
        original_write_pointer(hashlib.sha256(other).hexdigest()[:16])

    store._write_pointer = racing_write_pointer
    pointer, key = store.current()
    assert store.resolve(pointer) == key


# --- Upgrade path from the pre-split single-document store -----------------


def _seed_legacy_document(backend, keys, current):
    import base64

    doc = {
        "current": current,
        "keys": {key_id: base64.urlsafe_b64encode(key).decode() for key_id, key in keys.items()},
    }
    backend.set_password("openmuse-agent", "audit-hmac-keys", json.dumps(doc))


def test_legacy_document_store_migrates_on_first_use():
    backend = _SharedFakeKeyring()
    old, new = secrets.token_bytes(32), secrets.token_bytes(32)
    old_id = hashlib.sha256(old).hexdigest()[:16]
    new_id = hashlib.sha256(new).hexdigest()[:16]
    _seed_legacy_document(backend, {old_id: old, new_id: new}, new_id)

    store = KeyringAuditKeys(backend=backend)
    key_id, key = store.current()
    assert (key_id, key) == (new_id, new)
    assert store.resolve(old_id) == old
    # Both keys now live in their own targets and the document is removed.
    assert backend.get_password("openmuse-agent", "audit-hmac-keys") is None
    assert backend.get_password(f"openmuse-agent.audit-hmac-key.{old_id}", "key") is not None


class _NoDeleteFakeKeyring(_SharedFakeKeyring):
    delete_password = None  # attribute exists but is not callable


def test_resolve_falls_back_to_legacy_document_without_migration():
    backend = _NoDeleteFakeKeyring()
    old = secrets.token_bytes(32)
    old_id = hashlib.sha256(old).hexdigest()[:16]
    _seed_legacy_document(backend, {old_id: old}, old_id)
    store = KeyringAuditKeys(backend=backend)
    assert store.resolve(old_id) == old


def test_chain_keyed_under_legacy_document_store_still_verifies(tmp_path):
    # History written by the pre-split format must not become "unknown audit
    # key id" after upgrade - including before any migration runs.
    key = secrets.token_bytes(32)
    key_id = hashlib.sha256(key).hexdigest()[:16]
    backend = _NoDeleteFakeKeyring()
    _seed_legacy_document(backend, {key_id: key}, key_id)

    path = tmp_path / "audit"
    record = {
        "event": "before-upgrade",
        "previous_hash": "0" * 64,
        "chain": "hmac-sha256",
        "key_id": key_id,
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    record["hash"] = hmac.new(key, raw, hashlib.sha256).hexdigest()
    path.write_text(json.dumps(record, ensure_ascii=False) + "\n")

    store = KeyringAuditKeys(backend=backend)
    assert verify_chain(path, key_store=store) == (True, 1, None)
    AuditLog(path, key_store=store).append({"event": "after-upgrade"})
    assert verify_chain(path, key_store=store) == (True, 2, None)


def test_corrupt_legacy_document_fails_closed():
    backend = _SharedFakeKeyring()
    backend.set_password("openmuse-agent", "audit-hmac-keys", "not-json{")
    store = KeyringAuditKeys(backend=backend)
    with pytest.raises(AuditKeyError, match="corrupt"):
        store.current()


def test_legacy_document_without_current_key_creates_fresh():
    backend = _SharedFakeKeyring()
    old = secrets.token_bytes(32)
    old_id = hashlib.sha256(old).hexdigest()[:16]
    _seed_legacy_document(backend, {old_id: old}, None)
    store = KeyringAuditKeys(backend=backend)
    key_id, key = store.current()
    assert key_id != old_id and len(key) == 32
    assert store.resolve(old_id) == old
