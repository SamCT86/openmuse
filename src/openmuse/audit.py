"""Keyed (HMAC-SHA256) hash-chained audit with bounded append and independent verification.

Every audit record carries an HMAC-SHA256 over its canonical JSON, chained through
``previous_hash``. The key lives in the OS credential store (macOS Keychain, Windows
Credential Manager, or libsecret via the ``keyring`` package), never in the workspace
or repository. Forging or rewriting a record therefore requires key access, not just
write access to the audit file.

Legacy chains written before keying (plain SHA-256 links, no ``chain`` field) remain
verifiable without a key. A mixed chain may switch from legacy to keyed exactly once;
the first keyed record anchors the legacy head hash under its HMAC, so the legacy
prefix can no longer be altered without the key. Keyed records can never be followed
by legacy ones.

Residual limits, by design: a same-OS-user process with credential-store access can
still forge, and truncating or wholesale replacing the file is only detectable through
externally anchored signed checkpoints (see ``audit_anchor``).
"""

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from .keyring_keys import CredentialStore, MasterKeyError, system_credential_store

SENSITIVE = {"password", "token", "secret", "authorization", "api_key", "cookie"}
ZERO = "0" * 64
_RESERVED_RECORD_FIELDS = {"hash", "previous_hash", "chain", "key_id"}
KEYED_ALGORITHM = "hmac-sha256"
KEY_FILE_ENV = "OPENMUSE_AUDIT_KEY_FILE"
_KEYRING_SERVICE = "openmuse-agent"
_KEYRING_POINTER_SERVICE = "openmuse-agent.audit-hmac-key"
_KEYRING_POINTER_ACCOUNT = "current"
_KEYRING_KEY_ACCOUNT = "key"
_KEYRING_KEY_SERVICE_PREFIX = "openmuse-agent.audit-hmac-key."
_KEYRING_LEGACY_ACCOUNT = "audit-hmac-keys"  # pre-split single-document format
_KEY_ID_LENGTH = 16


def _keyring_key_service(key_id: str) -> str:
    """One credential target per key.

    The Windows Credential Manager adapter keeps a single credential per
    *service* name and read-modify-writes that target: a displaced value is
    moved to a compound ``{username}@{service}`` target before the new value
    is written. That move is not atomic - two writers to the same service can
    both read the old state and one value is lost - so distinct accounts
    under one shared service are not safe under concurrency. A unique service
    per key makes every key write touch a disjoint target.
    """
    return _KEYRING_KEY_SERVICE_PREFIX + key_id


class AuditKeyError(RuntimeError):
    """The audit chain key is unavailable; callers must fail closed."""


class AuditKeyStore(Protocol):
    """Resolves and rotates audit-chain HMAC keys."""

    def current(self) -> tuple[str, bytes]:
        """Return (key id, key), creating the first key when none exists."""
        ...

    def rotate(self) -> tuple[str, bytes]:
        """Retire the current key and return a fresh (key id, key)."""
        ...

    def resolve(self, key_id: str) -> bytes | None:
        """Return the key for a record's key id, or None when unknown."""
        ...


class _SharingViolation(PermissionError):
    """Win32 sharing violation (error 32) while acquiring the audit handle.

    Raised only for failures before any byte is written, so retrying the
    whole append cannot duplicate a record. Only Win32 errors carry a
    ``winerror`` of 32, which keeps the retry Windows-specific.
    """


def _fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:_KEY_ID_LENGTH]


def _valid_key_id(key_id: object) -> bool:
    return (
        isinstance(key_id, str)
        and len(key_id) == _KEY_ID_LENGTH
        and all(char in "0123456789abcdef" for char in key_id)
    )


class _DocKeyStore:
    """Shared logic for stores keeping ``{"current": id, "keys": {id: b64}}``."""

    def _read_text(self) -> str | None:
        raise NotImplementedError

    def _write_text(self, text: str, exclusive: bool = False) -> None:
        raise NotImplementedError

    @contextlib.contextmanager
    def _mutation_lock(self):
        """Serialize one whole read-modify-write across processes."""
        yield

    def _load(self) -> dict[str, Any]:
        text = self._read_text()
        if text is None:
            return {"current": None, "keys": {}}
        try:
            doc = json.loads(text)
            keys = {kid: _decode_key(raw) for kid, raw in doc["keys"].items()}
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise AuditKeyError("audit key store is corrupt") from error
        current = doc.get("current")
        if current is not None and current not in keys:
            raise AuditKeyError("audit key store current key is missing")
        return {"current": current, "keys": keys}

    def _save(self, doc: dict[str, Any], exclusive: bool = False) -> None:
        encoded = {kid: _encode_key(key) for kid, key in doc["keys"].items()}
        self._write_text(json.dumps({"current": doc["current"], "keys": encoded}, sort_keys=True), exclusive=exclusive)

    def current(self) -> tuple[str, bytes]:
        with self._mutation_lock():
            doc = self._load()
            if doc["current"] is None:
                key = secrets.token_bytes(32)
                key_id = _fingerprint(key)
                doc["keys"][key_id] = key
                doc["current"] = key_id
                try:
                    self._save(doc, exclusive=True)
                except FileExistsError:
                    doc = self._load()  # a concurrent creator won; use its key
            return doc["current"], doc["keys"][doc["current"]]

    def rotate(self) -> tuple[str, bytes]:
        with self._mutation_lock():
            doc = self._load()
            key = secrets.token_bytes(32)
            key_id = _fingerprint(key)
            doc["keys"][key_id] = key
            doc["current"] = key_id
            self._save(doc)
            return key_id, key

    def resolve(self, key_id: str) -> bytes | None:
        return self._load()["keys"].get(key_id)


def _encode_key(key: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(key).decode("ascii")


def _decode_key(raw: str) -> bytes:
    import base64

    key = base64.urlsafe_b64decode(raw.encode("ascii"))
    if len(key) != 32:
        raise ValueError("audit chain keys must be 256 bits")
    return key


class KeyringAuditKeys:
    """Audit-chain keys in the OS credential store; the only production store.

    Every key is its own credential target (service
    ``openmuse-agent.audit-hmac-key.<key id>``) and a small pointer credential
    names the current key id. This layout serves three purposes:

    - **Size.** Windows Credential Manager caps a credential at 2560 UTF-16
      bytes; a single growing JSON document hits that cap after roughly 18
      rotations. Every credential here stays far below the limit, so rotation
      has no practical count bound beyond the store's entry capacity.
    - **Concurrency.** OS stores offer no compare-and-swap, so a shared
      read-modify-write document loses keys when two rotations race (the
      loser's overwrite drops the winner's key, orphaning the records it
      covers). The Windows adapter makes this worse: it keeps one credential
      per service name and read-modify-writes that target non-atomically
      (a displaced value is moved to a compound ``{username}@{service}``
      target), so even separate accounts under one service can lose a value
      when writes race. Here every key write targets a disjoint credential,
      and writers converge on one current key by re-reading the pointer
      after moving it; a key already handed out stays resolvable regardless
      of the pointer's final value.
    - **Upgrade.** Stores written by the pre-split format (one JSON document
      under the ``audit-hmac-keys`` account) migrate on first use, and
      ``resolve`` falls back to the legacy document so old keyed history
      keeps verifying even before migration runs.

    Retired keys stay in the store so rotated history remains verifiable;
    deleting them invalidates verification of the records they cover.
    """

    def __init__(self, backend: CredentialStore | None = None) -> None:
        if backend is None:
            try:
                backend = system_credential_store()
            except MasterKeyError as error:
                raise AuditKeyError(
                    "audit chain requires an OS credential store (macOS Keychain, Windows "
                    "Credential Manager, or libsecret); none is available"
                ) from error
        self._backend = backend

    def _pointer(self) -> str | None:
        return self._backend.get_password(_KEYRING_POINTER_SERVICE, _KEYRING_POINTER_ACCOUNT)

    def _write_key(self, key_id: str, key: bytes) -> None:
        # Strict read-back is safe here: the target is unique to this key, so
        # no concurrent writer can legitimately change it.
        encoded = _encode_key(key)
        service = _keyring_key_service(key_id)
        self._backend.set_password(service, _KEYRING_KEY_ACCOUNT, encoded)
        if self._backend.get_password(service, _KEYRING_KEY_ACCOUNT) != encoded:
            raise AuditKeyError("credential store did not persist the audit chain key")

    def _write_pointer(self, key_id: str) -> None:
        # No strict read-back: a concurrent creator/rotator may legitimately
        # have moved the pointer past our value. _converge() validates what
        # actually landed.
        self._backend.set_password(_KEYRING_POINTER_SERVICE, _KEYRING_POINTER_ACCOUNT, key_id)

    def _converge(self) -> tuple[str, bytes]:
        """Re-read the pointer after moving it and return the actual current key.

        Without CAS the pointer is last-writer-wins; returning the post-write
        value keeps concurrent creators/rotators on one key, and every written
        key credential stays resolvable even when its writer loses the race.
        """
        pointer = self._pointer()
        if pointer is None:
            raise AuditKeyError("credential store did not persist the audit chain key pointer")
        key = self.resolve(pointer)
        if key is None:
            raise AuditKeyError("audit chain current key is missing from the credential store")
        return pointer, key

    def _legacy_doc(self) -> tuple[str | None, dict[str, bytes]] | None:
        """Read the pre-split single-document store, when present."""
        raw = self._backend.get_password(_KEYRING_SERVICE, _KEYRING_LEGACY_ACCOUNT)
        if raw is None:
            return None
        try:
            doc = json.loads(raw)
            keys = {kid: _decode_key(encoded) for kid, encoded in doc["keys"].items()}
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            raise AuditKeyError("audit key store is corrupt") from error
        current = doc.get("current")
        if current is not None and current not in keys:
            raise AuditKeyError("audit key store current key is missing")
        return current, keys

    def _migrate_legacy(self, current: str | None, keys: dict[str, bytes]) -> None:
        for key_id, key in keys.items():
            self._write_key(key_id, key)
        if current is not None:
            self._write_pointer(current)
        # Best-effort cleanup of the superseded document; resolve() keeps
        # falling back to it whenever deletion is unavailable or fails.
        delete = getattr(self._backend, "delete_password", None)
        if callable(delete):
            with contextlib.suppress(Exception):
                delete(_KEYRING_SERVICE, _KEYRING_LEGACY_ACCOUNT)

    def current(self) -> tuple[str, bytes]:
        pointer = self._pointer()
        if pointer is None:
            legacy = self._legacy_doc()
            if legacy is not None:
                self._migrate_legacy(*legacy)
                if legacy[0] is not None:
                    return self._converge()
                # A legacy store that never initialized has no current key:
                # its keys migrated above; fall through to first creation.
            key = secrets.token_bytes(32)
            self._write_key(_fingerprint(key), key)
            self._write_pointer(_fingerprint(key))
        else:
            existing = self.resolve(pointer)
            if existing is None:
                raise AuditKeyError("audit chain current key is missing from the credential store")
            return pointer, existing
        return self._converge()

    def rotate(self) -> tuple[str, bytes]:
        key = secrets.token_bytes(32)
        self._write_key(_fingerprint(key), key)
        self._write_pointer(_fingerprint(key))
        return self._converge()

    def _read_split_key(self, key_id: str) -> bytes | None:
        raw = self._backend.get_password(_keyring_key_service(key_id), _KEYRING_KEY_ACCOUNT)
        if raw is None:
            return None
        try:
            return _decode_key(raw)
        except ValueError as error:
            raise AuditKeyError("audit key store is corrupt") from error

    def resolve(self, key_id: str) -> bytes | None:
        # Key ids come from audit records; a malformed one must be a plain
        # miss, never a lookup of an attacker-shaped credential name.
        if not _valid_key_id(key_id):
            return None
        key = self._read_split_key(key_id)
        if key is not None:
            return key
        legacy = self._legacy_doc()
        if legacy is not None and key_id in legacy[1]:
            return legacy[1][key_id]
        # A concurrent first-use migration may have moved the key from the
        # legacy document to its split target between our two reads; check
        # the target once more before declaring the key unknown.
        return self._read_split_key(key_id)


class FileAuditKeys(_DocKeyStore):
    """Key file backend for disposable containers, demos, and tests.

    NOT a security boundary: anyone who can read the audit file can usually read a
    sibling key file too. Selected only through the explicit OPENMUSE_AUDIT_KEY_FILE
    environment variable or direct construction - never as a silent fallback. The
    file must be owner-only (0600); loose permissions fail closed on POSIX.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @contextlib.contextmanager
    def _mutation_lock(self):
        """Serialize current()/rotate() across processes via a sibling lock file.

        Held OS locks release on process death, so a crashed writer cannot
        wedge the store the way a stale create-if-absent lock file would.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path.with_name(self.path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                deadline = time.monotonic() + 10
                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("audit key store lock timed out")
                        time.sleep(0.01)
                try:
                    yield
                finally:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
        finally:
            os.close(fd)

    def _check_permissions(self) -> None:
        if os.name == "nt" or not self.path.exists():
            return
        mode = stat.S_IMODE(self.path.stat().st_mode)
        if mode & 0o077:
            raise AuditKeyError(f"audit key file {self.path} must be owner-only (0600)")

    def _read_text(self) -> str | None:
        self._check_permissions()
        try:
            return self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None

    def _write_text(self, text: str, exclusive: bool = False) -> None:
        # Write a complete temp file, then move it into place atomically so a
        # concurrent reader never observes a partial key document.
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f"{self.path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            if exclusive:
                try:
                    os.link(tmp, self.path)  # atomic create-or-fail
                except FileExistsError:
                    raise
                except OSError:
                    os.replace(tmp, self.path)  # no hardlink support on this volume
            else:
                os.replace(tmp, self.path)
        finally:
            tmp.unlink(missing_ok=True)


def default_key_store() -> AuditKeyStore:
    """Resolve the default store: explicit key file, else the OS credential store."""
    key_file = os.environ.get(KEY_FILE_ENV)
    if key_file:
        return FileAuditKeys(Path(key_file))
    return KeyringAuditKeys()


@contextlib.contextmanager
def _append_stream(path: Path):
    if os.name == "nt":
        from .windows_fs import audit_stream
        with audit_stream(path) as handle:
            yield handle
    else:
        import fcntl
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "r+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield handle


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


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class AuditLog:
    """Append-only keyed audit chain.

    ``key_store`` defaults to the OS credential store (or OPENMUSE_AUDIT_KEY_FILE
    when explicitly set) and fails closed when no store is available. Use
    ``AuditLog.legacy(path)`` only to reproduce the pre-keying unkeyed format in
    compatibility tests and migrations.
    """

    def __init__(self, path: Path, key_store: AuditKeyStore | None = None, _legacy: bool = False):
        self.path = path
        self._key_store = key_store
        self._legacy = _legacy

    @classmethod
    def legacy(cls, path: Path) -> "AuditLog":
        """Write the pre-keying unkeyed SHA-256 format; never for production use."""
        return cls(path, _legacy=True)

    def _keys(self) -> tuple[str, bytes]:
        if self._key_store is None:
            self._key_store = default_key_store()
        return self._key_store.current()

    def append(self, record: dict[str, Any]) -> None:
        reserved = _RESERVED_RECORD_FIELDS.intersection(record)
        if reserved:
            # Callers never supply chain fields; an injected "chain"/"key_id"
            # would otherwise land in the record and break verification.
            raise ValueError(f"audit record must not set reserved field(s): {', '.join(sorted(reserved))}")
        # Resolve the key before touching the file: no key, no record, no file.
        keys = None if self._legacy else self._keys()
        for attempt in range(4):
            try:
                self._append_once(record, keys)
                return
            except _SharingViolation:
                # Native Windows opens can lose a sharing race (antivirus,
                # indexer, a concurrent appender) before the lock is taken.
                # The write has not happened yet, so retrying the whole
                # append is safe (docs/native-windows.md).
                if attempt == 3:
                    raise
                time.sleep(0.05 * (attempt + 1))

    def _append_once(self, record: dict[str, Any], keys: tuple[str, bytes] | None) -> None:
        with contextlib.ExitStack() as stack:
            try:
                handle = stack.enter_context(_append_stream(self.path))
            except PermissionError as error:
                # Only a sharing violation while acquiring the handle is
                # retryable. Anything at or after the write - the write
                # itself, flush, sync, unlock - fails immediately, because
                # the record may already be on disk and a retry would
                # duplicate it.
                if getattr(error, "winerror", None) == 32:
                    raise _SharingViolation(*error.args) from error
                raise
            last = _last_record(handle)
            clean = redact(record)
            clean["previous_hash"] = last["hash"] if last else ZERO
            if keys is None:
                clean["hash"] = hashlib.sha256(_canonical(clean)).hexdigest()
            else:
                key_id, key = keys
                clean["chain"] = KEYED_ALGORITHM
                clean["key_id"] = key_id
                clean["hash"] = hmac.new(key, _canonical(clean), hashlib.sha256).hexdigest()
            handle.seek(0, os.SEEK_END)
            handle.write((json.dumps(clean, ensure_ascii=False) + "\n").encode())
            handle.flush()
            os.fsync(handle.fileno())


@contextlib.contextmanager
def _verify_stream(path: Path):
    """Read only a pinned ordinary file; never follow a leaf symlink."""
    if os.name == "nt":
        from .windows_fs import _duplicate_fd, file_handle
        with file_handle(path.parent, path.name) as handle, os.fdopen(
            _duplicate_fd(handle, write=False), "r", encoding="utf-8"
        ) as stream:
            yield stream
    else:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            yield stream


def verify_chain(
    path: Path,
    key_store: AuditKeyStore | None = None,
    require_keyed: bool = False,
) -> tuple[bool, int, str | None]:
    """Independently stream every link; memory usage is bounded by a record.

    Legacy (unkeyed) records verify without a key but must all precede the first
    keyed record. Keyed records require resolving their ``key_id``; ``key_store``
    defaults to the same resolution as appends (key file env, else OS credential
    store) and a missing store or unknown key fails rather than skipping the check.
    ``require_keyed=True`` rejects any unkeyed record, for deployments that know
    their chain must be keyed from the first line.
    """
    previous = ZERO
    count = 0
    seen_keyed = False
    try:
        with _verify_stream(path) as handle:
            for count, line in enumerate(handle, start=1):
                record = json.loads(line)
                if not isinstance(record, dict):
                    return False, count, "audit record must be an object"
                claimed = record.pop("hash")
                if record.get("previous_hash") != previous:
                    return False, count, "previous hash does not match"
                algorithm = record.get("chain")
                if algorithm is None:
                    if require_keyed:
                        return False, count, "record is not keyed"
                    if seen_keyed:
                        return False, count, "unkeyed record after keyed records"
                    actual = hashlib.sha256(_canonical(record)).hexdigest()
                elif algorithm == KEYED_ALGORITHM:
                    seen_keyed = True
                    key_id = record.get("key_id")
                    if not isinstance(key_id, str):
                        return False, count, "keyed record is missing its key id"
                    if key_store is None:
                        key_store = default_key_store()
                    key = key_store.resolve(key_id)
                    if key is None:
                        return False, count, "unknown audit key id"
                    actual = hmac.new(key, _canonical(record), hashlib.sha256).hexdigest()
                else:
                    return False, count, f"unknown chain algorithm: {algorithm}"
                if not hmac_compare(actual, claimed):
                    return False, count, "record hash does not match"
                previous = claimed
    except AuditKeyError as error:
        return False, count, str(error)
    except (OSError, KeyError, ValueError, TypeError) as exc:
        return False, count, str(exc)
    return True, count, None


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)
