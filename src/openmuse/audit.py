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
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from .keyring_keys import CredentialStore, MasterKeyError, system_credential_store

SENSITIVE = {"password", "token", "secret", "authorization", "api_key", "cookie"}
ZERO = "0" * 64
KEYED_ALGORITHM = "hmac-sha256"
KEY_FILE_ENV = "OPENMUSE_AUDIT_KEY_FILE"
_KEYRING_SERVICE = "openmuse-agent"
_KEYRING_ACCOUNT = "audit-hmac-keys"


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


def _fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


class _DocKeyStore:
    """Shared logic for stores keeping ``{"current": id, "keys": {id: b64}}``."""

    def _read_text(self) -> str | None:
        raise NotImplementedError

    def _write_text(self, text: str, exclusive: bool = False) -> None:
        raise NotImplementedError

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


class KeyringAuditKeys(_DocKeyStore):
    """Audit-chain keys in the OS credential store; the only production store.

    Retired keys stay in the store so rotated history remains verifiable; deleting
    them invalidates verification of the records they cover.
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

    def _read_text(self) -> str | None:
        return self._backend.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)

    def _write_text(self, text: str, exclusive: bool = False) -> None:
        self._backend.set_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT, text)
        if self._backend.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT) != text:
            raise AuditKeyError("credential store did not persist the audit chain key")


class FileAuditKeys(_DocKeyStore):
    """Key file backend for disposable containers, demos, and tests.

    NOT a security boundary: anyone who can read the audit file can usually read a
    sibling key file too. Selected only through the explicit OPENMUSE_AUDIT_KEY_FILE
    environment variable or direct construction - never as a silent fallback. The
    file must be owner-only (0600); loose permissions fail closed on POSIX.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

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
        # Resolve the key before touching the file: no key, no record, no file.
        keys = None if self._legacy else self._keys()
        for attempt in range(4):
            try:
                self._append_once(record, keys)
                return
            except PermissionError:
                # Native Windows opens can lose a sharing race against concurrent
                # appenders before the lock is taken; the write has not happened
                # yet, so retrying the whole append is safe (docs/native-windows.md).
                if os.name != "nt" or attempt == 3:
                    raise
                import time

                time.sleep(0.05 * (attempt + 1))

    def _append_once(self, record: dict[str, Any], keys: tuple[str, bytes] | None) -> None:
        with _append_stream(self.path) as handle:
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
