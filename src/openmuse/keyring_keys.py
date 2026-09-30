"""OS-backed master-key provider for encrypted OpenMuse vaults."""

import base64
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CredentialStore(Protocol):
    def get_password(self, service: str, account: str) -> str | None: ...
    def set_password(self, service: str, account: str, password: str) -> None: ...


class MasterKeyError(RuntimeError):
    pass


# OS credential stores we trust: the platform vaults only. Plaintext-file and
# in-memory keyring backends (keyrings.alt and similar) report a positive
# priority, so the priority check alone cannot keep them out.
_OS_STORE_BACKENDS = {
    ("keyring.backends.Windows", "WinVaultKeyring"),
    ("keyring.backends.macOS", "Keyring"),
    ("keyring.backends.SecretService", "Keyring"),
    ("keyring.backends.libsecret", "Keyring"),
    ("keyring.backends.kwallet", "DBusKeyring"),
}


def _is_os_store(backend: object) -> bool:
    """True only for known OS credential-store backends.

    A ChainerBackend qualifies only when every backend it can fall through to
    is itself an OS store - otherwise a degraded desktop session silently
    lands on a plaintext member.
    """
    cls = type(backend)
    if (cls.__module__, cls.__name__) in _OS_STORE_BACKENDS:
        return True
    chain = getattr(backend, "backends", None)  # keyring ChainerBackend
    if isinstance(chain, (list, tuple)) and chain:
        return all(_is_os_store(item) for item in chain)
    return False


@dataclass(frozen=True)
class KeyringMasterKey:
    """Load or create a 256-bit vault key in the system credential store."""

    service: str = "openmuse-agent"
    account: str = "default-vault-master-key"
    backend: CredentialStore | None = None

    def load_or_create(self) -> bytes:
        backend = self.backend or self._system_backend()
        encoded = backend.get_password(self.service, self.account)
        if encoded is None:
            key = AESGCM.generate_key(bit_length=256)
            backend.set_password(self.service, self.account, base64.urlsafe_b64encode(key).decode("ascii"))
            encoded = backend.get_password(self.service, self.account)
            if encoded is None:
                raise MasterKeyError("credential store did not persist the master key")
        try:
            key = base64.urlsafe_b64decode(encoded.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as error:
            raise MasterKeyError("credential store contains an invalid master key") from error
        if len(key) != 32:
            raise MasterKeyError("credential store master key must be 256 bits")
        return key

    @staticmethod
    def _system_backend() -> CredentialStore:
        return system_credential_store()


def system_credential_store() -> CredentialStore:
    """Return the OS credential store (Keychain, Credential Manager, libsecret).

    Fails closed when the keyring dependency is missing or no usable backend
    exists (for example a headless Linux session without Secret Service).
    """
    try:
        import keyring  # type: ignore[import-not-found]
    except ImportError as error:  # pragma: no cover - dependency is declared
        raise MasterKeyError("install the keyring dependency to use OS-backed keys") from error
    backend = keyring.get_keyring()
    priority = getattr(backend, "priority", 0)
    if priority <= 0 or not _is_os_store(backend):
        raise MasterKeyError(
            "no usable OS credential-store backend is available "
            f"(found {type(backend).__module__}.{type(backend).__name__}); "
            "plaintext-file and in-memory keyring backends are not accepted"
        )
    return keyring
