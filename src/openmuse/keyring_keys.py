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
        try:
            import keyring  # type: ignore[import-not-found]
        except ImportError as error:  # pragma: no cover - dependency is declared
            raise MasterKeyError("install the keyring dependency to use OS-backed keys") from error
        backend = keyring.get_keyring()
        priority = getattr(backend, "priority", 0)
        if priority <= 0:
            raise MasterKeyError("no usable OS credential-store backend is available")
        return keyring
