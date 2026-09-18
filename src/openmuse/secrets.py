"""Envelope-encrypted secret storage; plaintext never enters planner context."""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MasterKeyProvider(Protocol):
    def load_or_create(self) -> bytes: ...


@dataclass
class SecretVault:
    path: Path
    master_key: bytes

    @classmethod
    def open(cls, path: Path, provider: MasterKeyProvider) -> "SecretVault":
        return cls(path, provider.load_or_create())

    def put(self, name: str, value: str) -> None:
        dek = AESGCM.generate_key(bit_length=256)
        wrap_nonce, data_nonce = __import__("os").urandom(12), __import__("os").urandom(12)
        wrapped = AESGCM(self.master_key).encrypt(wrap_nonce, dek, name.encode())
        ciphertext = AESGCM(dek).encrypt(data_nonce, value.encode(), name.encode())
        records = self._load()
        records[name] = {
            "wrap_nonce": wrap_nonce.hex(),
            "wrapped_key": wrapped.hex(),
            "data_nonce": data_nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }
        self._write(records)

    def use(self, name: str, consumer) -> None:
        record = self._load()[name]
        dek = AESGCM(self.master_key).decrypt(
            bytes.fromhex(record["wrap_nonce"]), bytes.fromhex(record["wrapped_key"]), name.encode()
        )
        plaintext = AESGCM(dek).decrypt(
            bytes.fromhex(record["data_nonce"]), bytes.fromhex(record["ciphertext"]), name.encode()
        )
        try:
            consumer(plaintext.decode())
        finally:
            plaintext = b""

    def list(self) -> list[str]:
        return sorted(self._load())

    def delete(self, name: str) -> None:
        records = self._load()
        records.pop(name, None)
        self._write(records)

    def _write(self, records: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(records, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)
        self.path.chmod(0o600)

    def _load(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
