"""Envelope-encrypted secret storage; plaintext never enters planner context."""

import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class SecretVault:
    path: Path
    master_key: bytes

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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(records), encoding="utf-8")

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

    def _load(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
