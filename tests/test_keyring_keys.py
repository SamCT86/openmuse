import base64

import pytest

from openmuse.keyring_keys import KeyringMasterKey, MasterKeyError


class MemoryKeyring:
    def __init__(self, value=None):
        self.value = value

    def get_password(self, service, account):
        return self.value

    def set_password(self, service, account, value):
        self.value = value


def test_keyring_master_key_is_created_once_and_reloaded():
    backend = MemoryKeyring()
    provider = KeyringMasterKey(backend=backend)
    first = provider.load_or_create()
    assert len(first) == 32
    assert provider.load_or_create() == first
    assert base64.urlsafe_b64decode(backend.value) == first


@pytest.mark.parametrize("value", ["not-base64!", base64.urlsafe_b64encode(b"short").decode()])
def test_invalid_keyring_values_fail_closed(value):
    with pytest.raises(MasterKeyError):
        KeyringMasterKey(backend=MemoryKeyring(value)).load_or_create()


import sys
from types import SimpleNamespace

from openmuse.keyring_keys import system_credential_store


def _fake_backend(module, name, priority=5, **attrs):
    return type(name, (), {"__module__": module, "priority": priority, **attrs})()


def _install_fake_keyring(monkeypatch, backend):
    module = SimpleNamespace(get_keyring=lambda: backend)
    monkeypatch.setitem(sys.modules, "keyring", module)
    return module


@pytest.mark.parametrize(
    "module,name",
    [
        ("keyring.backends.macOS", "Keyring"),
        ("keyring.backends.Windows", "WinVaultKeyring"),
        ("keyring.backends.SecretService", "Keyring"),
        ("keyring.backends.libsecret", "Keyring"),
        ("keyring.backends.kwallet", "DBusKeyring"),
    ],
)
def test_os_store_backends_are_accepted(monkeypatch, module, name):
    backend = _fake_backend(module, name)
    installed = _install_fake_keyring(monkeypatch, backend)
    assert system_credential_store() is installed


@pytest.mark.parametrize(
    "module,name,priority",
    [
        # Plaintext-file and in-memory backends report a positive priority;
        # the priority check alone used to wave them through.
        ("keyrings.alt.file", "PlaintextKeyring", 1),
        ("keyrings.alt.file", "EncryptedKeyring", 1),
        ("keyring.backends.fail", "Keyring", 0),
        ("keyring.backends.null", "Keyring", 1),
    ],
)
def test_non_os_store_backends_fail_closed(monkeypatch, module, name, priority):
    _install_fake_keyring(monkeypatch, _fake_backend(module, name, priority=priority))
    with pytest.raises(MasterKeyError, match="no usable OS credential-store backend"):
        system_credential_store()


def test_chainer_backend_accepted_only_when_every_member_is_an_os_store(monkeypatch):
    macos = _fake_backend("keyring.backends.macOS", "Keyring")
    secret_service = _fake_backend("keyring.backends.SecretService", "Keyring")
    plaintext = _fake_backend("keyrings.alt.file", "PlaintextKeyring", priority=1)

    clean = _fake_backend("keyring.backends.chainer", "ChainerBackend", priority=10)
    clean.backends = [macos, secret_service]
    installed = _install_fake_keyring(monkeypatch, clean)
    assert system_credential_store() is installed

    mixed = _fake_backend("keyring.backends.chainer", "ChainerBackend", priority=10)
    mixed.backends = [macos, plaintext]
    _install_fake_keyring(monkeypatch, mixed)
    with pytest.raises(MasterKeyError, match="no usable OS credential-store backend"):
        system_credential_store()
