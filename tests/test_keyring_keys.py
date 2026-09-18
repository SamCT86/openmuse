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
