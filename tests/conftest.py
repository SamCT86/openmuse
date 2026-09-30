"""Shared fixtures: every test gets an isolated, explicit audit key file.

Production resolves keys from the OS credential store; tests point
OPENMUSE_AUDIT_KEY_FILE at a per-test file so keyed chains work without a
desktop credential service. Tests for store failure delete the variable.
"""

import pytest


@pytest.fixture(autouse=True)
def _audit_key_file(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENMUSE_AUDIT_KEY_FILE", str(tmp_path / "audit-keys.json"))
