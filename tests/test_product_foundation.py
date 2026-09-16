from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from openmuse.approval_ui import render_approval
from openmuse.browser_worker import BrowserJob, BrowserWorkerPolicy
from openmuse.channels import WebChannel
from openmuse.models import Action
from openmuse.secrets import SecretVault
from openmuse.tasks import TaskStore


def test_channel_round_trip():
    channel = WebChannel()
    channel.submit("c", "u", "hello")
    assert channel.receive().text == "hello"
    assert channel.send("c", "done") == "web:1"


def test_task_restart_and_cancel(tmp_path: Path):
    path = tmp_path / "tasks.db"
    first = TaskStore(path)
    task = first.create("demo", 2)
    first.checkpoint(task.id, 1, {"ok": True})
    second = TaskStore(path)
    assert second.get(task.id).checkpoint == {"ok": True}
    assert second.cancel(task.id).status == "canceled"


def test_envelope_vault_hides_plaintext(tmp_path: Path):
    vault = SecretVault(tmp_path / "vault.json", AESGCM.generate_key(bit_length=256))
    vault.put("api", "super-secret")
    assert "super-secret" not in vault.path.read_text()
    found = []
    vault.use("api", found.append)
    assert found == ["super-secret"]


def test_browser_policy_and_approval_html():
    policy = BrowserWorkerPolicy()
    policy.validate(BrowserJob("https://example.com", "open", frozenset({"example.com"})))
    with pytest.raises(ValueError):
        policy.validate(BrowserJob("https://example.com", "submit", frozenset({"example.com"})))
    page = render_approval(Action("send", {"body": "<hello>"}), "me", "sam")
    assert "&lt;hello&gt;" in page
