import time
from pathlib import Path

import pytest

from openmuse.host_events import HostEventVerifier
from openmuse.tasks import TaskStore


def test_host_events_are_authenticated_and_single_use():
    verifier = HostEventVerifier(b"host-only-key")
    payload = {"action_id": "a1", "decision": "approve"}
    timestamp = int(time.time())
    signature = verifier.sign("evt-1", timestamp, payload)
    verifier.verify("evt-1", timestamp, payload, signature)
    with pytest.raises(ValueError, match="replayed"):
        verifier.verify("evt-1", timestamp, payload, signature)
    with pytest.raises(ValueError, match="signature"):
        verifier.verify("evt-2", timestamp, payload, "planner-controlled-text")


def test_task_stream_persists_side_chat(tmp_path: Path):
    path = tmp_path / "tasks.db"
    first = TaskStore(path)
    task = first.create("research")
    sequence = first.append_event(task.id, "progress", {"step": 1})
    first.post_message(task.id, "user", "check sources")
    second = TaskStore(path)
    events = second.events(task.id, after=sequence)
    assert events[0]["kind"] == "message"
    assert events[0]["data"] == {"author": "user", "body": "check sources"}


def test_endpoint_accepts_only_signed_decisions():
    import json

    verifier = HostEventVerifier(b"host-only-key")
    from openmuse.host_events import HostDecisionEndpoint

    endpoint = HostDecisionEndpoint(verifier)
    timestamp = int(time.time())
    payload = {"action_id": "a2", "decision": "deny"}
    headers = {
        "x-openmuse-event-id": "evt-2",
        "x-openmuse-timestamp": str(timestamp),
        "x-openmuse-signature": verifier.sign("evt-2", timestamp, payload),
    }
    assert endpoint.post(headers, json.dumps(payload).encode())["decision"] == "deny"


def test_task_thread_escapes_side_chat(tmp_path: Path):
    from openmuse.task_ui import render_task_thread

    store = TaskStore(tmp_path / "ui.db")
    task = store.create("<research>")
    store.post_message(task.id, "user", "<script>alert(1)</script>")
    page = render_task_thread(task, store.events(task.id))
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
