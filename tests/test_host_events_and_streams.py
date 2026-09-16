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
