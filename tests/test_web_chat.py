import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

from openmuse.models import Action
from openmuse.web_chat import DemoPlanner, build_handler, build_session


class TokenForgingPlanner:
    """A hostile planner that tries to smuggle its own approval token."""

    def __init__(self):
        self.last_reply = None

    def plan(self, goal, tools, history):
        if history:
            return None
        return Action("write_file", {"path": "x.txt", "content": "pwned"}, approval_token="forged.token")


class ReplyPlanner:
    def __init__(self):
        self.last_reply = None

    def plan(self, goal, tools, history):
        self.last_reply = "<script>alert(1)</script>"


def test_read_runs_without_approval(tmp_path):
    (tmp_path / "note.txt").write_text("hello web")
    session = build_session(tmp_path, DemoPlanner())
    events = session.handle("c1", "read note.txt")["events"]
    assert events[0]["type"] == "tool"
    assert events[0]["status"] == "completed"
    assert events[0]["output"] == "hello web"
    assert events[-1]["type"] == "message"


def test_write_pauses_then_runs_once_after_approval(tmp_path):
    session = build_session(tmp_path, DemoPlanner())
    events = session.handle("c1", "write out/hi.txt: Hello <b>there</b>")["events"]
    approval = next(e for e in events if e["type"] == "approval")
    assert not (tmp_path / "out/hi.txt").exists()
    assert "&lt;b&gt;there&lt;/b&gt;" in approval["html"]
    assert "<b>" not in approval["html"]
    decided = session.decide(approval["request_id"], approval["session"], "approved")["events"]
    assert decided[1]["status"] == "completed"
    assert (tmp_path / "out/hi.txt").read_text() == "Hello <b>there</b>"
    with pytest.raises(ValueError):
        session.decide(approval["request_id"], approval["session"], "approved")
    audit = [json.loads(line) for line in (tmp_path / ".openmuse/web-chat-audit.jsonl").read_text().splitlines()]
    assert [r["status"] for r in audit] == ["blocked", "completed"]


def test_denied_write_never_runs(tmp_path):
    session = build_session(tmp_path, DemoPlanner())
    approval = next(e for e in session.handle("c1", "write a.txt: nope")["events"] if e["type"] == "approval")
    events = session.decide(approval["request_id"], approval["session"], "denied")["events"]
    assert events[0]["status"] == "denied"
    assert not (tmp_path / "a.txt").exists()


def test_wrong_session_is_rejected(tmp_path):
    session = build_session(tmp_path, DemoPlanner())
    approval = next(e for e in session.handle("c1", "write a.txt: nope")["events"] if e["type"] == "approval")
    with pytest.raises(ValueError):
        session.decide(approval["request_id"], "0" * 64, "approved")
    assert not (tmp_path / "a.txt").exists()


def test_planner_supplied_token_is_ignored(tmp_path):
    session = build_session(tmp_path, TokenForgingPlanner())
    events = session.handle("c1", "anything")["events"]
    assert any(e["type"] == "approval" for e in events)
    assert not (tmp_path / "x.txt").exists()


def test_help_and_planner_reply(tmp_path):
    assert "read README.md" in build_session(tmp_path, DemoPlanner()).handle("c1", "hi")["events"][-1]["text"]
    reply = build_session(tmp_path, ReplyPlanner()).handle("c1", "hi")["events"][-1]
    assert reply == {"type": "message", "role": "assistant", "text": "<script>alert(1)</script>"}


def test_path_escape_fails_closed(tmp_path):
    events = build_session(tmp_path, DemoPlanner()).handle("c1", "read ../../etc/passwd")["events"]
    assert events[0]["status"] == "failed"


def _exchange(server, url, path, data=None, headers=None):
    result = {}

    def client():
        req = urllib.request.Request(url + path, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as response:
                result.update(status=response.status, body=response.read().decode(), headers=response.headers)
        except urllib.error.HTTPError as exc:
            result.update(status=exc.code, body=exc.read().decode(), headers=exc.headers)

    thread = threading.Thread(target=client)
    thread.start()
    server.handle_request()
    thread.join()
    return result


def test_http_flow_requires_csrf_and_keeps_approval_boundary(tmp_path):
    session = build_session(tmp_path, DemoPlanner())
    server = HTTPServer(("127.0.0.1", 0), build_handler(session, "csrf-test", "offline demo planner"))
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        page = _exchange(server, url, "/")
        assert page["status"] == 200
        assert 'content="csrf-test"' in page["body"]
        assert "script-src 'self'" in page["headers"]["Content-Security-Policy"]
        assert _exchange(server, url, "/app.js")["status"] == 200
        body = json.dumps({"conversation_id": "c1", "text": "write w.txt: hi"}).encode()
        assert _exchange(server, url, "/api/chat", body, {"Content-Type": "application/json"})["status"] == 403
        good = {"Content-Type": "application/json", "X-OpenMuse-CSRF": "csrf-test"}
        chat = _exchange(server, url, "/api/chat", body, good)
        assert chat["status"] == 200
        approval = next(e for e in json.loads(chat["body"])["events"] if e["type"] == "approval")
        assert not (tmp_path / "w.txt").exists()
        decision = json.dumps({"request_id": approval["request_id"], "session": approval["session"], "decision": "approved"})
        decided = _exchange(server, url, "/api/approvals", decision.encode(), good)
        assert decided["status"] == 200
        assert (tmp_path / "w.txt").read_text() == "hi"
        replay = _exchange(server, url, "/api/approvals", decision.encode(), good)
        assert replay["status"] == 400
        bad = _exchange(server, url, "/api/chat", b"[]", good)
        assert bad["status"] == 400
        assert _exchange(server, url, "/nope")["status"] == 404
    finally:
        server.server_close()
