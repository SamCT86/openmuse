"""Local web chat: talk to an OpenMuse agent from the browser.

Every message goes through the same host boundary as the CLI and demo:
planner -> typed action -> schema validation -> policy -> tool -> audit.
Sensitive actions pause as an approval card rendered by the host from the
stored action, never from planner text. Approving it issues a one-time,
action-bound token and runs that exact action once.

This is a localhost reference app, not a hosted service. Production hosts
must add TLS, authenticated identity, and secure session handling.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass, field, replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Protocol

from .approval_service import ApprovalService
from .approval_ui import render_approval
from .approvals import ApprovalAuthority
from .channels.web import WebChannel
from .core import Agent
from .models import Action, ActionStatus, ToolResult
from .policy import Policy
from .providers import OpenAICompatiblePlanner
from .providers.openai_compatible import ProviderError
from .tools import FetchURL, ReadFile, WriteFile
from .web_chat_assets import APP_CSS, APP_JS, INDEX_HTML

MAX_BODY_BYTES = 16_384
MAX_TEXT_CHARS = 4_000
MAX_OUTPUT_CHARS = 2_000
HISTORY_TURNS = 12
HELP = (
    "I'm the offline demo planner. Try:\n"
    "  read README.md\n"
    "  write notes/hello.txt: Hello from the web chat\n"
    "  fetch https://example.com\n"
    "Reads run right away. Writes stop for your approval first.\n"
    "Set OPENAI_API_KEY to chat with a real model instead."
)


class ChatPlanner(Protocol):
    last_reply: str | None

    def plan(self, goal: str, tools: list[dict], history: list[ToolResult]) -> Action | None: ...


class DemoPlanner:
    """Deterministic, credential-free planner for trying the chat offline."""

    _READ = re.compile(r"^(?:read|cat|open)\s+(\S+)\s*$", re.IGNORECASE)
    _WRITE = re.compile(r"^(?:write|save)\s+(\S+?)\s*:\s*(.*)$", re.IGNORECASE | re.DOTALL)
    _FETCH = re.compile(r"^(?:fetch|get)\s+(https?://\S+)\s*$", re.IGNORECASE)

    def __init__(self) -> None:
        self.last_reply: str | None = None

    def plan(self, goal: str, tools: list[dict], history: list[ToolResult]) -> Action | None:
        self.last_reply = None
        if history:
            return None
        text = goal.rsplit("\nuser: ", 1)[-1].removeprefix("user: ").strip()
        if m := self._READ.match(text):
            return Action("read_file", {"path": m.group(1)})
        if m := self._WRITE.match(text):
            return Action("write_file", {"path": m.group(1), "content": m.group(2)})
        if m := self._FETCH.match(text):
            return Action("fetch_url", {"url": m.group(1)})
        self.last_reply = HELP
        return None


@dataclass
class _Pending:
    action: Action
    conversation_id: str
    session: str


@dataclass
class ChatSession:
    """Host-side chat state: conversations, pending approvals, and execution."""

    agent: Agent
    planner: ChatPlanner
    approvals: ApprovalService
    authority: ApprovalAuthority
    workspace: Path
    identity: str = "local web chat user"
    max_steps: int = 6
    channel: WebChannel = field(default_factory=WebChannel)
    transcripts: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    pending: dict[str, _Pending] = field(default_factory=dict)

    def handle(self, conversation_id: str, text: str) -> dict[str, Any]:
        self.channel.submit(conversation_id, "local-user", text)
        incoming = self.channel.receive()
        assert incoming is not None
        transcript = self.transcripts.setdefault(conversation_id, [])
        transcript.append(("user", incoming.text))
        goal = "\n".join(f"{role}: {body}" for role, body in transcript[-HISTORY_TURNS:])
        history: list[ToolResult] = []
        events: list[dict[str, Any]] = []
        for _ in range(self.max_steps):
            proposed = self.planner.plan(goal, self.agent.registry.catalogue(), history)
            if proposed is None:
                break
            # Planner output never carries authority: drop any token and use a fresh id.
            action = Action(proposed.tool, dict(proposed.arguments))
            result = self.agent.execute(action)
            history.append(result)
            if result.status is ActionStatus.BLOCKED and result.error_code == "approval_required":
                events.append(self._request_approval(conversation_id, action))
                self._say(conversation_id, "Waiting for your approval before running this action.")
                return {"events": events + [self._message("Waiting for your approval before running this action.")]}
            events.append(self._result_event(action, result))
            if result.status is not ActionStatus.COMPLETED:
                break
        reply = self.planner.last_reply or ("Done." if history else HELP)
        self._say(conversation_id, reply)
        events.append(self._message(reply))
        return {"events": events}

    def decide(self, request_id: str, session: str, decision: str) -> dict[str, Any]:
        pending = self.pending.get(request_id)
        if pending is None or not hmac.compare_digest(session, pending.session):
            raise ValueError("unknown approval")
        decided = self.approvals.decide(request_id, session, decision)
        del self.pending[request_id]
        stored = json.loads(decided.action_json)
        if stored != {"tool": pending.action.tool, "arguments": dict(pending.action.arguments)}:
            raise ValueError("stored action does not match pending action")
        if decided.status != "approved":
            reply = f"Denied. {pending.action.tool} did not run."
            self._say(pending.conversation_id, reply)
            return {"events": [{"type": "decision", "request_id": request_id, "status": "denied"}, self._message(reply)]}
        token = self.authority.issue(pending.action)
        result = self.agent.execute(replace(pending.action, approval_token=token))
        reply = "Approved and ran once." if result.status is ActionStatus.COMPLETED else "Approved, but the action failed."
        self._say(pending.conversation_id, reply)
        return {
            "events": [
                {"type": "decision", "request_id": request_id, "status": "approved"},
                self._result_event(pending.action, result),
                self._message(reply),
            ]
        }

    def _request_approval(self, conversation_id: str, action: Action) -> dict[str, Any]:
        destination = self._destination(action)
        request, session = self.approvals.create(action, self.identity, destination)
        self.pending[request.id] = _Pending(action, conversation_id, session)
        return {
            "type": "approval",
            "request_id": request.id,
            "session": session,
            "expires_at": request.expires_at,
            "html": render_approval(action, self.identity, destination),
        }

    def _destination(self, action: Action) -> str:
        path = action.arguments.get("path")
        return str(self.workspace / path) if isinstance(path, str) else action.tool

    def _result_event(self, action: Action, result: ToolResult) -> dict[str, Any]:
        output = result.output
        if len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + f"\n... ({len(result.output) - MAX_OUTPUT_CHARS} more characters)"
        return {
            "type": "tool",
            "tool": action.tool,
            "arguments": dict(action.arguments),
            "status": result.status.value,
            "error_code": result.error_code,
            "output": output,
        }

    def _say(self, conversation_id: str, text: str) -> None:
        self.channel.send(conversation_id, text)
        self.transcripts.setdefault(conversation_id, []).append(("assistant", text))

    @staticmethod
    def _message(text: str) -> dict[str, Any]:
        return {"type": "message", "role": "assistant", "text": text}


def build_session(workspace: Path, planner: ChatPlanner, state_dir: Path | None = None) -> ChatSession:
    workspace = workspace.resolve()
    state = state_dir or workspace / ".openmuse"
    state.mkdir(parents=True, exist_ok=True)
    authority = ApprovalAuthority(secrets.token_bytes(32))
    agent = Agent(
        [ReadFile(workspace), WriteFile(workspace), FetchURL()],
        Policy(allow_writes=False, approvals=authority),
        state / "web-chat-audit.jsonl",
    )
    service = ApprovalService(state / "web-chat-approvals.db", secrets.token_bytes(32))
    return ChatSession(agent, planner, service, authority, workspace)


def build_handler(session: ChatSession, csrf_token: str, planner_label: str):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                page = INDEX_HTML.replace("{{csrf}}", csrf_token).replace("{{planner}}", planner_label)
                self._reply(HTTPStatus.OK, page.encode(), "text/html; charset=utf-8")
            elif self.path == "/app.js":
                self._reply(HTTPStatus.OK, APP_JS.encode(), "text/javascript; charset=utf-8")
            elif self.path == "/app.css":
                self._reply(HTTPStatus.OK, APP_CSS.encode(), "text/css; charset=utf-8")
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self):
            if self.path not in {"/api/chat", "/api/approvals"}:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if not hmac.compare_digest(self.headers.get("X-OpenMuse-CSRF", ""), csrf_token):
                self._json(HTTPStatus.FORBIDDEN, {"error": "missing or invalid CSRF token"})
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "expected application/json"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_BODY_BYTES:
                    raise ValueError("request body size out of range")
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise TypeError("request body must be an object")
                if self.path == "/api/chat":
                    text = body.get("text")
                    conversation = body.get("conversation_id", "default")
                    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CHARS:
                        raise ValueError(f"text must be 1-{MAX_TEXT_CHARS} characters")
                    if not isinstance(conversation, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", conversation):
                        raise ValueError("invalid conversation_id")
                    payload = session.handle(conversation, text.strip())
                else:
                    fields = [body.get("request_id"), body.get("session"), body.get("decision")]
                    if not all(isinstance(v, str) for v in fields):
                        raise ValueError("request_id, session and decision are required")
                    payload = session.decide(*fields)
            except (ValueError, TypeError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            except ProviderError as exc:
                self._json(HTTPStatus.BAD_GATEWAY, {"error": f"planner unavailable: {exc}"})
                return
            self._json(HTTPStatus.OK, payload)

        def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            self._reply(status, json.dumps(payload).encode(), "application/json")

        def _reply(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return Handler


def _planner(choice: str, model: str, base_url: str) -> tuple[ChatPlanner, str]:
    if choice == "openai" or (choice == "auto" and os.environ.get("OPENAI_API_KEY")):
        return OpenAICompatiblePlanner(base_url=base_url, model=model), f"model: {model}"
    return DemoPlanner(), "offline demo planner"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="openmuse-chat", description="Chat with an OpenMuse agent in your browser.")
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost"])
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="files the agent may read and write")
    parser.add_argument("--planner", choices=["auto", "demo", "openai"], default="auto",
                        help="auto uses a model when OPENAI_API_KEY is set, otherwise the offline demo planner")
    parser.add_argument("--model", default="gpt-4.1-mini")
    parser.add_argument("--base-url", default="https://api.openai.com/v1")
    args = parser.parse_args(argv)
    planner, label = _planner(args.planner, args.model, args.base_url)
    session = build_session(args.workspace, planner)
    server = HTTPServer((args.host, args.port), build_handler(session, secrets.token_urlsafe(32), label))
    print(f"OpenMuse web chat ({label}) on http://{args.host}:{server.server_port}  workspace: {session.workspace}")
    print("Writes pause for approval in the browser. Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
