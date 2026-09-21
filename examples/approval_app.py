"""Local reference UI for inspecting and deciding one exact action.

This is a localhost demo, not a production approval surface. Production hosts
must add TLS, authenticated identity, CSRF protection, and secure cookies.
"""

from __future__ import annotations

import argparse
import html
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from openmuse.approval_service import ApprovalRequest, ApprovalService
from openmuse.approval_ui import render_approval
from openmuse.models import Action

_STYLES = """
body { background:#0d1117; color:#e6edf3; font:16px/1.5 system-ui; margin:0; }
main { max-width:720px; margin:5vh auto; padding:32px; background:#161b22; border:1px solid #30363d; border-radius:12px; }
h1 { margin-top:0; } table { border-collapse:collapse; width:100%; margin:20px 0; }
th,td { border-bottom:1px solid #30363d; padding:10px; text-align:left; vertical-align:top; }
th { width:30%; color:#8b949e; } button { border:0; border-radius:6px; padding:10px 18px; margin-right:8px; font-weight:600; }
.approve { background:#238636; color:white; } .deny { background:#da3633; color:white; }
.notice { color:#8b949e; } code { overflow-wrap:anywhere; }
"""


def _page(body: str) -> bytes:
    return f"<!doctype html><html><head><meta charset='utf-8'><title>OpenMuse approval demo</title><style>{_STYLES}</style></head><body>{body}</body></html>".encode()


def build_handler(service: ApprovalService, request: ApprovalRequest, session: str, action: Action):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            detail = render_approval(action, request.identity, request.destination)
            controls = f"""<form method='post' action='/decide'>
<input type='hidden' name='request_id' value='{html.escape(request.id)}'>
<input type='hidden' name='session' value='{html.escape(session)}'>
<button class='approve' name='decision' value='approved'>Approve exact action</button>
<button class='deny' name='decision' value='denied'>Deny</button>
</form><p class='notice'>Local reference app only. The stored decision is persistent and single-use.</p>"""
            self._reply(HTTPStatus.OK, _page(detail.replace("</main>", controls + "</main>")))

        def do_POST(self):
            if self.path != "/decide":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                fields = parse_qs(self.rfile.read(length).decode(), strict_parsing=True)
                decided = service.decide(fields["request_id"][0], fields["session"][0], fields["decision"][0])
            except (KeyError, ValueError) as exc:
                self._reply(HTTPStatus.BAD_REQUEST, _page(f"<main><h1>Decision rejected</h1><p>{html.escape(str(exc))}</p></main>"))
                return
            body = f"<main><h1>Action {html.escape(decided.status)}</h1><p>The host stored this decision. A second decision with the same request will fail closed.</p><p><code>{html.escape(decided.action_json)}</code></p></main>"
            self._reply(HTTPStatus.OK, _page(body))

        def _reply(self, status: HTTPStatus, body: bytes):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost"])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", type=Path, default=Path(".openmuse/approval-demo.db"))
    args = parser.parse_args()
    args.db.parent.mkdir(parents=True, exist_ok=True)
    service = ApprovalService(args.db, secrets.token_bytes(32))
    action = Action("write_file", {"path": "welcome.txt", "content": "Hello from OpenMuse\n"})
    request, session = service.create(action, identity="local demo user", destination=str(Path.cwd() / "welcome.txt"))
    server = HTTPServer((args.host, args.port), build_handler(service, request, session, action))
    print(f"Open http://{args.host}:{server.server_port} to inspect the exact action (Ctrl-C to stop).")
    server.serve_forever()


if __name__ == "__main__":
    main()
