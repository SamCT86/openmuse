import importlib.util
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import HTTPServer
from pathlib import Path

from openmuse.approval_service import ApprovalService
from openmuse.models import Action

spec = importlib.util.spec_from_file_location("approval_app", Path(__file__).parents[1] / "examples" / "approval_app.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(module)


def test_reference_app_renders_escaped_action_and_decides_once(tmp_path):
    service = ApprovalService(tmp_path / "approval.db", b"k")
    action = Action("send", {"body": "<script>alert(1)</script>", "to": "sam"})
    request, session = service.create(action, "local user", "sam")
    server = HTTPServer(("127.0.0.1", 0), module.build_handler(service, request, session, action))
    url = f"http://127.0.0.1:{server.server_port}"

    def exchange(path="", data=None):
        result = {}
        def client():
            try:
                response = urllib.request.urlopen(url + path, data=data)
                result["status"] = response.status
                result["body"] = response.read().decode()
            except urllib.error.HTTPError as exc:
                result["status"] = exc.code
                result["body"] = exc.read().decode()
        thread = threading.Thread(target=client)
        thread.start()
        server.handle_request()
        thread.join()
        return result

    try:
        page = exchange()["body"]
        assert "Approve exact action" in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
        assert "<script>alert(1)</script>" not in page
        data = urllib.parse.urlencode({"request_id": request.id, "session": session, "decision": "approved"}).encode()
        first = exchange("/decide", data)
        assert first["status"] == 200
        assert "Action approved" in first["body"]
        second = exchange("/decide", data)
        assert second["status"] == 400
        assert "already decided" in second["body"]
    finally:
        server.server_close()
