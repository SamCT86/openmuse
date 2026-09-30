import threading
import time

from openmuse.secret_service import SecretService, SecretServiceClient
from openmuse.secrets import SecretVault


def _use_when_ready(socket_path, auth_key, name, output, timeout=5.0):
    """Connect once the server is listening, not merely bound.

    The socket file exists after bind(); connecting before listen(1) runs is
    refused. A refused connection never reaches accept(), so retrying the
    real call is safe, while a polling probe would consume the single
    serve_once. The thread is a daemon so a failure cannot hang the suite.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            SecretServiceClient(socket_path, auth_key).use(name, output.append)
            return
        except (ConnectionRefusedError, FileNotFoundError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)


def test_process_boundary_protocol(tmp_path):
    vault=SecretVault(tmp_path/"vault.json",b"k"*32); vault.put("api","value")
    service=SecretService(tmp_path/"secrets.sock",vault,b"auth")
    thread=threading.Thread(target=service.serve_once, daemon=True); thread.start()
    output=[]; _use_when_ready(tmp_path/"secrets.sock",b"auth","api",output); thread.join()
    assert output==["value"] and not (tmp_path/"secrets.sock").exists()


def test_shared_key_client_can_request_any_name_not_isolation(tmp_path):
    vault = SecretVault(tmp_path / "vault.json", b"k" * 32)
    vault.put("unrelated", "plaintext-visible-to-client")
    service = SecretService(tmp_path / "secrets.sock", vault, b"shared")
    thread = threading.Thread(target=service.serve_once, daemon=True)
    thread.start()
    output = []
    _use_when_ready(tmp_path / "secrets.sock", b"shared", "unrelated", output)
    thread.join()
    assert output == ["plaintext-visible-to-client"]
