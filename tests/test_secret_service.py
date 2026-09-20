import threading
import time

from openmuse.secret_service import SecretService, SecretServiceClient
from openmuse.secrets import SecretVault


def test_process_boundary_protocol(tmp_path):
    vault=SecretVault(tmp_path/"vault.json",b"k"*32); vault.put("api","value")
    service=SecretService(tmp_path/"secrets.sock",vault,b"auth")
    thread=threading.Thread(target=service.serve_once); thread.start()
    for _ in range(100):
        if (tmp_path/"secrets.sock").exists(): break
        time.sleep(.01)
    output=[]; SecretServiceClient(tmp_path/"secrets.sock",b"auth").use("api",output.append); thread.join()
    assert output==["value"] and not (tmp_path/"secrets.sock").exists()
