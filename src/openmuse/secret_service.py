"""Local process-separated secret service over an authenticated Unix socket."""
import hashlib
import hmac
import json
import os
import socket
from collections.abc import Callable
from pathlib import Path

from .secrets import SecretVault


class SecretService:
    def __init__(self,socket_path:Path,vault:SecretVault,auth_key:bytes): self.socket_path=socket_path; self.vault=vault; self.auth_key=auth_key
    def serve_once(self):
        self.socket_path.unlink(missing_ok=True)
        server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); server.bind(str(self.socket_path)); os.chmod(self.socket_path,0o600); server.listen(1)
        try:
            connection,_=server.accept()
            with connection:
                request=json.loads(connection.recv(65_536)); name=request["name"]; signature=request["signature"]
                expected=hmac.new(self.auth_key,name.encode(),hashlib.sha256).hexdigest()
                if not hmac.compare_digest(signature,expected): raise ValueError("invalid secret service signature")
                output=[]; self.vault.use(name,output.append); connection.sendall(json.dumps({"secret":output[0]}).encode())
        finally: server.close(); self.socket_path.unlink(missing_ok=True)

class SecretServiceClient:
    def __init__(self,socket_path:Path,auth_key:bytes): self.socket_path=socket_path; self.auth_key=auth_key
    def use(self,name:str,consumer:Callable[[str],None]):
        signature=hmac.new(self.auth_key,name.encode(),hashlib.sha256).hexdigest(); client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            client.connect(str(self.socket_path)); client.sendall(json.dumps({"name":name,"signature":signature}).encode()); response=json.loads(client.recv(65_536)); consumer(response["secret"])
        finally: client.close()
