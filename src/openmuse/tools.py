"""Tool protocol plus workspace-safe file tools and SSRF-resistant fetch."""

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from .policy import Risk


class Tool(Protocol):
    name: str
    description: str
    risk: Risk

    def run(self, **kwargs: Any) -> str: ...
    def manifest(self) -> dict[str, Any]: ...


class ManifestMixin:
    def manifest(self):
        return {"name": self.name, "description": self.description, "risk": self.risk.value, "schema": self.schema}


def safe_path(root: Path, raw: str, write=False) -> Path:
    root = root.resolve()
    target = (root / raw).resolve(strict=False)
    if target != root and root not in target.parents:
        raise ValueError("path escapes workspace")
    cursor = target.parent if write else target
    while cursor != root:
        if cursor.is_symlink():
            raise ValueError("symlink paths are blocked")
        cursor = cursor.parent
    return target


@dataclass
class ReadFile(ManifestMixin):
    workspace: Path = field(default_factory=Path.cwd)
    name: str = "read_file"
    description: str = "Read UTF-8 text in workspace"
    risk: Risk = Risk.READ
    schema = None

    def __post_init__(self):
        self.schema = {"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}}

    def run(self, path: str, **_: Any) -> str:
        return safe_path(self.workspace, path).read_text(encoding="utf-8")


@dataclass
class WriteFile(ManifestMixin):
    workspace: Path = field(default_factory=Path.cwd)
    name: str = "write_file"
    description: str = "Write UTF-8 text in workspace"
    risk: Risk = Risk.WRITE
    schema = None

    def __post_init__(self):
        self.schema = {
            "type": "object",
            "required": ["path", "content"],
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
        }

    def run(self, path: str, content: str, **_: Any) -> str:
        target = safe_path(self.workspace, path, True)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise ValueError("symlink target blocked")
        target.write_text(content, encoding="utf-8")
        return f"wrote {target.relative_to(self.workspace.resolve())}"


def _public_addresses(host: str, port: int) -> list[str]:
    """Resolve once and reject the whole destination if any answer is non-public."""
    addresses = list(dict.fromkeys(str(info[4][0]) for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("private or special-use network blocked")
    return addresses


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a validated address instead of resolving the hostname again."""

    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Pin the TCP peer while retaining hostname certificate verification and SNI."""

    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        self._tls_context = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._tls_context)
        self._address = address

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._tls_context.wrap_socket(sock, server_hostname=self.host)


def _fetch_pinned(scheme: str, host: str, port: int, address: str, target: str) -> tuple[int, bytes]:
    connection_type = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
    connection = connection_type(host, port, address, timeout=15)
    try:
        connection.request("GET", target, headers={"Host": host, "User-Agent": "OpenMuse/0.2"})
        response = connection.getresponse()
        return response.status, response.read(200_001)
    finally:
        connection.close()


@dataclass
class FetchURL(ManifestMixin):
    name: str = "fetch_url"
    description: str = "Fetch a public HTTP(S) URL"
    risk: Risk = Risk.READ
    schema = None

    def __post_init__(self):
        self.schema = {"type": "object", "required": ["url"], "properties": {"url": {"type": "string"}}}

    def run(self, url: str, **_: Any) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("invalid public URL")
        if parsed.port not in {None, 80, 443}:
            raise ValueError("nonstandard port blocked")
        host = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = _public_addresses(host, port)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query

        last_error: OSError | None = None
        for address in addresses:
            try:
                status, body = _fetch_pinned(parsed.scheme, host, port, address, target)
            except OSError as exc:
                last_error = exc
                continue
            if 300 <= status < 400:
                raise ValueError("redirects are blocked")
            if status < 200 or status >= 300:
                raise ValueError(f"HTTP status {status}")
            return body[:200_000].decode("utf-8", errors="replace")
        raise OSError("all validated destination addresses failed") from last_error
