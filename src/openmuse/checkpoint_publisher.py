"""Publish canonical signed checkpoints to an independent immutable HTTPS target."""

from __future__ import annotations

import hashlib
import http.client
import json
import ssl
from dataclasses import asdict, dataclass
from typing import Protocol
from urllib.parse import urlsplit

from .audit_anchor import AuditCheckpoint


@dataclass(frozen=True)
class PublicationReceipt:
    url: str
    sha256: str
    status: int
    version: str | None = None


class CheckpointPublisher(Protocol):
    def publish(self, checkpoint: AuditCheckpoint, object_key: str) -> PublicationReceipt: ...


def canonical_checkpoint(checkpoint: AuditCheckpoint) -> bytes:
    return (json.dumps(asdict(checkpoint), sort_keys=True, separators=(",", ":")) + "\n").encode()


class HTTPSPutPublisher:
    """PUT a checkpoint to a pre-authorized immutable HTTPS destination.

    ``url_template`` must contain ``{key}``; callers should use a unique key.
    The server must reject overwrite (for example, S3 Object Lock plus a
    presigned PUT). Redirects are never followed.
    """

    def __init__(self, url_template: str, timeout: float = 15) -> None:
        if "{key}" not in url_template:
            raise ValueError("url template must contain {key}")
        self.url_template = url_template
        self.timeout = timeout

    def publish(self, checkpoint: AuditCheckpoint, object_key: str) -> PublicationReceipt:
        if not object_key or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for char in object_key):
            raise ValueError("object key contains unsafe characters")
        url = self.url_template.replace("{key}", object_key)
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("publisher requires a credential-free HTTPS URL")
        body = canonical_checkpoint(checkpoint)
        digest = hashlib.sha256(body).hexdigest()
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=self.timeout, context=ssl.create_default_context())
        try:
            connection.request("PUT", target, body=body, headers={"Content-Type": "application/json", "Content-Length": str(len(body)), "Digest": f"sha-256={digest}", "If-None-Match": "*"})
            response = connection.getresponse()
            response.read(64_001)
        finally:
            connection.close()
        if response.status not in {200, 201, 204}:
            raise RuntimeError(f"checkpoint publication failed with HTTP {response.status}")
        version = response.getheader("x-amz-version-id") or response.getheader("etag")
        return PublicationReceipt(url, digest, response.status, version)
