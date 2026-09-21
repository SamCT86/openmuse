import hashlib
import json

import pytest

from openmuse.audit_anchor import AuditCheckpoint
from openmuse.checkpoint_publisher import HTTPSPutPublisher, canonical_checkpoint


def checkpoint():
    return AuditCheckpoint(2, "a" * 64, 123, "b" * 64)


def test_checkpoint_encoding_is_canonical():
    body = canonical_checkpoint(checkpoint())
    assert body.endswith(b"\n")
    assert json.loads(body) == {"records": 2, "head_hash": "a" * 64, "created_at": 123, "signature": "b" * 64}
    assert body == canonical_checkpoint(checkpoint())


def test_publisher_validates_immutable_destination_before_network():
    with pytest.raises(ValueError, match="contain"):
        HTTPSPutPublisher("https://archive.example/checkpoint.json")
    publisher = HTTPSPutPublisher("https://archive.example/{key}")
    with pytest.raises(ValueError, match="unsafe"):
        publisher.publish(checkpoint(), "../overwrite")
    with pytest.raises(ValueError, match="HTTPS"):
        HTTPSPutPublisher("http://archive.example/{key}").publish(checkpoint(), "safe.json")


def test_publish_requires_success_and_returns_receipt(monkeypatch):
    seen = {}
    class Response:
        status = 201
        def read(self, _): return b""
        def getheader(self, name): return '"v1"' if name == "etag" else None
    class Connection:
        def __init__(self, host, port, timeout, context): seen.update(host=host, port=port, timeout=timeout)
        def request(self, method, target, body, headers): seen.update(method=method, target=target, body=body, headers=headers)
        def getresponse(self): return Response()
        def close(self): seen["closed"] = True
    monkeypatch.setattr("openmuse.checkpoint_publisher.http.client.HTTPSConnection", Connection)
    receipt = HTTPSPutPublisher("https://archive.example/anchors/{key}?signature=x").publish(checkpoint(), "2-a.json")
    assert seen["method"] == "PUT"
    assert seen["target"] == "/anchors/2-a.json?signature=x"
    assert seen["headers"]["If-None-Match"] == "*"
    assert receipt.sha256 == hashlib.sha256(seen["body"]).hexdigest()
    assert receipt.version == '"v1"'
    assert seen["closed"] is True
