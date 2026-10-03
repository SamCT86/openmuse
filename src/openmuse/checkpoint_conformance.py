"""Credential-free black-box conformance harness for HTTPS checkpoint publishing."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import ipaddress
import json
import os
import ssl
import tempfile
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .audit_anchor import AuditCheckpoint
from .checkpoint_publisher import HTTPSPutPublisher, canonical_checkpoint

_QUERY_SECRET = "conformance-query-secret"


class _ConformanceStore:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.events: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def record(self, event: dict[str, Any]) -> None:
        with self.lock:
            self.events.append(event)


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "OpenMuseCheckpointConformance/1"

    @property
    def store(self) -> _ConformanceStore:
        return self.server.store  # type: ignore[attr-defined,no-any-return]

    def log_message(self, format: str, *args: object) -> None:
        # Deliberately suppress BaseHTTPRequestHandler's raw request logging because
        # self.path may contain a presigned URL query secret.
        return

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        parsed = urlsplit(self.path)
        safe_path = parsed.path

        if safe_path.startswith("/redirect/"):
            self.store.record({"kind": "redirect", "path": safe_path})
            self.send_response(307)
            self.send_header("Location", "/objects/redirected.json")
            self.end_headers()
            return

        if safe_path.startswith("/failure/"):
            self.store.record({"kind": "failure", "path": safe_path})
            self.send_response(503)
            self.end_headers()
            return

        if not safe_path.startswith("/objects/"):
            self.store.record({"kind": "not_found", "path": safe_path})
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)
        digest = hashlib.sha256(body).hexdigest()
        claimed_digest = self.headers.get("Digest")
        if_none_match = self.headers.get("If-None-Match")

        self.store.record(
            {
                "kind": "put",
                "path": safe_path,
                "body_sha256": digest,
                "digest": claimed_digest,
                "if_none_match": if_none_match,
            }
        )

        if claimed_digest != f"sha-256={digest}" or if_none_match != "*":
            self.send_response(400)
            self.end_headers()
            return

        with self.store.lock:
            if safe_path in self.store.objects:
                self.send_response(412)
                self.end_headers()
                return
            self.store.objects[safe_path] = body

        self.send_response(201)
        self.send_header("ETag", f'"{digest}"')
        self.end_headers()


def _write_ephemeral_tls_material(directory: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenMuse checkpoint conformance")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path = directory / "conformance-cert.pem"
    key_path = directory / "conformance-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path


@contextmanager
def _local_https_server() -> Iterator[tuple[str, _ConformanceStore]]:
    store = _ConformanceStore()
    with tempfile.TemporaryDirectory(prefix="openmuse-checkpoint-conformance-") as tmp:
        tmp_path = Path(tmp)
        cert_path = _write_ephemeral_tls_material(tmp_path)
        key_path = tmp_path / "conformance-key.pem"

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        server.store = store  # type: ignore[attr-defined]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        previous_ca_file = os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"] = str(cert_path)
        try:
            host, port = server.server_address[:2]
            yield f"https://{host}:{port}", store
        finally:
            if previous_ca_file is None:
                os.environ.pop("SSL_CERT_FILE", None)
            else:
                os.environ["SSL_CERT_FILE"] = previous_ca_file
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def _expect_publication_failure(publisher: HTTPSPutPublisher, checkpoint: AuditCheckpoint, object_key: str, status: int) -> bool:
    try:
        publisher.publish(checkpoint, object_key)
    except RuntimeError as exc:
        return f"HTTP {status}" in str(exc)
    return False


def run_conformance() -> dict[str, Any]:
    checkpoint = AuditCheckpoint(2, "a" * 64, 123, "b" * 64)
    body = canonical_checkpoint(checkpoint)
    expected_digest = hashlib.sha256(body).hexdigest()

    with _local_https_server() as (base_url, store):
        publisher = HTTPSPutPublisher(f"{base_url}/objects/{{key}}?signature={_QUERY_SECRET}")
        receipt = publisher.publish(checkpoint, "checkpoint.json")

        overwrite_rejected = _expect_publication_failure(publisher, checkpoint, "checkpoint.json", 412)
        redirect_rejected = _expect_publication_failure(
            HTTPSPutPublisher(f"{base_url}/redirect/{{key}}?signature={_QUERY_SECRET}"),
            checkpoint,
            "checkpoint.json",
            307,
        )
        non_success_rejected = _expect_publication_failure(
            HTTPSPutPublisher(f"{base_url}/failure/{{key}}?signature={_QUERY_SECRET}"),
            checkpoint,
            "checkpoint.json",
            503,
        )

        stored_body = store.objects.get("/objects/checkpoint.json")
        serialized_events = json.dumps(store.events, sort_keys=True)
        query_secret_absent = _QUERY_SECRET not in serialized_events

        return {
            "canonical_body": stored_body == body,
            "digest_matches": receipt.sha256 == expected_digest,
            "overwrite_rejected": overwrite_rejected,
            "redirect_rejected": redirect_rejected,
            "non_success_rejected": non_success_rejected,
            "query_secret_absent_from_logs": query_secret_absent,
            "receipt": {
                "status": receipt.status,
                "sha256": receipt.sha256,
                "version": receipt.version,
            },
            "events": list(store.events),
        }


def _passed(report: dict[str, Any]) -> bool:
    required = (
        "canonical_body",
        "digest_matches",
        "overwrite_rejected",
        "redirect_rejected",
        "non_success_rejected",
        "query_secret_absent_from_logs",
    )
    return all(report.get(key) is True for key in required)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local HTTPS checkpoint publisher conformance checks.")
    parser.parse_args()
    report = run_conformance()
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if _passed(report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
