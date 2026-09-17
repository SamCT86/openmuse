"""Deterministic SSRF tests for resolution, address pinning, and redirects."""

import socket
from unittest.mock import Mock

import pytest

from openmuse import tools
from openmuse.tools import FetchURL


def addr(address: str, family: int = socket.AF_INET):
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))


def test_mixed_public_and_private_dns_answers_fail_closed(monkeypatch):
    monkeypatch.setattr(
        tools.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [addr("93.184.216.34"), addr("127.0.0.1")],
    )
    called = Mock()
    monkeypatch.setattr(tools, "_fetch_pinned", called)

    with pytest.raises(ValueError, match="private or special-use"):
        FetchURL().run("https://example.com/")
    called.assert_not_called()


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "169.254.169.254",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ],
)
def test_loopback_link_local_and_ipv4_mapped_ipv6_are_blocked(monkeypatch, address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *args, **kwargs: [addr(address, family)])
    with pytest.raises(ValueError, match="private or special-use"):
        FetchURL().run("https://example.com/")


def test_validated_address_is_pinned_for_request(monkeypatch):
    answers = iter([[addr("93.184.216.34")], [addr("127.0.0.1")]])
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *args, **kwargs: next(answers))
    request = Mock(return_value=(200, b"safe"))
    monkeypatch.setattr(tools, "_fetch_pinned", request)

    assert FetchURL().run("https://example.com/a?q=1") == "safe"
    request.assert_called_once_with("https", "example.com", 443, "93.184.216.34", "/a?q=1")
    # A rebinding resolver would now return loopback, but no second resolution occurs.
    assert next(answers)[0][4][0] == "127.0.0.1"


def test_redirect_to_private_destination_is_not_followed(monkeypatch):
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *args, **kwargs: [addr("93.184.216.34")])
    request = Mock(return_value=(302, b""))
    monkeypatch.setattr(tools, "_fetch_pinned", request)

    with pytest.raises(ValueError, match="redirects are blocked"):
        FetchURL().run("https://example.com/redirect")
    request.assert_called_once()


def test_response_is_bounded(monkeypatch):
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda *args, **kwargs: [addr("93.184.216.34")])
    monkeypatch.setattr(tools, "_fetch_pinned", Mock(return_value=(200, b"x" * 200_001)))
    assert len(FetchURL().run("https://example.com/large")) == 200_000
