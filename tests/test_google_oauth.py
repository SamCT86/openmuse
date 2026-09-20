import json
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

import pytest

from openmuse.google_oauth import GoogleOAuthManager, _post_form
from openmuse.secrets import SecretVault

SCOPE = "https://www.googleapis.com/auth/calendar.readonly"


def manager(tmp_path, transport, now):
    return GoogleOAuthManager(
        "client", "client-secret", "http://127.0.0.1/callback", {SCOPE},
        SecretVault(tmp_path / "vault.json", b"k" * 32), transport=transport, clock=lambda: now[0]
    )


def test_authorization_exchange_persists_encrypted_and_refreshes(tmp_path):
    now = [1000.0]
    transport = Mock(side_effect=[
        {"access_token": "access-1", "refresh_token": "refresh-1", "expires_in": 120, "scope": SCOPE},
        {"access_token": "access-2", "expires_in": 3600, "scope": SCOPE},
    ])
    oauth = manager(tmp_path, transport, now)
    url = oauth.authorization_url("csrf-state", code_challenge="challenge")
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert "client_secret" not in url and "csrf-state" in url and "code_challenge=challenge" in url
    oauth.exchange_code("code", code_verifier="verifier")
    stored = (tmp_path / "vault.json").read_text()
    assert "access-1" not in stored and "refresh-1" not in stored
    assert oauth.access_token() == "access-1"
    now[0] = 1061
    assert oauth.access_token() == "access-2"
    _, headers, body = transport.call_args.args
    fields = parse_qs(body.decode())
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert fields["refresh_token"] == ["refresh-1"]
    assert "client-secret" in fields["client_secret"]


def test_oauth_scope_response_and_deletion_fail_closed(tmp_path):
    now = [0.0]
    oauth = manager(tmp_path, Mock(return_value={"access_token": "a", "refresh_token": "r", "expires_in": 1, "scope": "other"}), now)
    with pytest.raises(ValueError, match="scopes"):
        oauth.exchange_code("code")
    missing = manager(tmp_path, Mock(), now)
    with pytest.raises(ValueError, match="unavailable"):
        missing.access_token()


def test_oauth_requires_refresh_token_and_deletes_credentials(tmp_path):
    now = [0.0]
    transport = Mock(return_value={"access_token": "a", "refresh_token": "r", "expires_in": 3600, "scope": SCOPE})
    oauth = manager(tmp_path, transport, now)
    oauth.exchange_code("code")
    oauth.revoke_and_delete()
    endpoint, _, body = transport.call_args.args
    assert endpoint == oauth.revocation_endpoint
    assert parse_qs(body.decode()) == {"token": ["r"]}
    assert "google-oauth" not in json.loads((tmp_path / "vault.json").read_text())
    with pytest.raises(ValueError, match="unavailable"):
        oauth.access_token()


def test_failed_provider_revocation_preserves_local_credentials(tmp_path):
    now = [0.0]
    transport = Mock(return_value={"access_token": "a", "refresh_token": "r", "expires_in": 3600, "scope": SCOPE})
    oauth = manager(tmp_path, transport, now)
    oauth.exchange_code("code")
    transport.side_effect = ValueError("provider unavailable")
    with pytest.raises(ValueError, match="provider unavailable"):
        oauth.revoke_and_delete()
    transport.side_effect = None
    transport.return_value = {}
    assert oauth.access_token() == "a"


def test_post_form_accepts_empty_success_response():
    response = Mock(status=200)
    response.read.return_value = b""
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    with patch("openmuse.google_oauth.urlopen", return_value=response):
        assert _post_form("https://oauth2.googleapis.com/revoke", {}, b"token=x") == {}
