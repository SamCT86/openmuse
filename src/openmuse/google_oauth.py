"""Managed Google OAuth authorization, refresh, and encrypted token storage."""

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import Lock
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .secrets import SecretVault

OAuthTransport = Callable[[str, Mapping[str, str], bytes], dict[str, Any]]


def _post_form(url: str, headers: Mapping[str, str], body: bytes) -> dict[str, Any]:
    request = Request(url, data=body, headers=dict(headers), method="POST")
    with urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError(f"OAuth endpoint status {response.status}")
        raw = response.read(100_001)
    if len(raw) > 100_000:
        raise ValueError("OAuth response too large")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise TypeError("OAuth response must be an object")
    return payload


@dataclass(frozen=True)
class OAuthTokens:
    access_token: str
    expires_at: float
    refresh_token: str
    scope: frozenset[str]


class GoogleOAuthManager:
    """Own Google tokens outside planner-visible connector arguments."""

    authorization_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
    token_endpoint = "https://oauth2.googleapis.com/token"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: set[str],
        vault: SecretVault,
        *,
        record_name: str = "google-oauth",
        transport: OAuthTransport = _post_form,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not client_id or not client_secret or not scopes:
            raise ValueError("client credentials and scopes are required")
        self.client_id = client_id
        self._client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = frozenset(scopes)
        self._vault = vault
        self._record_name = record_name
        self._transport = transport
        self._clock = clock
        self._refresh_lock = Lock()

    def authorization_url(self, state: str, *, code_challenge: str | None = None) -> str:
        if not state:
            raise ValueError("OAuth state is required")
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(sorted(self.scopes)),
            "access_type": "offline",
            "include_granted_scopes": "false",
            "prompt": "consent",
            "state": state,
        }
        if code_challenge:
            params.update({"code_challenge": code_challenge, "code_challenge_method": "S256"})
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    def exchange_code(self, code: str, *, code_verifier: str | None = None) -> None:
        fields = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self._client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        if code_verifier:
            fields["code_verifier"] = code_verifier
        payload = self._request(fields)
        self._save_payload(payload, require_refresh=True)

    def access_token(self) -> str:
        with self._refresh_lock:
            tokens = self._load()
            if tokens.expires_at > self._clock() + 60:
                return tokens.access_token
            payload = self._request(
                {
                    "client_id": self.client_id,
                    "client_secret": self._client_secret,
                    "refresh_token": tokens.refresh_token,
                    "grant_type": "refresh_token",
                }
            )
            self._save_payload(payload, refresh_token=tokens.refresh_token)
            return self._load().access_token

    def revoke_and_delete(self) -> None:
        self._vault.delete(self._record_name)

    def _request(self, fields: Mapping[str, str]) -> dict[str, Any]:
        return self._transport(
            self.token_endpoint,
            {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            urlencode(fields).encode("ascii"),
        )

    def _save_payload(
        self, payload: Mapping[str, Any], *, require_refresh: bool = False, refresh_token: str | None = None
    ) -> None:
        access = payload.get("access_token")
        refresh = payload.get("refresh_token", refresh_token)
        expires = payload.get("expires_in")
        granted = frozenset(str(payload.get("scope", "")).split())
        if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh:
            raise ValueError("OAuth response is missing tokens")
        if require_refresh and "refresh_token" not in payload:
            raise ValueError("OAuth consent did not return a refresh token")
        if not isinstance(expires, (int, float)) or isinstance(expires, bool) or expires <= 0:
            raise ValueError("OAuth response has invalid expiry")
        if granted and not self.scopes <= granted:
            raise ValueError("OAuth response did not grant all requested scopes")
        record = {
            "access_token": access,
            "refresh_token": refresh,
            "expires_at": self._clock() + float(expires),
            "scope": sorted(granted or self.scopes),
        }
        self._vault.put(self._record_name, json.dumps(record, sort_keys=True))

    def _load(self) -> OAuthTokens:
        value: list[str] = []
        try:
            self._vault.use(self._record_name, value.append)
        except KeyError as error:
            raise ValueError("Google OAuth credentials are unavailable") from error
        try:
            record = json.loads(value[0])
            tokens = OAuthTokens(
                str(record["access_token"]),
                float(record["expires_at"]),
                str(record["refresh_token"]),
                frozenset(str(scope) for scope in record["scope"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("stored Google OAuth credentials are invalid") from error
        if not tokens.access_token or not tokens.refresh_token or not self.scopes <= tokens.scope:
            raise ValueError("stored Google OAuth credentials do not cover configured scopes")
        return tokens
