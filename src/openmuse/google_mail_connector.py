"""Production-capable, read-only Gmail API connector boundary."""

import json
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .connectors import Capability, ReadOnlyConnector
from .policy import Risk

MailTransport = Callable[[str, Mapping[str, str]], dict[str, Any]]
GOOGLE_MAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def _https_json(url: str, headers: Mapping[str, str]) -> dict[str, Any]:
    request = Request(url, headers=dict(headers))
    with urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError(f"Gmail API status {response.status}")
        body = response.read(500_001)
    if len(body) > 500_000:
        raise ValueError("Gmail API response too large")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise TypeError("Gmail API response must be an object")
    return payload


class GoogleMailConnector(ReadOnlyConnector):
    """List, search, and retrieve messages through Gmail's read-only API."""

    name = "google_mail"
    _origin = "https://gmail.googleapis.com/gmail/v1"

    def __init__(
        self,
        access_token: Callable[[], str],
        *,
        user_id: str = "me",
        transport: MailTransport = _https_json,
    ) -> None:
        self._access_token = access_token
        self._user_id = user_id
        self._transport = transport
        self._revoked = False

    def read_capabilities(self) -> list[Capability]:
        list_schema: dict[str, Any] = {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "label_ids": {"type": "array", "items": {"type": "string"}},
                "max_results": {"type": "integer"},
            },
            "additionalProperties": False,
        }
        get_schema = {
            "type": "object",
            "required": ["message_id"],
            "properties": {"message_id": {"type": "string"}},
            "additionalProperties": False,
        }
        return [
            Capability("list_messages", "mail.read", Risk.READ, list_schema),
            Capability("search_messages", "mail.read", Risk.READ, {**list_schema, "required": ["query"]}),
            Capability("get_message", "mail.read", Risk.READ, get_schema),
        ]

    def invoke(self, capability: str, arguments: Mapping[str, Any]) -> str:
        if self._revoked:
            raise ValueError("connector credentials revoked")
        if capability == "get_message":
            message_id = str(arguments["message_id"])
            if not message_id or "/" in message_id:
                raise ValueError("invalid message_id")
            url = f"{self._base()}/messages/{quote(message_id, safe='')}?format=full"
            payload = self._request(url)
            if not isinstance(payload.get("id"), str) or not isinstance(payload.get("payload"), dict):
                raise TypeError("Gmail message response has invalid shape")
            return json.dumps(payload, ensure_ascii=False, sort_keys=True)
        if capability not in {"list_messages", "search_messages"}:
            raise ValueError(f"unknown capability: {capability}")
        maximum = int(arguments.get("max_results", 50))
        if maximum < 1 or maximum > 250:
            raise ValueError("max_results must be between 1 and 250")
        params: list[tuple[str, str]] = [("maxResults", str(maximum)), ("includeSpamTrash", "false")]
        query = arguments.get("query")
        if capability == "search_messages" and (not isinstance(query, str) or not query.strip()):
            raise ValueError("search query is required")
        if query is not None:
            params.append(("q", str(query)))
        labels = arguments.get("label_ids", [])
        if not isinstance(labels, list) or any(not isinstance(label, str) or not label for label in labels):
            raise ValueError("label_ids must be an array of strings")
        params.extend(("labelIds", label) for label in labels)
        payload = self._request(f"{self._base()}/messages?{urlencode(params)}")
        messages = payload.get("messages", [])
        if not isinstance(messages, list) or any(not isinstance(item, dict) for item in messages):
            raise TypeError("Gmail messages must be an array of objects")
        if len(messages) > maximum:
            raise ValueError("Gmail response exceeded requested result bound")
        return json.dumps(messages, ensure_ascii=False, sort_keys=True)

    def delete_cached_data(self) -> None:
        self._revoked = True
        self._access_token = lambda: ""

    def _base(self) -> str:
        return f"{self._origin}/users/{quote(self._user_id, safe='')}"

    def _request(self, url: str) -> dict[str, Any]:
        token = self._access_token()
        if not token:
            raise ValueError("mail access token unavailable")
        return self._transport(url, {"Authorization": f"Bearer {token}", "Accept": "application/json"})
