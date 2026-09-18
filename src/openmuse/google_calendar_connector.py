"""Production-capable, read-only Google Calendar connector boundary."""

import json
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .connectors import Capability, ReadOnlyConnector
from .policy import Risk

CalendarTransport = Callable[[str, Mapping[str, str]], dict[str, Any]]
GOOGLE_CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"


def _https_json(url: str, headers: Mapping[str, str]) -> dict[str, Any]:
    request = Request(url, headers=dict(headers))
    with urlopen(request, timeout=15) as response:
        if response.status != 200:
            raise ValueError(f"calendar API status {response.status}")
        body = response.read(200_001)
    if len(body) > 200_000:
        raise ValueError("calendar API response too large")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise TypeError("calendar API response must be an object")
    return payload


class GoogleCalendarConnector(ReadOnlyConnector):
    """List/search events without exposing OAuth tokens to planner arguments.

    The host owns `access_token`, which is called only at invocation time. The
    connector is deliberately read-only and talks only to Calendar API v3.
    OAuth login/refresh and token persistence remain host responsibilities.
    """

    name = "google_calendar"
    _origin = "https://www.googleapis.com/calendar/v3"

    def __init__(
        self,
        access_token: Callable[[], str],
        calendar_id: str = "primary",
        transport: CalendarTransport = _https_json,
    ) -> None:
        self._access_token = access_token
        self._calendar_id = calendar_id
        self._transport = transport
        self._revoked = False

    def read_capabilities(self) -> list[Capability]:
        common: dict[str, Any] = {
            "type": "object",
            "properties": {
                "time_min": {"type": "string"},
                "time_max": {"type": "string"},
                "max_results": {"type": "integer"},
            },
            "additionalProperties": False,
        }
        search = {
            "type": "object",
            "required": ["query"],
            "properties": {
                "time_min": {"type": "string"},
                "time_max": {"type": "string"},
                "max_results": {"type": "integer"},
                "query": {"type": "string"},
            },
            "additionalProperties": False,
        }
        return [
            Capability("list_events", "calendar.read", Risk.READ, common),
            Capability("search_events", "calendar.read", Risk.READ, search),
        ]

    def invoke(self, capability: str, arguments: Mapping[str, Any]) -> str:
        if self._revoked:
            raise ValueError("connector credentials revoked")
        if capability not in {"list_events", "search_events"}:
            raise ValueError(f"unknown capability: {capability}")
        maximum = int(arguments.get("max_results", 50))
        if maximum < 1 or maximum > 250:
            raise ValueError("max_results must be between 1 and 250")
        params: dict[str, str] = {
            "singleEvents": "true",
            "orderBy": "startTime",
            "maxResults": str(maximum),
        }
        for source, target in (("time_min", "timeMin"), ("time_max", "timeMax")):
            if source in arguments:
                params[target] = str(arguments[source])
        if capability == "search_events":
            params["q"] = str(arguments["query"])
        calendar_id = self._calendar_id.replace("/", "%2F")
        url = f"{self._origin}/calendars/{calendar_id}/events?{urlencode(params)}"
        token = self._access_token()
        if not token:
            raise ValueError("calendar access token unavailable")
        payload = self._transport(url, {"Authorization": f"Bearer {token}", "Accept": "application/json"})
        items = payload.get("items", [])
        if not isinstance(items, list):
            raise TypeError("calendar items must be an array")
        if len(items) > maximum:
            raise ValueError("calendar response exceeded requested result bound")
        return json.dumps(items, ensure_ascii=False, sort_keys=True)

    def delete_cached_data(self) -> None:
        """Revoke this connector instance; host token deletion is separate."""
        self._revoked = True
        self._access_token = lambda: ""
