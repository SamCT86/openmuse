"""Credential-free mail and calendar connectors for local development."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .connectors import Capability, ReadOnlyConnector
from .policy import Risk


class JSONFixtureConnector(ReadOnlyConnector):
    """Read-only connector backed by a local JSON array, never live credentials."""

    def __init__(self, fixture: Path, name: str, item_scope: str) -> None:
        self.fixture = fixture
        self.name = name
        self.item_scope = item_scope

    def read_capabilities(self) -> list[Capability]:
        return [
            Capability(
                "list",
                self.item_scope,
                Risk.READ,
                {"type": "object", "properties": {}, "additionalProperties": False},
            ),
            Capability(
                "search",
                self.item_scope,
                Risk.READ,
                {
                    "type": "object",
                    "required": ["query"],
                    "properties": {"query": {"type": "string"}},
                    "additionalProperties": False,
                },
            ),
        ]

    def invoke(self, capability: str, arguments: Mapping[str, Any]) -> str:
        records = self._load()
        if capability == "search":
            query = str(arguments["query"]).casefold()
            records = [record for record in records if query in json.dumps(record, ensure_ascii=False).casefold()]
        elif capability != "list":
            raise ValueError(f"unknown capability: {capability}")
        return json.dumps(records, ensure_ascii=False, sort_keys=True)

    def delete_cached_data(self) -> None:
        self.fixture.unlink(missing_ok=True)

    def _load(self) -> list[dict[str, Any]]:
        if not self.fixture.exists():
            return []
        records = json.loads(self.fixture.read_text(encoding="utf-8"))
        if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
            raise ValueError("fixture must be a JSON array of objects")
        return records


class SimulatedMailConnector(JSONFixtureConnector):
    def __init__(self, fixture: Path) -> None:
        super().__init__(fixture, "mail", "mail.read")


class SimulatedCalendarConnector(JSONFixtureConnector):
    def __init__(self, fixture: Path) -> None:
        super().__init__(fixture, "calendar", "calendar.read")
