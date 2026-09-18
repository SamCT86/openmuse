import json
from unittest.mock import Mock

import pytest

from openmuse.connectors import ScopeDenied, ScopeGrants, connector_tools
from openmuse.google_calendar_connector import GoogleCalendarConnector


def test_production_calendar_connector_is_scoped_read_only_and_hides_token():
    token = "private-oauth-token"
    transport = Mock(return_value={"items": [{"id": "event-1", "summary": "Review"}]})
    connector = GoogleCalendarConnector(lambda: token, transport=transport)
    grants = ScopeGrants()
    tools = {tool.name: tool for tool in connector_tools(connector, grants)}

    with pytest.raises(ScopeDenied):
        tools["google_calendar:list_events"].run()
    grants.grant(connector, {"calendar.read"})
    output = tools["google_calendar:search_events"].run(query="review", time_min="2026-09-20T00:00:00Z", max_results=25)
    assert json.loads(output)[0]["id"] == "event-1"
    url, headers = transport.call_args.args
    assert url.startswith("https://www.googleapis.com/calendar/v3/calendars/primary/events?")
    assert "q=review" in url and "maxResults=25" in url
    assert headers["Authorization"] == f"Bearer {token}"
    assert token not in json.dumps([tool.manifest() for tool in tools.values()])


def test_calendar_revocation_fails_closed_and_clears_provider():
    connector = GoogleCalendarConnector(lambda: "token", transport=Mock(return_value={"items": []}))
    grants = ScopeGrants()
    grants.grant(connector, {"calendar.read"})
    tool = connector_tools(connector, grants)[0]
    grants.revoke_and_delete(connector)
    with pytest.raises(ScopeDenied):
        tool.run()
    with pytest.raises(ValueError, match="revoked"):
        connector.invoke("list_events", {})


def test_calendar_bounds_and_provider_shapes_fail_closed():
    connector = GoogleCalendarConnector(lambda: "token", transport=Mock(return_value={"items": "bad"}))
    with pytest.raises(ValueError, match="between 1 and 250"):
        connector.invoke("list_events", {"max_results": 251})
    with pytest.raises(TypeError, match="array"):
        connector.invoke("list_events", {})
    with pytest.raises(ValueError, match="unknown capability"):
        connector.invoke("delete_event", {})
