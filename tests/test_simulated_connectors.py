import json

import pytest

from openmuse.connectors import ScopeDenied, ScopeGrants, connector_tools
from openmuse.simulated_connectors import SimulatedCalendarConnector, SimulatedMailConnector


@pytest.mark.parametrize(
    ("connector_type", "scope", "records", "query", "match"),
    [
        (SimulatedMailConnector, "mail.read", [{"subject": "Launch", "body": "Ship it"}], "launch", "Launch"),
        (
            SimulatedCalendarConnector,
            "calendar.read",
            [{"summary": "Security review", "starts_at": "2026-09-20T10:00:00Z"}],
            "security",
            "Security review",
        ),
    ],
)
def test_credential_free_read_only_connector(tmp_path, connector_type, scope, records, query, match):
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps(records), encoding="utf-8")
    connector = connector_type(fixture)
    grants = ScopeGrants()
    tools = {tool.name: tool for tool in connector_tools(connector, grants)}

    with pytest.raises(ScopeDenied):
        tools[f"{connector.name}:list"].run()
    grants.grant(connector, {scope})
    assert match in tools[f"{connector.name}:list"].run()
    assert match in tools[f"{connector.name}:search"].run(query=query)
    assert tools[f"{connector.name}:search"].run(query="absent") == "[]"

    grants.revoke_and_delete(connector)
    assert not fixture.exists()
    with pytest.raises(ScopeDenied):
        tools[f"{connector.name}:list"].run()


def test_malformed_fixture_fails_closed(tmp_path):
    fixture = tmp_path / "fixture.json"
    fixture.write_text('{"not": "a list"}', encoding="utf-8")
    connector = SimulatedMailConnector(fixture)
    grants = ScopeGrants()
    grants.grant(connector, {"mail.read"})
    with pytest.raises(ValueError, match="array of objects"):
        connector_tools(connector, grants)[0].run()
