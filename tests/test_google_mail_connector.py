import json
from unittest.mock import Mock

import pytest

from openmuse.connectors import ScopeDenied, ScopeGrants, connector_tools
from openmuse.google_mail_connector import GoogleMailConnector


def test_mail_connector_is_scoped_read_only_and_hides_token():
    token = "private-oauth-token"
    transport = Mock(return_value={"messages": [{"id": "m1", "threadId": "t1"}]})
    connector = GoogleMailConnector(lambda: token, transport=transport)
    grants = ScopeGrants()
    tools = {tool.name: tool for tool in connector_tools(connector, grants)}
    with pytest.raises(ScopeDenied):
        tools["google_mail:list_messages"].run()
    grants.grant(connector, {"mail.read"})
    output = tools["google_mail:search_messages"].run(query="from:alice", label_ids=["INBOX"], max_results=25)
    assert json.loads(output)[0]["id"] == "m1"
    url, headers = transport.call_args.args
    assert url.startswith("https://gmail.googleapis.com/gmail/v1/users/me/messages?")
    assert "q=from%3Aalice" in url and "labelIds=INBOX" in url and "maxResults=25" in url
    assert headers["Authorization"] == f"Bearer {token}"
    assert token not in json.dumps([tool.manifest() for tool in tools.values()])


def test_get_message_validates_provider_shape():
    connector = GoogleMailConnector(lambda: "token", transport=Mock(return_value={"id": "m1", "payload": {}}))
    assert json.loads(connector.invoke("get_message", {"message_id": "m1"}))["id"] == "m1"
    bad = GoogleMailConnector(lambda: "token", transport=Mock(return_value={"id": "m1"}))
    with pytest.raises(TypeError, match="invalid shape"):
        bad.invoke("get_message", {"message_id": "m1"})
    with pytest.raises(ValueError, match="invalid message_id"):
        connector.invoke("get_message", {"message_id": "../x"})


def test_mail_bounds_revocation_and_provider_shapes_fail_closed():
    connector = GoogleMailConnector(lambda: "token", transport=Mock(return_value={"messages": "bad"}))
    with pytest.raises(ValueError, match="between 1 and 250"):
        connector.invoke("list_messages", {"max_results": 251})
    with pytest.raises(TypeError, match="array"):
        connector.invoke("list_messages", {})
    oversized = GoogleMailConnector(lambda: "token", transport=Mock(return_value={"messages": [{}, {}]}))
    with pytest.raises(ValueError, match="exceeded"):
        oversized.invoke("list_messages", {"max_results": 1})
    with pytest.raises(ValueError, match="required"):
        connector.invoke("search_messages", {"query": ""})
    grants = ScopeGrants(); grants.grant(connector, {"mail.read"}); tool = connector_tools(connector, grants)[0]
    grants.revoke_and_delete(connector)
    with pytest.raises(ScopeDenied):
        tool.run()
    with pytest.raises(ValueError, match="revoked"):
        connector.invoke("list_messages", {})
