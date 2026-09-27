import openmuse


def test_public_api_is_explicit_and_importable():
    assert openmuse.__all__
    for name in openmuse.__all__: assert getattr(openmuse,name) is not None


def test_extension_exports_match_documented_protocol():
    from openmuse import (
        Action,
        Agent,
        Capability,
        ManifestMixin,
        Policy,
        ReadOnlyConnector,
        Risk,
        ScopeGrants,
        Tool,
        WorkerTool,
        connector_tools,
    )

    assert Tool and ManifestMixin and Agent and Action and Policy and Risk and WorkerTool
    assert Capability and ReadOnlyConnector and ScopeGrants and connector_tools
