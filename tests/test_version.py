from importlib.metadata import version

import openmuse


def test_module_version_matches_distribution():
    assert openmuse.__version__ == version("openmuse-agent")
