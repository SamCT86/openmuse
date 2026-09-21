from pathlib import Path


def test_conformance_script_uses_documented_boundary():
    source=(Path(__file__).parents[1]/"scripts/container_conformance.py").read_text()
    for flag in ("--network=none","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges","--pids-limit=64","--memory=128m","--user=65532:65532"):
        assert flag in source
    assert "@sha256:" in source
    assert "--volume" not in source and " -v " not in source
