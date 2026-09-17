from pathlib import Path


def test_generated_artifacts_are_ignored():
    ignored = Path(".gitignore").read_text().splitlines()
    assert ".coverage" in ignored
    assert "build/" in ignored
    assert "*.egg-info/" in ignored
