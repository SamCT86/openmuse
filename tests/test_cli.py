import json

import pytest

from openmuse.cli import main


def test_cli_reads_workspace_file(tmp_path, monkeypatch, capsys):
    (tmp_path / "hello.txt").write_text("hello")
    monkeypatch.setattr("sys.argv", ["openmuse", "read_file", "--workspace", str(tmp_path), "--args", json.dumps({"path": "hello.txt"})])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == "hello"


def test_cli_blocks_write_without_flag(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["openmuse", "write_file", "--workspace", str(tmp_path), "--args", json.dumps({"path": "blocked.txt", "content": "no"})])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 2
    assert not (tmp_path / "blocked.txt").exists()
