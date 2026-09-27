import os

import pytest

from openmuse.tools import ReadFile, WriteFile


def test_file_tools_block_symlinks_and_parent_escape(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "private.txt"
    outside.write_text("private")
    (workspace / "link").symlink_to(outside)
    (workspace / "dir").symlink_to(tmp_path, target_is_directory=True)
    for path in ("link", "dir/private.txt", "../private.txt", "/private.txt"):
        with pytest.raises((OSError, ValueError)):
            ReadFile(workspace).run(path)
        with pytest.raises((OSError, ValueError)):
            WriteFile(workspace).run(path, "overwrite")
    assert outside.read_text() == "private"


def test_parent_swapped_after_fd_open_stays_anchored(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    (workspace / "safe").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    real_open = os.open
    swapped = False

    def racing_open(path, flags, *args, **kwargs):
        nonlocal swapped
        fd = real_open(path, flags, *args, **kwargs)
        if path == "safe" and not swapped:
            swapped = True
            (workspace / "safe").rename(workspace / "moved")
            (workspace / "safe").symlink_to(outside, target_is_directory=True)
        return fd

    monkeypatch.setattr(os, "open", racing_open)
    WriteFile(workspace).run("safe/note.txt", "inside")
    assert (workspace / "moved/note.txt").read_text() == "inside"
    assert not (outside / "note.txt").exists()
