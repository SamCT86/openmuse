"""Native Windows conformance; parser tests also run on POSIX."""
import multiprocessing
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest

from openmuse.audit import AuditLog, verify_chain
from openmuse.tools import ReadFile, WriteFile
from openmuse.windows_fs import components


@pytest.mark.parametrize("raw", ["../x", "/x", "a//b", "a\\b", "C:/x", "x:ads", "CON", "nul.txt", "LPT1.log",
                                 "name.", "name ", "a/../b", "\\\\server\\file", "a\x00b", "COM¹.txt"])
def test_reject_windows_aliases(raw):
    with pytest.raises(ValueError):
        components(raw)


def test_unicode_components():
    assert components("notes/한글-😊.txt") == ["notes", "한글-😊.txt"]


native = pytest.mark.skipif(os.name != "nt", reason="requires native Windows")


@native
def test_native_read_write_and_no_truncate_hardlink(tmp_path):
    WriteFile(tmp_path).run("notes/한글.txt", "hello\nworld")
    assert ReadFile(tmp_path).run("notes/한글.txt") == "hello\nworld"
    outside = tmp_path.parent / (tmp_path.name + "-outside.txt")
    outside.write_text("private")
    os.link(outside, tmp_path / "hard")
    with pytest.raises(ValueError, match="hard-linked"):
        WriteFile(tmp_path).run("hard", "overwrite")
    assert outside.read_text() == "private"


@native
def test_native_junction_and_leaf_symlink_refused(tmp_path):
    workspace, outside = tmp_path / "workspace", tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("untouched")
    subprocess.run(["cmd", "/c", "mklink", "/J", str(workspace / "junction"), str(outside)], check=True,
                   capture_output=True)
    for tool in (ReadFile(workspace), WriteFile(workspace)):
        with pytest.raises((OSError, ValueError)):
            tool.run("junction/secret.txt", content="bad")
    assert (outside / "secret.txt").read_text() == "untouched"
    # Symlinks may require developer mode/admin; do not silently skip this gate.
    (workspace / "leaf").symlink_to(outside / "secret.txt")
    with pytest.raises((OSError, ValueError)):
        WriteFile(workspace).run("leaf", "bad")
    assert (outside / "secret.txt").read_text() == "untouched"


@native
def test_native_ancestor_is_pinned(tmp_path, monkeypatch):
    import openmuse.windows_fs as backend
    workspace, outside = tmp_path / "workspace", tmp_path / "outside"
    (workspace / "safe").mkdir(parents=True)
    outside.mkdir()
    original = backend._relative
    attempts = []

    def racing(parent, name, **kwargs):
        handle = original(parent, name, **kwargs)
        if name == "safe":
            try:
                (workspace / "safe").rename(workspace / "moved")
            except OSError:
                attempts.append("blocked")
            else:
                attempts.append("renamed")
                subprocess.run(["cmd", "/c", "mklink", "/J", str(workspace / "safe"), str(outside)], check=True,
                               capture_output=True)
        return handle

    monkeypatch.setattr(backend, "_relative", racing)
    WriteFile(workspace).run("safe/note.txt", "inside")
    assert attempts == ["blocked"]
    assert not (outside / "note.txt").exists()


def _append_process(path):
    from pathlib import Path
    for i in range(10):
        AuditLog(Path(path)).append({"event": str(i)})


@native
def test_native_audit_threads_and_processes(tmp_path):
    path = tmp_path / "audit.jsonl"
    # Create directory/file before racing so setup is not mistaken for append locking.
    AuditLog(path).append({"event": "start"})
    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda i: AuditLog(path).append({"event": str(i)}), range(32)))
    processes = [multiprocessing.get_context("spawn").Process(target=_append_process, args=(str(path),))
                 for _ in range(4)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(30)
        if process.is_alive():
            process.kill()
            process.join()
        assert process.exitcode == 0
    assert verify_chain(path) == (True, 73, None)


@native
def test_native_lock_timeout_and_failed_sync(tmp_path, monkeypatch):
    import openmuse.windows_fs as backend
    from openmuse.windows_fs import audit_stream
    path = tmp_path / "audit"
    with audit_stream(path), pytest.raises(TimeoutError), audit_stream(path, timeout=0.02):
        pass
    monkeypatch.setattr(backend, "flush_file", lambda _: False)
    with pytest.raises(OSError):
        AuditLog(path).append({"event": "not-reported-success"})


@native
def test_native_workers_refuse_unbounded_fallback(tmp_path):
    from openmuse.bounded_process import run_bounded
    from openmuse.isolated_worker import IsolatedWorker
    with pytest.raises(OSError, match="unsupported"):
        run_bounded(["cmd"], "", 100, 1)
    with pytest.raises(OSError, match="resource limits"):
        IsolatedWorker(tmp_path / "x.py", tmp_path).run({})


def _lock_until_killed(path, ready):
    import time
    from pathlib import Path

    from openmuse.windows_fs import audit_stream
    with audit_stream(Path(path)):
        ready.set()
        time.sleep(60)


@native
def test_native_crash_releases_lock_and_incomplete_tail_refuses(tmp_path):
    path = tmp_path / "audit"
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    process = context.Process(target=_lock_until_killed, args=(str(path), ready))
    process.start()
    try:
        assert ready.wait(15)
    finally:
        process.kill()
        process.join(10)
    AuditLog(path).append({"event": "after-crash"})
    assert verify_chain(path) == (True, 1, None)
    with path.open("ab") as stream:
        stream.write(b'{"partial":')
    before = path.read_bytes()
    with pytest.raises(ValueError, match="incomplete"):
        AuditLog(path).append({"event": "must-fail"})
    assert path.read_bytes() == before


@native
def test_native_leaf_pinned_and_reparse_workspace_refused(tmp_path, monkeypatch):
    import openmuse.windows_fs as backend
    workspace, outside = tmp_path / "workspace", tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "note").write_text("original")
    (outside / "secret").write_text("private")
    original = backend._relative
    attempted = []

    def racing(parent, name, **kwargs):
        handle = original(parent, name, **kwargs)
        if name == "note":
            with pytest.raises(OSError):
                (workspace / "note").unlink()
            attempted.append(True)
        return handle

    monkeypatch.setattr(backend, "_relative", racing)
    WriteFile(workspace).run("note", "updated")
    assert attempted and (workspace / "note").read_text() == "updated"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(tmp_path / "alias"), str(outside)], check=True,
                   capture_output=True)
    with pytest.raises((ValueError, OSError)):
        WriteFile(tmp_path / "alias").run("secret", "bad")
    assert (outside / "secret").read_text() == "private"


@native
def test_native_audit_failure_blocks_effect(tmp_path, monkeypatch):
    import openmuse.windows_fs as backend
    from openmuse.core import Agent
    from openmuse.models import Action
    from openmuse.policy import Policy
    monkeypatch.setattr(backend, "lock_file", lambda *args: False)
    monkeypatch.setattr(backend.ctypes, "get_last_error", lambda: 5)
    agent = Agent([WriteFile(tmp_path)], Policy(allow_writes=True), tmp_path / "audit")
    with pytest.raises(OSError):
        agent.execute(Action("write_file", {"path": "must-not-exist", "content": "bad"}))
    assert not (tmp_path / "must-not-exist").exists()


@native
def test_native_unsupported_volume_and_directory_type_refused(tmp_path, monkeypatch):
    import openmuse.windows_fs as backend
    with pytest.raises((ValueError, OSError)):
        ReadFile(tmp_path).run("missing")
    (tmp_path / "directory").mkdir()
    with pytest.raises((ValueError, OSError)):
        WriteFile(tmp_path).run("directory", "bad")
    monkeypatch.setattr(backend, "volume_info", lambda *args: False)
    with pytest.raises(OSError):
        ReadFile(tmp_path).run("directory")


@native
def test_native_hardlink_creation_blocked_while_write_handle_held(tmp_path, monkeypatch):
    import openmuse.windows_fs as backend
    original = backend._relative
    (tmp_path / "note").write_text("original")
    attempts = []

    def racing(parent, name, **kwargs):
        handle = original(parent, name, **kwargs)
        if name == "note":
            with pytest.raises(OSError):
                os.link(tmp_path / "note", tmp_path / "alias")
            attempts.append(True)
        return handle

    monkeypatch.setattr(backend, "_relative", racing)
    WriteFile(tmp_path).run("note", "inside")
    assert attempts and not (tmp_path / "alias").exists()
