from pathlib import Path

import pytest

from openmuse.isolated_worker import IsolatedWorker, WorkerLimits


def script(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "worker.py"
    path.write_text(source)
    return path


def test_worker_has_separate_pid_workspace_and_scrubbed_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENMUSE_SECRET", "must-not-cross")
    entrypoint = script(
        tmp_path,
        "import json, os, sys\n"
        "request=json.load(sys.stdin)\n"
        "print(json.dumps({'pid':os.getpid(),'cwd':os.getcwd(),'secret':os.getenv('OPENMUSE_SECRET'),'x':request['x']}))\n",
    )
    workspace = tmp_path / "sandbox"
    result = IsolatedWorker(entrypoint, workspace).run({"x": 3})
    assert result.output["x"] == 3
    assert result.output["cwd"] == str(workspace)
    assert result.output["secret"] is None


def test_worker_timeout_is_enforced(tmp_path):
    entrypoint = script(tmp_path, "import time\ntime.sleep(2)\n")
    with pytest.raises(TimeoutError, match="timed out"):
        IsolatedWorker(entrypoint, tmp_path / "sandbox", WorkerLimits(timeout_seconds=0.05)).run({})


def test_worker_output_and_response_shape_fail_closed(tmp_path):
    huge = script(tmp_path, "print('x'*1000)\n")
    with pytest.raises(ValueError, match="output limit"):
        IsolatedWorker(huge, tmp_path / "sandbox", WorkerLimits(output_bytes=100)).run({})
    scalar = script(tmp_path, "print('[]')\n")
    with pytest.raises(TypeError, match="JSON object"):
        IsolatedWorker(scalar, tmp_path / "sandbox").run({})
