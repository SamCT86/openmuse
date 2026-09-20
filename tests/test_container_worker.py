import json
import subprocess
from unittest.mock import Mock

import pytest

from openmuse.container_worker import ContainerWorker
from openmuse.isolated_worker import WorkerLimits


def test_container_profile_has_no_network_or_host_mounts():
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, '{"ok": true}', ""))
    worker = ContainerWorker("example/worker@sha256:abc", ["python", "/app/worker.py"], runner=runner)
    assert worker.run({"hello": "world"}).output == {"ok": True}
    command = runner.call_args.args[0]
    for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
        assert flag in command
    assert not any(item.startswith("--volume") or item == "-v" for item in command)
    assert json.loads(runner.call_args.kwargs["input"]) == {"hello": "world"}

def test_container_worker_enforces_output_limit():
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, "x" * 11, ""))
    worker = ContainerWorker("worker@sha256:abc", ["run"], limits=WorkerLimits(output_bytes=10), runner=runner)
    with pytest.raises(ValueError, match="output limit"):
        worker.run({})

def test_container_worker_surfaces_runtime_failure():
    runner = Mock(return_value=subprocess.CompletedProcess([], 125, "", "runtime unavailable"))
    with pytest.raises(RuntimeError, match="runtime unavailable"):
        ContainerWorker("worker@sha256:abc", ["run"], runner=runner).run({})


def test_container_image_must_be_digest_pinned():
    with pytest.raises(ValueError, match="pinned"):
        ContainerWorker("worker:latest", ["run"])
