import json
import subprocess
import sys
from pathlib import Path


def test_isolated_worker_demo_runs_without_credentials(tmp_path):
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [sys.executable, root / "examples" / "isolated_worker_demo.py"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    output = json.loads(completed.stdout)
    assert output["child_pid"] != 0
    assert output["cwd_name"] == ".openmuse-worker-demo"
    assert output["message"] == "hello from the host"
    assert output["sum"] == 10
    (root / ".openmuse-worker-demo").rmdir()
