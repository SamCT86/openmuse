"""Credential-free IsolatedWorker example used by the local walkthrough."""

import json
from pathlib import Path

from openmuse.isolated_worker import IsolatedWorker, WorkerLimits

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT / ".openmuse-worker-demo"
ENTRYPOINT = ROOT / "examples" / "worker_echo.py"

result = IsolatedWorker(
    ENTRYPOINT,
    WORKSPACE,
    WorkerLimits(timeout_seconds=2, memory_bytes=128 * 1024 * 1024),
).run({"message": "hello from the host", "numbers": [2, 3, 5]})
print(json.dumps(result.output, sort_keys=True))
