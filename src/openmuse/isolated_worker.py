"""OS-process worker boundary with bounded time, memory, files, and output."""

import json
import os
import resource
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class WorkerLimits:
    timeout_seconds: float = 10
    memory_bytes: int = 256 * 1024 * 1024
    output_bytes: int = 200_000
    open_files: int = 64


@dataclass(frozen=True)
class WorkerResult:
    output: dict[str, Any]
    stderr: str


def _limit_process(limits: WorkerLimits) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits.open_files, limits.open_files))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class IsolatedWorker:
    """Run a JSON request in a fresh, resource-limited Python process.

    The child receives only an explicit environment allowlist and a dedicated
    working directory. Production deployments should add a container/seccomp
    or VM network boundary; this class makes process and resource separation
    real without claiming kernel-enforced network isolation.
    """

    def __init__(self, entrypoint: Path, workspace: Path, limits: WorkerLimits | None = None) -> None:
        self.entrypoint = entrypoint.resolve()
        self.workspace = workspace.resolve()
        self.limits = limits or WorkerLimits()

    def run(self, request: dict[str, Any], environment: dict[str, str] | None = None) -> WorkerResult:
        self.workspace.mkdir(parents=True, exist_ok=True)
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8", **(environment or {})}
        try:
            completed = subprocess.run(
                [sys.executable, "-I", str(self.entrypoint)],
                input=json.dumps(request),
                text=True,
                capture_output=True,
                cwd=self.workspace,
                env=env,
                timeout=self.limits.timeout_seconds,
                preexec_fn=lambda: _limit_process(self.limits),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("isolated worker timed out") from exc
        stdout = completed.stdout.encode()
        stderr = completed.stderr.encode()
        if len(stdout) > self.limits.output_bytes or len(stderr) > self.limits.output_bytes:
            raise ValueError("isolated worker output limit exceeded")
        if completed.returncode != 0:
            raise RuntimeError(f"isolated worker failed ({completed.returncode}): {completed.stderr.strip()}")
        response = json.loads(completed.stdout)
        if not isinstance(response, dict):
            raise TypeError("isolated worker response must be a JSON object")
        return WorkerResult(response, completed.stderr)
