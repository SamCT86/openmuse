"""Container-backed worker profile with network and mount isolation."""
import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from .isolated_worker import WorkerLimits, WorkerResult

Runner = Callable[..., subprocess.CompletedProcess[str]]

@dataclass(frozen=True)
class ContainerPolicy:
    runtime: str = "docker"
    pids_limit: int = 64
    tmpfs_bytes: int = 64 * 1024 * 1024

class ContainerWorker:
    """Run a JSON worker in a locked-down, mount-free container."""
    def __init__(self, image: str, command: Sequence[str], *, limits: WorkerLimits | None = None, policy: ContainerPolicy | None = None, runner: Runner = subprocess.run) -> None:
        if not image or not command:
            raise ValueError("container image and worker command are required")
        if "@sha256:" not in image:
            raise ValueError("container image must be pinned by sha256 digest")
        self.image, self.command = image, tuple(command)
        self.limits, self.policy, self._runner = limits or WorkerLimits(), policy or ContainerPolicy(), runner

    def runtime_command(self) -> list[str]:
        return [self.policy.runtime, "run", "--rm", "--interactive", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", f"--pids-limit={self.policy.pids_limit}", f"--memory={self.limits.memory_bytes}", "--user=65532:65532", f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={self.policy.tmpfs_bytes}", self.image, *self.command]

    def run(self, request: dict[str, Any]) -> WorkerResult:
        try:
            completed = self._runner(self.runtime_command(), input=json.dumps(request), text=True, capture_output=True, timeout=self.limits.timeout_seconds, check=False)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("container worker timed out") from error
        if len(completed.stdout.encode()) > self.limits.output_bytes or len(completed.stderr.encode()) > self.limits.output_bytes:
            raise ValueError("container worker output limit exceeded")
        if completed.returncode != 0:
            raise RuntimeError(f"container worker failed ({completed.returncode}): {completed.stderr.strip()}")
        response = json.loads(completed.stdout)
        if not isinstance(response, dict):
            raise TypeError("container worker response must be a JSON object")
        return WorkerResult(response, completed.stderr)
