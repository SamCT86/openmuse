"""Capture child output to capped files instead of unbounded RAM pipes."""

import resource
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def run_bounded(
    command: Sequence[str], request: str, output_bytes: int, timeout_seconds: float,
    *, cwd: Path | None = None, env: dict[str, str] | None = None,
    preexec_fn: Any = None,
) -> subprocess.CompletedProcess[str]:
    if output_bytes < 1 or timeout_seconds <= 0:
        raise ValueError("positive output and timeout limits required")

    def limit_child() -> None:
        # Each output file is capped by the kernel before it can grow without bound.
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_bytes, output_bytes))
        if preexec_fn is not None:
            preexec_fn()

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            completed = subprocess.run(
                command, input=request, text=True, stdout=stdout, stderr=stderr,
                timeout=timeout_seconds, cwd=cwd, env=env, preexec_fn=limit_child, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("worker timed out") from exc
        for handle in (stdout, stderr):
            handle.seek(0, 2)
            if handle.tell() >= output_bytes:
                raise ValueError("worker output limit exceeded")
            handle.seek(0)
        return subprocess.CompletedProcess(
            completed.args, completed.returncode,
            stdout.read().decode("utf-8", errors="replace"),
            stderr.read().decode("utf-8", errors="replace"),
        )
