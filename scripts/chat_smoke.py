"""Credential-free black-box smoke for the installed browser-chat command."""
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import urllib.request
from pathlib import Path


def smoke() -> None:
    command = shutil.which("openmuse-chat")
    if command is None:
        raise RuntimeError("Install the package before running this smoke test")
    env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
    env["PYTHONUNBUFFERED"] = "1"
    with tempfile.TemporaryDirectory(prefix="openmuse-chat-smoke-") as workspace:
        process = subprocess.Popen(
            [command, "--planner", "demo", "--port", "0", "--workspace", workspace],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
        )
        lines: queue.Queue[str] = queue.Queue()

        def read_output() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                lines.put(line)
            lines.put("")

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            line = lines.get(timeout=20)
            match = re.search(r"http://127\.0\.0\.1:(\d+)", line)
            if match is None:
                raise RuntimeError(f"Chat did not announce a loopback address: {line!r}")
            with urllib.request.urlopen(match.group(0), timeout=10) as response:
                assert response.status == 200
                page = response.read().decode()
                assert "OpenMuse" in page and "openmuse-csrf" in page
                assert "offline demo planner" in page
            assert not (Path(workspace) / "notes").exists()
            print("PASS: installed openmuse-chat serves its offline landing page on an ephemeral loopback port")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=5)
            assert process.stdout is not None
            process.stdout.close()
            if reader.is_alive():
                raise RuntimeError("Chat output reader failed to stop")


if __name__ == "__main__":
    smoke()
