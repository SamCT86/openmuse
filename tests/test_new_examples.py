import subprocess
import sys
from pathlib import Path


def run_example(name: str) -> str:
    root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [sys.executable, root / "examples" / name], cwd=root, text=True, capture_output=True, check=True
    ).stdout


def test_memory_demo():
    output = run_example("memory_demo.py")
    assert "found='Prefers quiet cafés'" in output
    assert "verified=True violations=[]" in output
    assert "forgotten=True verified=True" in output


def test_scheduler_demo():
    output = run_example("scheduler_demo.py")
    assert "created='verify the audit chain'" in output
    assert "first_claim=1 second_claim=0" in output
