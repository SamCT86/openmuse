import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_e2e_demo_and_verifier(tmp_path):
    demo = subprocess.run([sys.executable, str(ROOT / "examples/e2e_demo.py"), "--auto-approve"], cwd=tmp_path, check=True, capture_output=True, text=True)
    assert "PAUSED before sensitive action" in demo.stdout
    assert "Action runs; task completes" in demo.stdout
    verify = subprocess.run([sys.executable, str(ROOT / "examples/verify_audit.py")], cwd=tmp_path, check=True, capture_output=True, text=True)
    assert "VERIFIED: 3 records" in verify.stdout
