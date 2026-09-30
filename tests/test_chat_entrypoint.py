import runpy
from pathlib import Path


def test_installed_chat_entrypoint():
    namespace = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/chat_smoke.py"))
    namespace["smoke"]()
