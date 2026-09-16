import json
from pathlib import Path

from openmuse.audit import AuditLog, verify_chain


def test_verify_chain_and_detect_tampering(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append({"action": "read"})
    log.append({"action": "write", "token": "secret"})
    assert verify_chain(path) == (True, 2, None)
    records = path.read_text().splitlines()
    changed = json.loads(records[0])
    changed["action"] = "tampered"
    records[0] = json.dumps(changed)
    path.write_text("\n".join(records))
    assert verify_chain(path)[0] is False
