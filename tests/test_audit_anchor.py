from dataclasses import replace

from openmuse.audit import AuditLog
from openmuse.audit_anchor import create_checkpoint, verify_checkpoint, write_checkpoint


def test_signed_checkpoint_detects_tampering(tmp_path):
    audit=tmp_path/"audit.jsonl"; AuditLog(audit).append({"event":"x"})
    checkpoint=create_checkpoint(audit,b"k",clock=lambda:123)
    assert checkpoint.records==1 and verify_checkpoint(checkpoint,b"k")
    assert not verify_checkpoint(replace(checkpoint,head_hash="0"*64),b"k")
    write_checkpoint(checkpoint,tmp_path/"checkpoint.json")
    assert '"signature"' in (tmp_path/"checkpoint.json").read_text()
