"""Signed audit-chain checkpoints for external anchoring."""
import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from time import time

from .audit import verify_chain


@dataclass(frozen=True)
class AuditCheckpoint:
    records: int
    head_hash: str
    created_at: int
    signature: str

def create_checkpoint(audit_path: Path, signing_key: bytes, clock=time) -> AuditCheckpoint:
    ok, count, error=verify_chain(audit_path)
    if not ok: raise ValueError(f"cannot anchor broken audit chain: {error}")
    lines=audit_path.read_text(encoding="utf-8").splitlines()
    head=json.loads(lines[-1])["hash"] if lines else "0"*64
    created_at=int(clock()); message=f"{count}.{head}.{created_at}".encode()
    return AuditCheckpoint(count,head,created_at,hmac.new(signing_key,message,hashlib.sha256).hexdigest())

def verify_checkpoint(checkpoint: AuditCheckpoint, signing_key: bytes) -> bool:
    message=f"{checkpoint.records}.{checkpoint.head_hash}.{checkpoint.created_at}".encode()
    return hmac.compare_digest(checkpoint.signature,hmac.new(signing_key,message,hashlib.sha256).hexdigest())

def write_checkpoint(checkpoint: AuditCheckpoint,path: Path) -> None:
    path.parent.mkdir(parents=True,exist_ok=True); path.write_text(json.dumps(asdict(checkpoint),sort_keys=True)+"\n",encoding="utf-8")
