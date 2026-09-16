"""Redacted, hash-chained JSONL audit trail."""
import hashlib,json,os
from pathlib import Path
from typing import Any,Mapping
SENSITIVE={"password","token","secret","authorization","api_key","cookie"}
def redact(v:Any)->Any:
    if isinstance(v,Mapping):return {k:("[REDACTED]" if k.lower() in SENSITIVE else redact(x)) for k,x in v.items()}
    if isinstance(v,list):return [redact(x) for x in v]
    return v
class AuditLog:
    def __init__(self,path:Path):self.path=path
    def append(self,record:dict[str,Any])->None:
        self.path.parent.mkdir(parents=True,exist_ok=True);previous="0"*64
        if self.path.exists():
            lines=self.path.read_text(encoding="utf-8").splitlines();previous=json.loads(lines[-1]).get("hash",previous) if lines else previous
        clean=redact(record);clean["previous_hash"]=previous;raw=json.dumps(clean,sort_keys=True,separators=(",",":"),ensure_ascii=False);clean["hash"]=hashlib.sha256(raw.encode()).hexdigest()
        fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        with os.fdopen(fd,"a",encoding="utf-8") as h:h.write(json.dumps(clean,ensure_ascii=False)+"\n")
