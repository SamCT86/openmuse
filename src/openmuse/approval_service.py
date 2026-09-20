"""Persistent approval requests with authenticated, single-use decisions."""
import hashlib
import hmac
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .models import Action


@dataclass(frozen=True)
class ApprovalRequest:
    id:str; action_json:str; identity:str; destination:str; expires_at:int; status:str

class ApprovalService:
    def __init__(self,path:Path,session_key:bytes,clock=time.time):
        self.db=sqlite3.connect(path); self.session_key=session_key; self.clock=clock
        self.db.execute("CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,action_json TEXT,identity TEXT,destination TEXT,expires_at INTEGER,status TEXT)"); self.db.commit()
    def create(self,action:Action,identity:str,destination:str,ttl_seconds:int=300)->tuple[ApprovalRequest,str]:
        request=ApprovalRequest(uuid4().hex,json.dumps({"tool":action.tool,"arguments":action.arguments},sort_keys=True),identity,destination,int(self.clock())+ttl_seconds,"pending")
        with self.db: self.db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?)",(request.id,request.action_json,identity,destination,request.expires_at,request.status))
        return request,self._session(request.id,request.expires_at)
    def decide(self,request_id:str,session:str,decision:str)->ApprovalRequest:
        if decision not in {"approved","denied"}: raise ValueError("invalid decision")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row=self.db.execute("SELECT * FROM approvals WHERE id=?",(request_id,)).fetchone()
            if row is None: raise ValueError("unknown approval")
            request=ApprovalRequest(*row)
            if not hmac.compare_digest(session,self._session(request.id,request.expires_at)): raise ValueError("invalid approval session")
            if int(self.clock())>=request.expires_at: raise ValueError("approval expired")
            if request.status!="pending": raise ValueError("approval already decided")
            self.db.execute("UPDATE approvals SET status=? WHERE id=?",(decision,request_id)); self.db.commit()
            return ApprovalRequest(request.id,request.action_json,request.identity,request.destination,request.expires_at,decision)
        except Exception: self.db.rollback(); raise
    def _session(self,request_id,expires_at): return hmac.new(self.session_key,f"{request_id}.{expires_at}".encode(),hashlib.sha256).hexdigest()
