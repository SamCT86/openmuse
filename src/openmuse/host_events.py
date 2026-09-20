"""Authenticated host decision events, isolated from planner and page text."""
import hashlib
import hmac
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path


class ReplayStore:
    """Atomic, durable, TTL-bounded event consumption."""
    def __init__(self, path: Path, clock=time.time):
        self.db = sqlite3.connect(path)
        self.clock = clock
        self.db.execute("CREATE TABLE IF NOT EXISTS seen(event_id TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)")
        self.db.commit()
    def consume(self, event_id: str, expires_at: int) -> None:
        now = int(self.clock())
        with self.db:
            self.db.execute("DELETE FROM seen WHERE expires_at < ?", (now,))
            try: self.db.execute("INSERT INTO seen VALUES(?,?)", (event_id, expires_at))
            except sqlite3.IntegrityError as error: raise ValueError("replayed host event") from error

@dataclass
class HostEventVerifier:
    secret: bytes
    maximum_age_seconds: int = 60
    replay_store: ReplayStore | None = None
    def __post_init__(self):
        if self.replay_store is None: self.replay_store = ReplayStore(Path(":memory:"))
    def sign(self, event_id: str, timestamp: int, payload: dict[str, object]) -> str:
        return hmac.new(self.secret, self._message(event_id,timestamp,payload), hashlib.sha256).hexdigest()
    def verify(self,event_id,timestamp,payload,signature):
        now=int(time.time())
        if abs(now-timestamp)>self.maximum_age_seconds: raise ValueError("stale host event")
        expected=self.sign(event_id,timestamp,payload)
        if not hmac.compare_digest(expected,signature): raise ValueError("invalid host signature")
        assert self.replay_store is not None
        self.replay_store.consume(event_id, timestamp+self.maximum_age_seconds)
    @staticmethod
    def _message(event_id,timestamp,payload):
        canonical=json.dumps(payload,sort_keys=True,separators=(",",":"))
        return f"{event_id}.{timestamp}.{canonical}".encode()

@dataclass(frozen=True)
class HostDecisionEndpoint:
    verifier: HostEventVerifier
    def post(self,headers,body):
        payload=json.loads(body)
        if not isinstance(payload,dict): raise TypeError("host event payload must be an object")
        event_id=headers["x-openmuse-event-id"]; timestamp=int(headers["x-openmuse-timestamp"]); signature=headers["x-openmuse-signature"]
        self.verifier.verify(event_id,timestamp,payload,signature)
        if payload.get("decision") not in {"approve","deny"} or not payload.get("action_id"): raise ValueError("invalid decision event")
        return {"accepted":True,"event_id":event_id,"action_id":payload["action_id"],"decision":payload["decision"]}
