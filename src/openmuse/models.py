"""Typed runtime models."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4
class ActionStatus(str, Enum):
    PROPOSED="proposed"; COMPLETED="completed"; FAILED="failed"; BLOCKED="blocked"; CANCELED="canceled"
@dataclass(frozen=True)
class Action:
    tool:str; arguments:Mapping[str,Any]=field(default_factory=dict); id:str=field(default_factory=lambda:uuid4().hex); approval_token:str|None=None
@dataclass(frozen=True)
class ToolResult:
    action_id:str; status:ActionStatus; output:str=""; error_code:str|None=None; retryable:bool=False
