from dataclasses import dataclass
from enum import Enum
from .approvals import ApprovalAuthority
from .models import Action
class Risk(str,Enum):READ="read";WRITE="write";REPRESENT="represent";MONEY="money"
@dataclass(frozen=True)
class Decision:allowed:bool;reason:str
class Policy:
    def __init__(self,allow_writes=False,approvals:ApprovalAuthority|None=None):self.allow_writes=allow_writes;self.approvals=approvals
    def check(self,risk:Risk,action:Action)->Decision:
        if risk is Risk.READ:return Decision(True,"read-only action")
        if risk is Risk.WRITE and self.allow_writes:return Decision(True,"writes enabled for this run")
        if self.approvals and self.approvals.verify(action,action.approval_token):return Decision(True,"valid one-time approval")
        return Decision(False,f"{risk.value} action requires host approval")
