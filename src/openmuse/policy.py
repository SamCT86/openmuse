"""Policy checks for actions with external effects."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Risk(str, Enum):
    READ = "read"
    WRITE = "write"
    REPRESENT = "represent"
    MONEY = "money"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class Policy:
    """Small, explicit policy engine.

    Reads can run unattended. Writes need opt-in. Messages, purchases and
    other high-impact actions always need a fresh approval token.
    """

    def __init__(self, allow_writes: bool = False) -> None:
        self.allow_writes = allow_writes

    def check(self, risk: Risk, approval: str | None = None) -> Decision:
        if risk is Risk.READ:
            return Decision(True, "read-only action")
        if risk is Risk.WRITE and self.allow_writes:
            return Decision(True, "writes enabled for this run")
        if risk in {Risk.REPRESENT, Risk.MONEY} and approval == "approved":
            return Decision(True, "explicit approval supplied")
        return Decision(False, f"{risk.value} action requires approval")
