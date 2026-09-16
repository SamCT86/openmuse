"""Evidence, verification state, and bounded retry policy."""

from dataclasses import dataclass
from enum import Enum


class Verification(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    CONFLICTED = "conflicted"


@dataclass(frozen=True)
class Evidence:
    claim: str
    source_url: str | None
    verification: Verification
    observed_at: str
    detail: str = ""


@dataclass
class RetryBudget:
    maximum: int = 1
    attempts: int = 0

    def take(self, retryable: bool) -> bool:
        if not retryable or self.attempts >= self.maximum:
            return False
        self.attempts += 1
        return True
