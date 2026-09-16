"""Typed, approval-bound external effect proposals."""

from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class MessageEffect:
    identity: str
    recipient: str
    body: str
    channel: str


@dataclass(frozen=True)
class ScheduleEffect:
    identity: str
    summary: str
    starts_at: str
    ends_at: str
    attendees: tuple[str, ...] = ()


@dataclass(frozen=True)
class PurchaseEffect:
    merchant: str
    currency: str
    subtotal: Decimal
    tax: Decimal
    shipping: Decimal
    fees: Decimal
    total: Decimal
    address_hint: str
    payment_hint: str

    def validate(self) -> None:
        expected = self.subtotal + self.tax + self.shipping + self.fees
        if expected != self.total:
            raise ValueError(f"final total mismatch: {expected} != {self.total}")
