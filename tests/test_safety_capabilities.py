from decimal import Decimal
from pathlib import Path

import pytest

from openmuse.effects import PurchaseEffect
from openmuse.ephemeral import EphemeralBroker
from openmuse.evidence import RetryBudget
from openmuse.memory import MemoryStore


def test_exact_total():
    p = PurchaseEffect("shop", "USD", Decimal(10), Decimal(1), Decimal(2), Decimal(0), Decimal(13), "home", "visa-42")
    p.validate()


def test_bad_total():
    with pytest.raises(ValueError):
        PurchaseEffect(
            "shop", "USD", Decimal(10), Decimal(1), Decimal(0), Decimal(0), Decimal(99), "home", "card"
        ).validate()


def test_otp_consumed_once():
    b = EphemeralBroker()
    h = b.issue("123456", "login:example")
    assert b.consume(h, "login:example") == "123456"
    with pytest.raises(KeyError):
        b.consume(h, "login:example")


def test_memory_forget(tmp_path: Path):
    s = MemoryStore(tmp_path / "memory.json")
    m = s.remember("likes tea", "chat:1", "2026-09-16")
    assert s.explain(m.id).source == "chat:1"
    assert s.forget(m.id).deleted


def test_retry_budget():
    b = RetryBudget(1)
    assert b.take(True)
    assert not b.take(True)
    assert not RetryBudget().take(False)
