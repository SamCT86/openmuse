"""Approval token safety: expiry boundary, exact binding, atomic one-time use."""

import json
import threading

import pytest

from openmuse import approvals
from openmuse.approvals import ApprovalAuthority
from openmuse.models import Action

SECRET = b"test-secret"


def make_action() -> Action:
    return Action("write_file", {"path": "plan.md", "content": "x"}, id="act-1")


def issue_at(authority: ApprovalAuthority, action: Action, now: int, ttl: int) -> str:
    payload = {"id": action.id, "tool": action.tool, "arguments": action.arguments, "exp": now + ttl}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    import hashlib
    import hmac

    return raw.hex() + "." + hmac.new(authority.secret, raw, hashlib.sha256).hexdigest()


@pytest.fixture
def frozen_time(monkeypatch: pytest.MonkeyPatch):
    state = {"now": 1_800_000_000}
    monkeypatch.setattr(approvals.time, "time", lambda: state["now"])
    return state


def test_valid_token_consumed_once(frozen_time):
    authority = ApprovalAuthority(SECRET)
    action = make_action()
    token = authority.issue(action, ttl_seconds=300)
    assert authority.verify(action, token)
    assert not authority.verify(action, token), "replay must fail"


def test_expiry_boundary_rejects_exp_equals_now(frozen_time):
    authority = ApprovalAuthority(SECRET)
    action = make_action()
    token = issue_at(authority, action, frozen_time["now"], ttl=0)
    assert not authority.verify(action, token), "now >= exp must be expired"


def test_token_valid_one_second_before_expiry(frozen_time):
    authority = ApprovalAuthority(SECRET)
    action = make_action()
    token = issue_at(authority, action, frozen_time["now"], ttl=1)
    assert authority.verify(action, token)


def test_tampered_signature_rejected(frozen_time):
    authority = ApprovalAuthority(SECRET)
    action = make_action()
    token = authority.issue(action)
    raw_hex, _ = token.split(".", 1)
    assert not authority.verify(action, raw_hex + "." + "0" * 64)


def test_binding_rejects_action_substitution(frozen_time):
    authority = ApprovalAuthority(SECRET)
    action = make_action()
    token = authority.issue(action)
    other = Action("write_file", {"path": "other.md", "content": "x"}, id="act-1")
    assert not authority.verify(other, token)
    renamed = Action("read_file", {"path": "plan.md", "content": "x"}, id="act-1")
    assert not authority.verify(renamed, token)


def test_malformed_tokens_fail_closed(frozen_time):
    authority = ApprovalAuthority(SECRET)
    action = make_action()
    for bad in (None, "", "zz", "a.b", "a.b.c"):
        assert not authority.verify(action, bad)
    not_an_object = json.dumps([1, 2, 3]).encode().hex()
    assert not authority.verify(action, not_an_object + "." + "0" * 64)
    missing_exp = json.dumps({"id": "act-1", "tool": "write_file", "arguments": {}}).encode().hex()
    assert not authority.verify(action, missing_exp + "." + "0" * 64)
    bad_exp = json.dumps(
        {"id": "act-1", "tool": "write_file", "arguments": {}, "exp": "soon"}, separators=(",", ":")
    ).encode().hex()
    assert not authority.verify(action, bad_exp + "." + "0" * 64)


def test_concurrent_verify_consumes_exactly_once(frozen_time):
    """Barrier-synchronized contention: exactly one thread may consume a token."""
    authority = ApprovalAuthority(SECRET)
    action = make_action()
    token = authority.issue(action)
    threads_n = 32
    barrier = threading.Barrier(threads_n)
    outcomes: list[bool] = []
    outcomes_lock = threading.Lock()

    def contender() -> None:
        barrier.wait(timeout=10)
        result = authority.verify(action, token)
        with outcomes_lock:
            outcomes.append(result)

    threads = [threading.Thread(target=contender) for _ in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive()

    assert len(outcomes) == threads_n
    assert sum(outcomes) == 1, "exactly one concurrent verification may succeed"
    assert not authority.verify(action, token), "token remains consumed after the race"
