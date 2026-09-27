"""Delegated authority: narrowing rules and grant-bound verification."""

import pytest

from openmuse.approvals import ApprovalAuthority
from openmuse.audit import AuditLog, verify_chain
from openmuse.models import Action
from openmuse.subagents import DelegatedAuthority, Grant, GrantError, GrantLedger

SECRET = b"root-secret"


def root_and_action():
    root = ApprovalAuthority(SECRET)
    action = Action("fetch_url", {"url": "https://example.com"}, id="act-1")
    return root, action


def test_child_verifies_within_grant():
    root, action = root_and_action()
    child = DelegatedAuthority(root, Grant(tools=frozenset({"fetch_url"})))
    token = root.issue(action)
    assert child.verify(action, token)
    assert not child.verify(action, token)


def test_child_cannot_exceed_grant():
    root, action = root_and_action()
    child = DelegatedAuthority(root, Grant(tools=frozenset({"read_file"})))
    token = root.issue(action)
    assert not child.verify(action, token), "tool outside the grant must fail closed"


def test_argument_constraints_enforced():
    root, _ = root_and_action()
    grant = Grant(
        tools=frozenset({"fetch_url"}),
        constraints={"fetch_url": {"url": "https://example.com"}},
    )
    child = DelegatedAuthority(root, grant)
    allowed = Action("fetch_url", {"url": "https://example.com"}, id="a")
    other = Action("fetch_url", {"url": "https://evil.example"}, id="b")
    assert child.verify(allowed, root.issue(allowed))
    assert not child.verify(other, root.issue(other))


def test_max_uses_enforced(tmp_path):
    root, _ = root_and_action()
    child = DelegatedAuthority(root, Grant(tools=frozenset({"fetch_url"}), max_uses=1), ledger=GrantLedger(tmp_path / "grants.db"))
    first = Action("fetch_url", {"url": "https://a.example"}, id="a")
    second = Action("fetch_url", {"url": "https://b.example"}, id="b")
    assert child.verify(first, root.issue(first))
    assert not child.verify(second, root.issue(second)), "use budget exhausted"


def test_expired_grant_fails_closed():
    root, action = root_and_action()
    child = DelegatedAuthority(root, Grant(tools=frozenset({"fetch_url"}), expires_at=1.0))
    assert not child.verify(action, root.issue(action))


def test_narrowing_must_be_strict(tmp_path):
    root, _ = root_and_action()
    parent_grant = Grant(tools=frozenset({"fetch_url", "read_file"}), max_uses=4)
    child = DelegatedAuthority(root, parent_grant, ledger=GrantLedger(tmp_path / "grants.db"))

    with pytest.raises(GrantError):
        child.narrow(parent_grant), "equal grants are not narrower"
    with pytest.raises(GrantError):
        child.narrow(Grant(tools=frozenset({"fetch_url", "read_file", "write_file"})))
    with pytest.raises(GrantError):
        child.narrow(Grant(tools=frozenset({"fetch_url"}), max_uses=9))
    with pytest.raises(GrantError):
        child.narrow(Grant(tools=frozenset({"fetch_url"}), max_uses=None))

    narrower = child.narrow(Grant(tools=frozenset({"fetch_url"}), max_uses=2))
    assert narrower.grant.tools == frozenset({"fetch_url"})
    with pytest.raises(GrantError):
        narrower.narrow(Grant(tools=frozenset({"fetch_url"}), max_uses=2))


def test_parent_constraints_must_survive_narrowing(tmp_path):
    root, _ = root_and_action()
    parent = DelegatedAuthority(
        root,
        Grant(tools=frozenset({"fetch_url"}), constraints={"fetch_url": {"url": "https://example.com"}}),
        ledger=GrantLedger(tmp_path / "grants.db"),
    )
    with pytest.raises(GrantError):
        parent.narrow(Grant(tools=frozenset({"fetch_url"}), max_uses=1)), "dropping a constraint widens"
    ok = parent.narrow(
        Grant(
            tools=frozenset({"fetch_url"}),
            max_uses=1,
            constraints={"fetch_url": {"url": "https://example.com"}},
        )
    )
    assert ok.grant.max_uses == 1


def test_delegation_is_audited(tmp_path):
    root, _ = root_and_action()
    audit = AuditLog(tmp_path / "audit.jsonl")
    DelegatedAuthority(root, Grant(tools=frozenset({"fetch_url"})), audit=audit)
    ok, count, error = verify_chain(tmp_path / "audit.jsonl")
    assert ok and count == 1, error


def test_siblings_share_parent_budget_concurrently(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    root = ApprovalAuthority(SECRET)
    parent = DelegatedAuthority(
        root, Grant(tools=frozenset({"fetch_url", "read_file"}), max_uses=3),
        ledger=GrantLedger(tmp_path / "grants.db"),
    )
    siblings = [parent.narrow(Grant(tools=frozenset({"fetch_url"}), max_uses=3)) for _ in range(8)]
    actions = [Action("fetch_url", {"url": f"https://{i}.example"}) for i in range(8)]
    tokens = [root.issue(action) for action in actions]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda triple: triple[0].verify(*triple[1:]), zip(siblings, actions, tokens)))
    assert sum(results) == 3
    assert not siblings[0].verify(actions[0], tokens[0])


def test_quota_requires_durable_ledger():
    root, _ = root_and_action()
    with pytest.raises(GrantError, match="durable"):
        DelegatedAuthority(root, Grant(tools=frozenset({"fetch_url"}), max_uses=1))
