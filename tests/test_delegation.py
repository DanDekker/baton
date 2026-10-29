from concurrent.futures import ThreadPoolExecutor
import time

import pytest

from baton_auth import delegation
from baton_auth.catalog import build_credential
from baton_auth.models import Context, LeaseError
from baton_auth.vault import Vault


@pytest.fixture
def vault(tmp_path):
    with Vault(tmp_path / "broker", master_key=b"k" * 32) as vault:
        vault.put_credential(build_credential("gh", "github", {"token": "ghp_" + "Z" * 36}))
        vault.put_credential(build_credential("ai", "openai", {"token": "sk-" + "X" * 40}))
        vault.put_context(Context("work", credentials=["gh", "ai"]))
        for name in ("alice", "bob", "carol"):
            vault._conn.execute("INSERT INTO agents VALUES(?,?,?,0,?)", (name, name, "test-public-key", time.time()))
        vault._conn.commit()
        yield vault


def grant(vault, **kwargs):
    options = dict(recipient="alice", services=["github"], ttl=60, max_uses=5, delegatable=True)
    options.update(kwargs)
    return vault.issue_lease("work", **options)


def test_recipient_proof_and_acceptance_are_required(vault):
    lease = grant(vault)
    with pytest.raises(LeaseError, match="authenticated"):
        vault.resolve_lease(lease.token)
    with pytest.raises(LeaseError, match="not bound"):
        delegation.accept(vault, lease.id, "bob")
    with pytest.raises(LeaseError, match="accepted"):
        delegation.resolve(vault, lease.id, "alice")
    assert [l["id"] for l in delegation.inbox(vault, "alice")] == [lease.id]
    assert delegation.inbox(vault, "bob") == []
    delegation.accept(vault, lease.id, "alice")
    assert delegation.resolve(vault, lease.id, "alice").uses == 1
    assert delegation.resolve(vault, lease.token, "alice", consume=False).id == lease.id
    unbound = vault.issue_lease("work")
    with pytest.raises(LeaseError, match="not bound"):
        delegation.resolve(vault, unbound.token, "alice")


def test_child_permissions_and_lifetime_only_narrow(vault):
    root = grant(vault, http_methods=["GET", "POST"], path_prefixes=["/repos/acme"])
    delegation.accept(vault, root.id, "alice")
    child = delegation.delegate(vault, root.id, "alice", "bob", ttl=9999, max_uses=999,
                                http_methods=["GET"], path_prefixes=["/repos/acme/project"],
                                task={"summary": "Review the change", "artifacts": ["pr:42"]})
    assert child.expires_at <= root.expires_at
    assert child.max_uses == root.max_uses
    assert child.parent_id == root.id
    assert child.credential_ids == root.credential_ids
    assert child.host_policies == root.host_policies
    assert child.task["artifacts"] == ["pr:42"]
    delegation.accept(vault, child.id, "bob")
    with pytest.raises(LeaseError, match="further delegation"):
        delegation.delegate(vault, child.id, "bob", "carol")
    for options in ({"http_methods": ["DELETE"]}, {"path_prefixes": ["/"]},
                    {"path_prefixes": ["/repos/acme-other"]}, {"services": ["openai"]},
                    {"services": []}):
        with pytest.raises(LeaseError):
            delegation.delegate(vault, root.id, "alice", "bob", **options)


def test_ancestor_budget_shared_atomically_across_connections(vault):
    root = grant(vault, max_uses=3)
    delegation.accept(vault, root.id, "alice")
    children = [delegation.delegate(vault, root.id, "alice", name) for name in ("bob", "carol")]
    for child in children:
        delegation.accept(vault, child.id, child.recipient)
    def consume(i):
        child = children[i % 2]
        with Vault(vault.state_dir, master_key=b"k" * 32) as independent:
            try:
                delegation.resolve(independent, child.id, child.recipient)
                return True
            except LeaseError:
                return False
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(consume, range(12))) == 3
    assert vault._conn.execute("SELECT uses FROM leases WHERE id=?", (root.id,)).fetchone()[0] == 3
    uses = [vault._conn.execute("SELECT uses FROM leases WHERE id=?", (c.id,)).fetchone()[0] for c in children]
    assert sum(uses) == 3


def test_parent_and_identity_revocation_cascade(vault):
    root = grant(vault)
    delegation.accept(vault, root.id, "alice")
    child = delegation.delegate(vault, root.id, "alice", "bob", delegatable=True)
    delegation.accept(vault, child.id, "bob")
    leaf = delegation.delegate(vault, child.id, "bob", "carol")
    delegation.accept(vault, leaf.id, "carol")
    vault.revoke_lease(root.id)
    with pytest.raises(LeaseError, match="revoked"):
        delegation.resolve(vault, leaf.id, "carol")
    root2 = grant(vault)
    delegation.accept(vault, root2.id, "alice")
    child2 = delegation.delegate(vault, root2.id, "alice", "bob")
    delegation.accept(vault, child2.id, "bob")
    vault._conn.execute("UPDATE agents SET revoked=1 WHERE id='alice'")
    vault._conn.commit()
    with pytest.raises(LeaseError, match="revoked"):
        delegation.resolve(vault, child2.id, "bob")


def test_revoke_only_own_tree_even_when_exhausted(vault):
    root = grant(vault, max_uses=1)
    other = grant(vault)
    delegation.accept(vault, root.id, "alice")
    child = delegation.delegate(vault, root.id, "alice", "bob")
    delegation.accept(vault, child.id, "bob")
    delegation.resolve(vault, child.id, "bob")
    with pytest.raises(LeaseError, match="descendant"):
        delegation.revoke(vault, root.id, "alice", other.id)
    assert delegation.revoke(vault, root.id, "alice", child.id)
    assert delegation.revoke(vault, root.id, "alice")


def test_http_policy_rejects_alternate_authorities_and_traversal(vault):
    lease = grant(vault, path_prefixes=["/repos/acme"])
    delegation.check_http(lease, "GET", "https://api.github.com/repos/acme/prs", "gh")
    for url in ("http://api.github.com/repos/acme", "https://api.github.com:8443/repos/acme",
                "https://evil.example/repos/acme", "https://user@api.github.com/repos/acme",
                "https://api.github.com/repos/acme/../elsewhere",
                "https://api.github.com/repos/acme/%252e%252e/elsewhere",
                "https://api.github.com/repos/acme/..;/elsewhere",
                "https://api.github.com/repos/acme-other", "https://api.github.com/repos/acme#x"):
        with pytest.raises(LeaseError):
            delegation.check_http(lease, "GET", url, "gh")
    with pytest.raises(LeaseError, match="method"):
        delegation.check_http(lease, "POST", "https://api.github.com/repos/acme", "gh")


def test_root_requires_finite_limits_and_explicit_host_scoping(vault):
    for ttl in (float("nan"), float("inf"), -1, 0):
        with pytest.raises(LeaseError):
            grant(vault, ttl=ttl)
    for uses in (-1, 0, True, 1.5):
        with pytest.raises(LeaseError):
            grant(vault, max_uses=uses)
    vault.put_credential(build_credential("unscoped", "generic", {"token": "example_secret_value"}))
    with pytest.raises(LeaseError, match="explicit allowed hosts"):
        vault.issue_lease("unscoped", recipient="alice")


def test_delegation_depth_is_bounded(vault):
    parent = grant(vault)
    delegation.accept(vault, parent.id, "alice")
    for _ in range(delegation.MAX_DEPTH - 1):
        parent = delegation.delegate(vault, parent.id, "alice", "alice", delegatable=True)
        delegation.accept(vault, parent.id, "alice")
    with pytest.raises(LeaseError, match="further delegation"):
        delegation.delegate(vault, parent.id, "alice", "alice")


def test_audit_chain_serializes_independent_writers(vault):
    def record(i):
        with Vault(vault.state_dir, master_key=b"k" * 32) as independent:
            independent.audit(None, f"agent-{i}", "test", None, True, {})
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(record, range(20)))
    assert vault.verify_audit()[0]
