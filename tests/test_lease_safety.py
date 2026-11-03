import json
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from baton_auth import crypto, delegation
from baton_auth.catalog import build_credential
from baton_auth.models import Context, Lease, LeaseError, MAX_LEASE_USES
from baton_auth.vault import Vault

KEY = b"k" * 32


@pytest.fixture
def vault(tmp_path):
    with Vault(state_dir=tmp_path / "state", master_key=KEY) as vault:
        vault.put_credential(build_credential("gh", "github", {"token": "test-token"}))
        vault.put_context(Context("work", credentials=["gh"]))
        vault._conn.execute(
            "INSERT INTO agents VALUES('alice','alice','test-key',0,?)", (time.time(),)
        )
        vault._conn.commit()
        yield vault


@pytest.mark.parametrize("recipient", [None, "alice"])
@pytest.mark.parametrize(
    "options",
    [
        {"ttl": value}
        for value in (0, -1, True, "30", float("nan"), float("inf"), 10**1000)
    ]
    + [{"max_uses": value} for value in (0, -1, True, 1.5, "2", 1 << 63, 10**1000)],
)
def test_invalid_limits_never_create_a_grant(vault, recipient, options):
    with pytest.raises(LeaseError):
        vault.issue_lease("work", recipient=recipient, **options)
    assert vault._conn.execute("SELECT count(*) FROM leases").fetchone()[0] == 0


def test_sqlite_counter_boundary_cannot_overflow(vault):
    lease = vault.issue_lease("work", max_uses=MAX_LEASE_USES)
    vault._conn.execute(
        "UPDATE leases SET uses=? WHERE id=?", (MAX_LEASE_USES - 1, lease.id)
    )
    vault._conn.commit()

    def consume(_):
        with Vault(state_dir=vault.state_dir, master_key=KEY) as connection:
            try:
                connection.resolve_lease(lease.token)
                return True
            except LeaseError:
                return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(consume, range(16))) == 1
    row = vault._conn.execute(
        "SELECT uses,typeof(uses) FROM leases WHERE id=?", (lease.id,)
    ).fetchone()
    assert tuple(row) == (MAX_LEASE_USES, "integer")


def test_lease_expiring_while_waiting_for_writer_is_rejected(vault, monkeypatch):
    lease = vault.issue_lease("work", ttl=0.3)
    checked = threading.Event()
    original = Lease.ensure_valid

    def check(self):
        original(self)
        checked.set()

    monkeypatch.setattr(Lease, "ensure_valid", check)
    with Vault(state_dir=vault.state_dir, master_key=KEY) as other:
        vault._conn.execute("BEGIN IMMEDIATE")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(other.resolve_lease, lease.token)
            try:
                assert checked.wait(2)
                time.sleep(max(0, lease.expires_at - time.time()) + 0.03)
            finally:
                vault._conn.rollback()
            with pytest.raises(LeaseError, match="expired"):
                future.result(timeout=2)
    assert (
        vault._conn.execute(
            "SELECT uses FROM leases WHERE id=?", (lease.id,)
        ).fetchone()[0]
        == 0
    )


def test_malformed_token_fuzz_never_consumes_a_grant(vault):
    lease = vault.issue_lease("work")
    rng = random.Random(20261103)
    alphabet = "abc0123._-\x00\n\u2603\ud800"
    samples = [None, 123, [], {}, "btn_" + "x" * 5000]
    samples += [
        "btn_" + "".join(rng.choices(alphabet, k=rng.randrange(1, 300)))
        for _ in range(1000)
    ]
    samples += [
        lease.token[:-1] + "\u2603",
        lease.token.replace("btn_", ""),
        " " + lease.token,
    ]
    for token in samples:
        with pytest.raises(LeaseError):
            vault.resolve_lease(token)
        with pytest.raises(LeaseError):
            delegation.resolve(vault, token, "alice")
    assert (
        vault._conn.execute(
            "SELECT uses FROM leases WHERE id=?", (lease.id,)
        ).fetchone()[0]
        == 0
    )


@pytest.mark.parametrize(
    "payload", [None, [], "id", {"i": []}, {"i": 123}, {"i": ""}, {}]
)
def test_signed_malformed_payload_is_a_lease_error(vault, payload):
    body = crypto.b64u_encode(json.dumps(payload).encode())
    token = f"btn_{body}.{vault._sign(body)}"
    with pytest.raises(LeaseError):
        vault.resolve_lease(token)


def test_signed_token_must_match_the_stored_grant(vault):
    lease = vault.issue_lease("work")
    body = crypto.b64u_encode(json.dumps({"i": lease.id, "n": "different"}).encode())
    token = f"btn_{body}.{vault._sign(body)}"
    with pytest.raises(LeaseError, match="stored grant"):
        vault.resolve_lease(token)
    assert vault.resolve_lease(lease.token).uses == 1


@pytest.mark.parametrize("expiry", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_expiry_fails_closed(expiry):
    with pytest.raises(LeaseError):
        Lease(context="work", subject="test", issued_at=0, ttl=expiry).ensure_valid()
