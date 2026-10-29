import concurrent.futures
import os
import sys

import pytest

from baton_auth import crypto, runner
from baton_auth.catalog import build_credential
from baton_auth.models import Context, LeaseError
from baton_auth.redact import Redactor
from baton_auth.vault import Vault

KEY = b"k" * 32


@pytest.fixture()
def vault(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    yield v
    v.close()


# ------------------------------------------------------------- zeroization
def test_zeroize_memoryview_and_bytearray():
    buf = bytearray(b"super_secret_payload_12345678")
    crypto.zeroize(buf)
    assert buf == bytearray(len(buf))

    buf2 = bytearray(b"another_secret_key_material_99")
    mv = memoryview(buf2)
    crypto.zeroize(mv)
    assert buf2 == bytearray(len(buf2))

    # Calling zeroize on immutable bytes does not crash
    crypto.zeroize(b"immutable")  # type: ignore[arg-type]


def test_vault_memory_zeroization_on_close(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    assert any(b != 0 for b in v._master)
    assert any(b != 0 for b in v._k_storage)
    assert any(b != 0 for b in v._k_lease)

    v.close()
    assert all(b == 0 for b in v._master)
    assert all(b == 0 for b in v._k_storage)
    assert all(b == 0 for b in v._k_lease)
    assert all(b == 0 for b in v._k_audit)
    assert all(b == 0 for b in v._k_commit)


# ----------------------------------------------------------- SQLite WAL mode
def test_sqlite_wal_mode_enabled(vault):
    row = vault._conn.execute("PRAGMA journal_mode;").fetchone()
    assert row[0].lower() == "wal"

    row = vault._conn.execute("PRAGMA synchronous;").fetchone()
    # NORMAL synchronous is 1
    assert row[0] in (1, "1", "NORMAL", "normal")


# ----------------------------------------------- race-free atomic lease uses
def test_concurrent_lease_consumption_race_free(vault):
    cred = build_credential("k", "generic", {"token": "secret_token_12345"})
    vault.put_credential(cred)
    vault.put_context(Context(name="work", credentials=["k"]))

    lease = vault.issue_lease("work", subject="concurrency_test", max_uses=5)

    successes = 0
    failures = 0

    def worker():
        try:
            vault.resolve_lease(lease.token, consume=True)
            return True
        except LeaseError:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker) for _ in range(15)]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                successes += 1
            else:
                failures += 1

    assert successes == 5
    assert failures == 10

    # Ensure DB record reflects exactly max_uses
    row = vault._conn.execute("SELECT uses FROM leases WHERE id=?", (lease.id,)).fetchone()
    assert row["uses"] == 5


# ---------------------------------------------- expanded redactor patterns
def test_redactor_expanded_patterns():
    redactor = Redactor(["known_literal_secret_value"])

    text = (
        "Here are keys: github_pat_11AAAAAAA0000000000000000000000000000000000000000000000000000000000000000000000000 "
        "and sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl "
        "and sk-proj-123456789012345678901234567890123456789012345678 "
        "and hf_0123456789abcdef0123456789abcdef01 "
        "and sk_" + "live_0123456789abcdef01234567 "
        "and -----BEGIN OPENSSH PRIVATE KEY----- "
        "and known_literal_secret_value"
    )

    scrubbed, count = redactor.redact_counted(text)
    assert count >= 7
    assert "github_pat_" not in scrubbed
    assert "sk-ant-api03-" not in scrubbed
    assert "sk-proj-" not in scrubbed
    assert "hf_" not in scrubbed
    assert "sk_live_" not in scrubbed
    assert "OPENSSH PRIVATE KEY" not in scrubbed
    assert "known_literal_secret_value" not in scrubbed
    assert "«baton:redacted»" in scrubbed


@pytest.mark.parametrize(
    "token",
    [
        "AKIA" + "A" * 16,
        "github_pat_" + "A" * 82,
        "ghp_" + "A" * 20,
        "glpat-" + "A" * 20,
        "xoxb-" + "A" * 10,
        "sk-proj-" + "A" * 48,
        "sk-" + "A" * 20,
        "sk-ant-api03-" + "A" * 86,
        "sk-ant-" + "A" * 20,
        "AIza" + "A" * 35,
        "hf_" + "A" * 34,
        "sk_live_" + "A" * 24,
        "eyJ" + "A" * 8 + "." + "B" * 8 + "." + "C" * 8,
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
)
def test_redactor_prefix_guards_cover_all_token_shapes(token):
    clean, hits = Redactor().redact_counted(f"before {token} after")
    assert token not in clean
    assert hits == 1


# ---------------------------------------------------- runner env scrubbing
def test_runner_host_env_sanitization(vault, monkeypatch):
    monkeypatch.setenv("LD_PRELOAD", "/malicious/lib.so")
    monkeypatch.setenv("PYTHONPATH", "/malicious/pypath")
    monkeypatch.setenv("NODE_OPTIONS", "--require /evil.js")
    monkeypatch.setenv("BASH_ENV", "/evil.sh")
    monkeypatch.setenv("SAFE_VAR", "keep_me")

    cred = build_credential("k", "generic", {"token": "secret_token_12345"})
    vault.put_credential(cred)
    vault.put_context(Context(name="isolated", credentials=["k"], passthrough=["SAFE_VAR"]))

    # Inspect environment passed into subprocess
    cmd = [
        sys.executable,
        "-c",
        "import os; print('SAFE=' + os.environ.get('SAFE_VAR', 'NONE') + "
        "' LD=' + os.environ.get('LD_PRELOAD', 'NONE') + "
        "' PY=' + os.environ.get('PYTHONPATH', 'NONE'))",
    ]
    res = runner.run(vault, "isolated", cmd)
    assert res.exit_code == 0
    assert "SAFE=keep_me" in res.stdout
    assert "LD=NONE" in res.stdout
    assert "PY=NONE" in res.stdout


def test_scoped_lease_materializes_only_permitted_service(vault):
    gh = build_credential("gh", "github", {"token": "ghp_" + "a" * 36})
    aws = build_credential(
        "aws",
        "aws",
        {"access_key_id": "AKIA" + "B" * 16, "secret_access_key": "s" * 40},
    )
    vault.put_credential(gh)
    vault.put_credential(aws)
    vault.put_context(Context(name="multi", credentials=["gh", "aws"]))

    # Lease restricted to github must not expose AWS credentials in the sandbox
    lease = vault.issue_lease("multi", "agent", services=["github"], ttl=60)
    res = runner.run(
        vault,
        lease.token,
        ["sh", "-c", "test -n \"$GH_TOKEN\" && echo gh_ok; echo aws=${AWS_SECRET_ACCESS_KEY:-absent}"],
    )
    assert res.exit_code == 0
    assert "gh_ok" in res.stdout
    assert "aws=absent" in res.stdout


def test_redactor_catches_url_and_base64_encoded_secrets():
    import base64
    from urllib.parse import quote

    secret = "my_high_entropy_secret_value+123/456="
    r = Redactor([secret])
    b64 = base64.b64encode(secret.encode()).decode()
    url_enc = quote(secret, safe="")
    assert b64 not in r(f"auth: {b64}")
    assert url_enc not in r(f"url: {url_enc}")


def test_materialize_rejects_path_traversal(vault, tmp_path):
    from baton_auth.materialize import FileSpec, MaterializeError, Plan, apply

    bad_plan = Plan(
        context=Context(name="bad"),
        files=[FileSpec(path="../../escape.txt", content="nope")],
    )
    with pytest.raises(MaterializeError, match="unsafe path"):
        apply(bad_plan, tmp_path / "sandbox")
