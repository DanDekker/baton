"""Encrypted credential migration, recovery, and rollback checks."""

import base64
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from baton_auth import crypto
from baton_auth.catalog import build_credential
from baton_auth.models import VaultLocked
from baton_auth.vault import SCHEMA_VERSION, Vault

KEY = b"k" * 32
SECRET = "fake-refresh-secret-123456"


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("BATON_MASTER_KEY", base64.urlsafe_b64encode(KEY).decode())
    with Vault(state_dir=tmp_path / "state", master_key=KEY) as vault:
        yield vault


def _credential(config):
    return build_credential(
        "api",
        "generic",
        {"token": "working-token", "refresh_token": SECRET},
        expires_at=time.time() - 1,
        refresh=config,
    )


def _oauth_config(**extra):
    return {"provider": "oauth2", "token_url": "http://127.0.0.1/token", **extra}


def test_refresh_settings_encrypted_and_roundtrip(vault):
    config = _oauth_config(
        client_secret=SECRET,
        refresh_token="fallback-refresh-secret",
        headers={"X-Api-Key": "header-secret-value"},
        extra_params={"private": "extra-secret-value"},
    )
    vault.put_credential(_credential(config))
    public = json.loads(vault.get_credential_row("api")["meta"])
    assert public["refresh"] == {"provider": "oauth2"}
    assert vault.get_credential("api").refresh == config
    assert vault.list_credentials()[0]["refreshable"] is True
    assert vault.list_credentials()[0]["refresh_provider"] == "oauth2"
    for value in (
        SECRET,
        "fallback-refresh-secret",
        "header-secret-value",
        "extra-secret-value",
    ):
        assert value not in json.dumps(vault.list_credentials())
        assert value not in json.dumps(vault.audit_tail(10))
        for path in vault.state_dir.glob("baton.db*"):
            assert value.encode() not in path.read_bytes()


def _legacy_vault(path):
    """Construct the schema-3 format without relying on the new writer."""
    with Vault(state_dir=path, master_key=KEY) as vault:
        for name in ("a", "b"):
            cred = _credential(_oauth_config(client_secret=SECRET))
            cred.name = cred.id = name
            vault.put_credential(cred)
            row = vault.get_credential_row(name)
            public = json.loads(row["meta"])
            public["refresh"] = cred.refresh
            envelope = crypto.seal(
                vault._k_storage,
                json.dumps(cred.secret).encode(),
                vault._cred_aad(cred.id, cred.name),
                commit_key=vault._k_commit,
            )
            vault._conn.execute(
                "UPDATE credentials SET meta=?,envelope=? WHERE name=?",
                (json.dumps(public), envelope, name),
            )
        vault._set_meta("schema_version", "3")
        vault._conn.execute("DELETE FROM meta WHERE key='key_check'")
        vault._conn.commit()


def test_legacy_migration_is_concurrent_and_idempotent(tmp_path):
    path = tmp_path / "legacy"
    _legacy_vault(path)
    with sqlite3.connect(path / "baton.db") as db:
        before = db.execute(
            "SELECT id,created_at,updated_at FROM credentials ORDER BY id"
        ).fetchall()
        audit = db.execute("SELECT * FROM audit").fetchall()

    def open_vault(_):
        with Vault(state_dir=path, master_key=KEY) as vault:
            for name in ("a", "b"):
                assert vault.get_credential(name).refresh["client_secret"] == SECRET
                assert vault.get_credential(name).secret["token"] == "working-token"
                assert SECRET not in vault.get_credential_row(name)["meta"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(open_vault, range(24)))
    with sqlite3.connect(path / "baton.db") as db:
        assert db.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0] == str(SCHEMA_VERSION)
        assert (
            db.execute(
                "SELECT id,created_at,updated_at FROM credentials ORDER BY id"
            ).fetchall()
            == before
        )
        assert db.execute("SELECT * FROM audit").fetchall() == audit


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_failed_migration_rolls_back_every_record(tmp_path, monkeypatch, failure):
    path = tmp_path / "legacy"
    _legacy_vault(path)
    with sqlite3.connect(path / "baton.db") as db:
        before = db.execute("SELECT * FROM credentials ORDER BY id").fetchall()
    original = Vault._seal_credential

    def fail_second(self, ident, *args):
        if ident == "b":
            raise failure("simulated write failure")
        return original(self, ident, *args)

    with monkeypatch.context() as patch:
        patch.setattr(Vault, "_seal_credential", fail_second)
        with pytest.raises(failure, match="simulated"):
            Vault(state_dir=path, master_key=KEY)
    with sqlite3.connect(path / "baton.db") as db:
        assert db.execute("SELECT * FROM credentials ORDER BY id").fetchall() == before
        assert (
            db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[
                0
            ]
            == "3"
        )
    with Vault(state_dir=path, master_key=KEY) as vault:
        assert vault.get_credential("b").refresh["client_secret"] == SECRET


def test_future_schema_is_not_downgraded(vault):
    vault._set_meta("schema_version", "999")
    with pytest.raises(VaultLocked, match="upgrade"):
        Vault(state_dir=vault.state_dir, master_key=KEY)
    assert vault._get_meta("schema_version") == "999"


def test_repeated_migration_preserves_encrypted_refresh_settings(vault):
    config = _oauth_config(client_secret=SECRET)
    vault.put_credential(_credential(config))
    vault._set_meta("schema_version", "3")
    with Vault(state_dir=vault.state_dir, master_key=KEY) as reopened:
        assert reopened.get_credential("api").refresh == config
        assert reopened.get_credential("api").secret["token"] == "working-token"


def test_wrong_key_does_not_change_legacy_vault(tmp_path):
    path = tmp_path / "legacy"
    _legacy_vault(path)
    with pytest.raises(crypto.CryptoError):
        Vault(state_dir=path, master_key=b"x" * 32)
    with sqlite3.connect(path / "baton.db") as db:
        assert (
            db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[
                0
            ]
            == "3"
        )
    with Vault(state_dir=path, master_key=KEY) as vault:
        assert vault.get_credential("a").refresh["client_secret"] == SECRET


def test_plaintext_metadata_cannot_override_encrypted_refresh(vault):
    config = _oauth_config(client_secret=SECRET)
    vault.put_credential(_credential(config))
    row = vault.get_credential_row("api")
    public = json.loads(row["meta"])
    public["refresh"] = {"provider": "exec", "argv": ["malicious-command"]}
    vault._conn.execute(
        "UPDATE credentials SET meta=? WHERE name='api'", (json.dumps(public),)
    )
    vault._conn.commit()
    assert vault.get_credential("api").refresh == config
