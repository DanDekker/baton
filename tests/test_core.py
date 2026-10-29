import json
import os
import time

import pytest

from baton_auth import crypto
from baton_auth.catalog import PresetError, build_credential
from baton_auth.materialize import MaterializeError, apply, plan
from baton_auth.models import Context, Credential, LeaseError
from baton_auth.redact import Redactor
from baton_auth.vault import Vault

KEY = b"k" * 32


@pytest.fixture()
def vault(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    yield v
    v.close()


# --------------------------------------------------------------- crypto
def test_envelope_roundtrip_and_tamper():
    sk = crypto.subkey(KEY, "storage")
    env = crypto.seal(sk, b"secret-bytes", b"aad")
    assert crypto.open_envelope(sk, env, b"aad") == b"secret-bytes"
    assert b"secret-bytes" not in env

    flipped = bytearray(env)
    flipped[-20] ^= 0x01
    with pytest.raises(crypto.CryptoError, match="commitment"):
        crypto.open_envelope(sk, bytes(flipped), b"aad")


def test_envelope_commits_to_key():
    env = crypto.seal(crypto.subkey(KEY, "storage"), b"x", b"aad")
    other = crypto.subkey(b"z" * 32, "storage")
    with pytest.raises(crypto.CryptoError, match="commitment"):
        crypto.open_envelope(other, env, b"aad")


def test_envelope_aad_binding():
    sk = crypto.subkey(KEY, "storage")
    env = crypto.seal(sk, b"x", b"cred:a:name")
    with pytest.raises(crypto.CryptoError):
        crypto.open_envelope(sk, env, b"cred:b:name")


def test_subkeys_are_domain_separated():
    assert crypto.subkey(KEY, "storage") != crypto.subkey(KEY, "lease")
    assert crypto.subkey(KEY, "lease") == crypto.subkey(KEY, "lease")


def test_audit_chain_detects_tamper(vault):
    vault.put_credential(Credential(name="c1", secret={"token": "t" * 20}))
    vault.put_credential(Credential(name="c2", secret={"token": "u" * 20}))
    assert vault.verify_audit() == (True, 0)
    vault._conn.execute("UPDATE audit SET target='rewritten' WHERE seq=1")
    vault._conn.commit()
    ok, seq = vault.verify_audit()
    assert not ok and seq == 1


# ---------------------------------------------------------------- vault
def test_credential_never_plaintext_on_disk(vault):
    secret = "ghp_" + "a" * 36
    vault.put_credential(Credential(name="gh", provider="github", secret={"token": secret}))
    assert vault.get_credential("gh").secret["token"] == secret
    assert secret.encode() not in vault.db_path.read_bytes()


def test_credential_update_keeps_id(vault):
    first = vault.put_credential(Credential(name="gh", secret={"token": "a" * 20}))
    second = vault.put_credential(Credential(name="gh", secret={"token": "b" * 20}))
    assert first.id == second.id
    assert vault.get_credential("gh").secret["token"] == "b" * 20


# --------------------------------------------------------------- leases
def test_lease_ttl_budget_and_revocation(vault):
    vault.put_credential(Credential(name="gh", secret={"token": "a" * 20}))
    vault.put_context(Context(name="work", credentials=["gh"]))

    lease = vault.issue_lease("work", "agent-1", ttl=60, max_uses=2)
    assert vault.resolve_lease(lease.token).context == "work"
    vault.resolve_lease(lease.token)
    with pytest.raises(LeaseError, match="exhausted"):
        vault.resolve_lease(lease.token)

    short = vault.issue_lease("work", "agent-2", ttl=0.05)
    time.sleep(0.06)
    with pytest.raises(LeaseError, match="expired"):
        vault.resolve_lease(short.token)

    revocable = vault.issue_lease("work", "agent-3", ttl=60)
    vault.revoke_lease(revocable.id)
    with pytest.raises(LeaseError, match="revoked"):
        vault.resolve_lease(revocable.token)


def test_lease_forgery_rejected(vault):
    vault.put_credential(Credential(name="gh", secret={"token": "a" * 20}))
    vault.put_context(Context(name="work", credentials=["gh"]))
    lease = vault.issue_lease("work", "agent", ttl=60)
    with pytest.raises(LeaseError, match="signature"):
        vault.resolve_lease(lease.token[:-6] + "AAAAAA")


def test_lease_token_not_stored(vault):
    vault.put_credential(Credential(name="gh", secret={"token": "a" * 20}))
    vault.put_context(Context(name="work", credentials=["gh"]))
    lease = vault.issue_lease("work", "agent", ttl=60)
    assert lease.token.encode() not in vault.db_path.read_bytes()


# ---------------------------------------------------------- materialize
def test_materialize_aws_isolated_home(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    cred = build_credential(
        "aws-prod",
        "aws",
        {"access_key_id": "AKIA" + "Q" * 16, "secret_access_key": "s" * 40, "region": "us-east-1"},
    )
    v.put_credential(cred)
    v.put_context(Context(name="prod", credentials=["aws-prod"]))

    p = plan(v, "prod")
    home = tmp_path / "home"
    env = apply(p, home)

    assert env["AWS_ACCESS_KEY_ID"] == "AKIA" + "Q" * 16
    assert env["AWS_REGION"] == "us-east-1"
    assert env["HOME"] == str(home.resolve())
    creds = (home / ".aws" / "credentials").read_text()
    assert creds.startswith("[default]")
    assert "aws_secret_access_key = " + "s" * 40 in creds
    assert (home / ".aws" / "credentials").stat().st_mode & 0o777 == 0o600


def test_materialize_skips_absent_optional(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    cred = build_credential(
        "aws-ro", "aws", {"access_key_id": "AKIA" + "R" * 16, "secret_access_key": "t" * 40}
    )
    v.put_credential(cred)
    v.put_context(Context(name="ro", credentials=["aws-ro"]))
    env = apply(plan(v, "ro"), tmp_path / "home")
    assert "AWS_SESSION_TOKEN" not in env
    assert "AWS_REGION" not in env
    assert "aws_session_token" not in (tmp_path / "home" / ".aws" / "credentials").read_text()


def test_materialize_github(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    v.put_credential(
        build_credential("gh", "github", {"token": "ghp_" + "x" * 36, "user": "octo"})
    )
    v.put_context(Context(name="gh", credentials=["gh"]))
    env = apply(plan(v, "gh"), tmp_path / "home")
    assert env["GH_TOKEN"].startswith("ghp_")
    hosts = (tmp_path / "home" / ".config" / "gh" / "hosts.yml").read_text()
    assert "oauth_token: ghp_" in hosts and "user: octo" in hosts


def test_gcp_env_gets_absolute_home_path(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    v.put_credential(build_credential("gcp", "gcp", {"service_account_json": '{"type": "service_account"}'}))
    v.put_context(Context(name="gcp", credentials=["gcp"]))
    home = tmp_path / "home"
    env = apply(plan(v, "gcp"), home)
    assert env["GOOGLE_APPLICATION_CREDENTIALS"] == f"{home.resolve()}/.config/gcloud/baton-sa.json"
    assert json.loads((home / ".config/gcloud/baton-sa.json").read_text())["type"] == "service_account"


def test_host_credentials_are_not_inherited(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "host-leak")
    monkeypatch.setenv("GH_TOKEN", "host-leak-2")
    monkeypatch.setenv("PATH", os.environ.get("PATH", "/usr/bin"))
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    v.put_credential(Credential(name="bare", secret={"token": "z" * 20}))
    v.put_context(Context(name="empty", credentials=["bare"]))
    env = apply(plan(v, "empty"), tmp_path / "home")
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GH_TOKEN" not in env
    assert "PATH" in env


def test_passthrough_can_reenable_a_variable(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "sso-dev")
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    v.put_credential(Credential(name="bare", secret={"token": "z" * 20}))
    v.put_context(Context(name="pts", credentials=["bare"], passthrough=["AWS_PROFILE"]))
    assert apply(plan(v, "pts"), tmp_path / "home")["AWS_PROFILE"] == "sso-dev"


def test_missing_field_is_fatal(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    v.put_credential(
        Credential(
            name="broken",
            secret={"token": "a" * 20},
            materialize=[{"kind": "file", "path": ".x", "template": "{missing}"}],
        )
    )
    v.put_context(Context(name="b", credentials=["broken"]))
    with pytest.raises(MaterializeError, match="missing field"):
        plan(v, "b")


# ---------------------------------------------------------------- catalog
def test_catalog_rejects_missing_fields():
    with pytest.raises(PresetError, match="missing required"):
        build_credential("x", "aws", {"access_key_id": "a"})


def test_catalog_rejects_unknown_provider():
    with pytest.raises(PresetError, match="unknown provider"):
        build_credential("x", "nope", {"token": "a"})


def test_docker_preset_builds_auth_blob(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    v.put_credential(
        build_credential("reg", "docker", {"username": "u", "password": "p", "registry": "ghcr.io"})
    )
    v.put_context(Context(name="d", credentials=["reg"]))
    apply(plan(v, "d"), tmp_path / "home")
    cfg = json.loads((tmp_path / "home" / ".docker/config.json").read_text())
    import base64

    assert base64.b64decode(cfg["auths"]["ghcr.io"]["auth"]).decode() == "u:p"


# ---------------------------------------------------------------- redact
def test_redactor_scrubs_known_and_shaped_secrets():
    r = Redactor(["super-secret-value"])
    assert "super-secret-value" not in r("x super-secret-value y")
    assert "ghp_" not in r("token ghp_" + "a" * 36)
    assert "AKIA" not in r("AKIA" + "Q" * 16)
    assert r.redact_obj({"k": "super-secret-value"})["k"] == "«baton:redacted»"
