import base64
import os
import sys

import pytest

from baton_auth.cli import build_parser, main
from baton_auth.vault import Vault


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BATON_MASTER_KEY", _key())
    monkeypatch.delenv("BATON_STATE_DIR", raising=False)
    return tmp_path / "state"


def test_parser_has_no_conflicting_options():
    # Only list commands expose the JSON option they implement.
    parser = build_parser()
    for argv in (
        ["status"],
        ["cred", "list"],
        ["ctx", "list"],
        ["lease", "list"],
        ["http", "ctx", "https://example.com", "--body", "{}"],
        ["cred", "list", "--json"],
        ["ctx", "list", "--json"],
        ["lease", "list", "--json"],
    ):
        assert parser.parse_args(argv) is not None


def test_status_and_lists(env, capsys):
    assert main(["status", "--state-dir", str(env)]) == 0
    assert main(["cred", "list", "--state-dir", str(env)]) == 0
    assert main(["ctx", "list", "--state-dir", str(env)]) == 0
    out = capsys.readouterr().out
    assert "blake3" in out


def test_cred_add_ctx_and_run(env, capsys):
    token = "ghp_" + "Q" * 36
    assert (
        main(
            [
                "cred",
                "add",
                "gh",
                "--provider",
                "github",
                "--field",
                f"token={token}",
                "--state-dir",
                str(env),
            ]
        )
        == 0
    )
    assert main(["ctx", "add", "work", "--cred", "gh", "--state-dir", str(env)]) == 0

    code = main(
        ["run", "--state-dir", str(env), "work", "--", "sh", "-c", "echo $GH_TOKEN"]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert token not in out
    assert "«baton:redacted»" in out


def test_lease_new_roundtrip(env, capsys):
    main(
        [
            "cred", "add", "gh", "--provider", "github", "--field", "token=ghp_" + "w" * 36,
            "--state-dir", str(env),
        ]
    )
    main(["ctx", "add", "work", "--cred", "gh", "--state-dir", str(env)])
    capsys.readouterr()
    assert main(["lease", "new", "work", "--ttl", "60", "--state-dir", str(env)]) == 0
    token = capsys.readouterr().out.strip()
    assert token.startswith("btn_")


def test_audit_reports_intact_chain(env, capsys):
    main(["status", "--state-dir", str(env)])
    assert main(["audit", "--state-dir", str(env)]) == 0
    assert "intact" in capsys.readouterr().out


def test_run_preserves_child_argument_separator(env, capsys):
    assert main([
        "cred", "add", "api", "--provider", "generic",
        "--field", "token=sample_token_12345", "--state-dir", str(env),
    ]) == 0
    assert main(["ctx", "add", "work", "--cred", "api", "--state-dir", str(env)]) == 0
    capsys.readouterr()

    assert main([
        "run", "--state-dir", str(env), "work", "--",
        sys.executable, "-c", "import sys; print(sys.argv[1:])", "--", "tail",
    ]) == 0
    assert "['--', 'tail']" in capsys.readouterr().out


def test_http_invalid_json_has_friendly_error(env, capsys):
    assert main([
        "http", "missing", "https://example.com", "--body", "{",
        "--state-dir", str(env),
    ]) == 1
    err = capsys.readouterr().err
    assert "--body must be valid JSON" in err
    assert "Traceback" not in err


def test_refresh_flags_store_secrets_in_encrypted_payload(env):
    client_secret = "client_secret_sample_12345"
    refresh_token = "refresh_token_sample_12345"
    assert main([
        "cred", "add", "api", "--provider", "generic",
        "--field", "token=sample_token_12345",
        "--refresh-provider", "oauth2",
        "--refresh-token-url", "https://auth.example.com/token",
        "--refresh-client-secret", client_secret,
        "--refresh-token", refresh_token,
        "--state-dir", str(env),
    ]) == 0
    with Vault(state_dir=env) as vault:
        row = vault.get_credential_row("api")
        assert client_secret not in row["meta"]
        assert refresh_token not in row["meta"]
        cred = vault.get_credential("api")
        assert cred.secret["client_secret"] == client_secret
        assert cred.secret["refresh_token"] == refresh_token
