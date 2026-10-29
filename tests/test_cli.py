import base64
import json
import os
import sys

import pytest
from ruamel.yaml import YAML

from baton_auth import broker
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
        ["setup"],
        ["setup", "--root", "servers"],
    ):
        assert parser.parse_args(argv) is not None


def test_status_and_lists(env, capsys):
    assert main(["status", "--state-dir", str(env)]) == 0
    assert main(["cred", "list", "--state-dir", str(env)]) == 0
    assert main(["ctx", "list", "--state-dir", str(env)]) == 0
    out = capsys.readouterr().out
    assert "blake3" in out


def test_setup_prints_and_merges_mcp_config_without_opening_vault(env, tmp_path, capsys):
    assert main(["setup", "--state-dir", str(env)]) == 0
    config = json.loads(capsys.readouterr().out)
    entry = config["mcpServers"]["baton"]
    assert entry["command"] == sys.executable
    assert entry["args"] == ["-m", "baton_auth.mcp_server"]
    assert entry["env"]["BATON_STATE_DIR"] == str(env)
    assert not env.exists()

    target = tmp_path / "client" / "mcp.json"
    target.parent.mkdir()
    target.write_text(json.dumps({"mcpServers": {"other": {"command": "other"}}}))
    assert main(["setup", "--output", str(target), "--state-dir", str(env)]) == 0
    assert main(["setup", "--output", str(target), "--state-dir", str(env)]) == 0
    saved = json.loads(target.read_text())
    assert saved["mcpServers"]["other"] == {"command": "other"}
    assert saved["mcpServers"]["baton"] == entry
    assert os.stat(target).st_mode & 0o777 == 0o600

    vscode = tmp_path / "vscode.json"
    assert main(["setup", "--client", "vscode", "--output", str(vscode), "--state-dir", str(env)]) == 0
    assert json.loads(vscode.read_text())["servers"]["baton"] == {"type": "stdio", **entry}


def test_setup_client_commands_use_installed_python(env, monkeypatch):
    calls = []
    monkeypatch.setattr("baton_auth.cli.subprocess.run", lambda cmd, check: calls.append(cmd))
    assert main(["setup", "--client", "codex", "--state-dir", str(env)]) == 0
    assert main(["setup", "--client", "claude-code", "--state-dir", str(env)]) == 0
    assert calls[0] == [
        "codex", "mcp", "add", "baton", "--env", f"BATON_STATE_DIR={env}",
        "--", sys.executable, "-m", "baton_auth.mcp_server",
    ]
    assert calls[1] == [
        "claude", "mcp", "add", "--env", f"BATON_STATE_DIR={env}",
        "--transport", "stdio", "--scope", "user", "baton", "--",
        sys.executable, "-m", "baton_auth.mcp_server",
    ]


def test_muse_code_setup_preserves_settings_and_legacy_key(env, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    target = tmp_path / "xdg" / "muse" / "settings.json"
    assert main(["setup", "--client", "muse-code", "--state-dir", str(env)]) == 0
    data = json.loads(target.read_text())
    assert data["schema_version"] == 1
    assert data["mcpServers"]["baton"]["type"] == "stdio"
    assert data["mcpServers"]["baton"]["env"]["BATON_STATE_DIR"] == str(env)

    target.write_text(json.dumps({
        "schema_version": 1,
        "model": "keep-me",
        "mcp_servers": {
            "other": {"transport": "stdio", "command": "other"},
            "baton": {"env": {"EXTRA": "keep"}},
        },
    }))
    assert main(["setup", "--client", "muse-code", "--state-dir", str(env)]) == 0
    data = json.loads(target.read_text())
    assert data["model"] == "keep-me"
    assert "mcpServers" not in data
    assert data["mcp_servers"]["other"]["command"] == "other"
    assert data["mcp_servers"]["baton"]["transport"] == "stdio"
    assert data["mcp_servers"]["baton"]["env"]["EXTRA"] == "keep"


def test_hermes_agent_setup_preserves_yaml_and_other_servers(env, tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    target = tmp_path / "hermes" / "config.yaml"
    target.parent.mkdir()
    target.write_text(
        "# keep this comment\nmodel: existing\nmcp_servers:\n"
        "  other:\n    command: other\n"
        "  baton:\n    env:\n      EXTRA: keep\n"
    )
    assert main(["setup", "--client", "hermes-agent", "--state-dir", str(env)]) == 0
    saved = target.read_text()
    assert "# keep this comment" in saved
    data = YAML().load(saved)
    assert data["model"] == "existing"
    assert data["mcp_servers"]["other"]["command"] == "other"
    baton = data["mcp_servers"]["baton"]
    assert baton["command"] == sys.executable
    assert baton["args"] == ["-m", "baton_auth.mcp_server"]
    assert baton["env"] == {"EXTRA": "keep", "BATON_STATE_DIR": str(env)}
    assert os.stat(target).st_mode & 0o777 == 0o600


def test_muse_code_refuses_ambiguous_mcp_keys(env, tmp_path, capsys):
    target = tmp_path / "settings.json"
    original = '{"schema_version":1,"mcpServers":{},"mcp_servers":{}}'
    target.write_text(original)
    assert main([
        "setup", "--client", "muse-code", "--output", str(target),
        "--state-dir", str(env),
    ]) == 1
    assert target.read_text() == original
    assert "both Muse MCP keys" in capsys.readouterr().err


def test_custom_provider_auth_and_context(env, capsys):
    assert main([
        "cred", "add", "api", "--provider", "example-api",
        "--field", "api_key=sample_secret_12345", "--auth", "header:x-api-key",
        "--auth-field", "api_key", "--context", "work", "--state-dir", str(env),
    ]) == 0
    assert main([
        "cred", "add", "cli-only", "--provider", "another-api",
        "--field", "secret=sample_secret_67890", "--auth", "none",
        "--env", "EXAMPLE_TOKEN={secret}", "--context", "work", "--state-dir", str(env),
    ]) == 0
    with Vault(state_dir=env) as vault:
        cred = vault.get_credential("api")
        assert cred.provider == "example-api"
        assert cred.auth == {"scheme": "header", "header": "x-api-key", "field": "api_key"}
        headers, _ = broker.attach_auth(cred, "GET", "https://example.com", {}, b"")
        assert headers["x-api-key"] == "sample_secret_12345"
        assert vault.get_context("work").credentials == ["api", "cli-only"]
    assert "sample_secret" not in capsys.readouterr().out


def test_invalid_auth_name_does_not_store_credential(env, capsys):
    assert main([
        "cred", "add", "api", "--provider", "example-api", "--field", "token=secret",
        "--auth", "header:bad\nname", "--state-dir", str(env),
    ]) == 1
    assert "valid name" in capsys.readouterr().err
    with Vault(state_dir=env) as vault:
        assert vault.list_credentials() == []


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


def test_cred_add_reads_piped_stdin_and_field_file_dash(env, monkeypatch):
    from io import StringIO

    class _NonTTY(StringIO):
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(sys, "stdin", _NonTTY("piped_secret_token_12345\n"))
    assert main([
        "cred", "add", "piped", "--provider", "generic",
        "--field", "token", "--state-dir", str(env),
    ]) == 0

    monkeypatch.setattr(sys, "stdin", _NonTTY("multiline_secret_blob\nline2\n"))
    assert main([
        "cred", "add", "from-dash", "--provider", "generic",
        "--field-file", "token=-", "--state-dir", str(env),
    ]) == 0

    with Vault(state_dir=env) as vault:
        assert vault.get_credential("piped").secret["token"] == "piped_secret_token_12345"
        assert vault.get_credential("from-dash").secret["token"] == "multiline_secret_blob\nline2\n"


def test_cli_json_outputs_and_http_headers(env, monkeypatch, capsys):
    import httpx

    assert main(["status", "--json", "--state-dir", str(env)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["hash"] == "blake3"

    assert main(["info", "--json", "--state-dir", str(env)]) == 0
    info = json.loads(capsys.readouterr().out)
    assert "anthropic" in info["presets"]

    assert main([
        "cred", "add", "api", "--provider", "generic",
        "--field", "token=secret_value_12345",
        "--context", "work", "--state-dir", str(env),
    ]) == 0
    capsys.readouterr()

    assert main(["env", "work", "--json", "--state-dir", str(env)]) == 0
    env_data = json.loads(capsys.readouterr().out)
    assert env_data["context"] == "work"

    assert main(["audit", "--json", "--state-dir", str(env)]) == 0
    audit_data = json.loads(capsys.readouterr().out)
    assert audit_data["intact"] is True

    seen_headers = {}

    class _Client:
        def __init__(self, **_kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            pass

        def request(self, _method, _url, **kwargs):
            seen_headers.update(kwargs.get("headers") or {})
            return httpx.Response(200, text='{"ok":true}')

    monkeypatch.setattr(broker.httpx, "Client", _Client)
    assert main([
        "http", "work", "http://127.0.0.1/test",
        "-H", "X-Custom: hello",
        "--json", "--state-dir", str(env),
    ]) == 0
    http_out = json.loads(capsys.readouterr().out)
    assert http_out["status"] == 200
    assert seen_headers["X-Custom"] == "hello"
