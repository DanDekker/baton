import asyncio
import base64
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from baton_auth import broker, runner
from baton_auth.catalog import build_credential
from baton_auth.cli import main
from baton_auth.mcp_server import build
from baton_auth.models import Context, Credential, RefreshError
from baton_auth.refresh import RefreshResult, register_refresh_provider
from baton_auth.vault import Vault

KEY = b"k" * 32


class _OAuthMockHandler(BaseHTTPRequestHandler):
    requests: list[dict] = []
    fail_next = False

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length).decode()
        auth_hdr = self.headers.get("Authorization", "")

        _OAuthMockHandler.requests.append({
            "path": self.path,
            "body": body,
            "auth": auth_hdr,
        })

        if _OAuthMockHandler.fail_next:
            self.send_response(400)
            self.send_header("content-type", "application/json")
            resp = json.dumps({"error": "invalid_grant", "error_description": "bad refresh token"}).encode()
            self.send_header("content-length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        self.send_response(200)
        self.send_header("content-type", "application/json")
        resp = json.dumps({
            "access_token": "acc_refreshed_999",
            "refresh_token": "ref_rotated_888",
            "expires_in": 3600,
            "token_type": "Bearer",
        }).encode()
        self.send_header("content-length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture()
def oauth_server():
    _OAuthMockHandler.requests = []
    _OAuthMockHandler.fail_next = False
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OAuthMockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/token"
    server.shutdown()
    server.server_close()


@pytest.fixture()
def vault(tmp_path, monkeypatch):
    b64_key = base64.urlsafe_b64encode(KEY).decode().rstrip("=")
    monkeypatch.setenv("BATON_MASTER_KEY", b64_key)
    monkeypatch.setenv("BATON_STATE_DIR", str(tmp_path / "state"))
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    yield v
    v.close()


# --------------------------------------------------------------- oauth2
def test_oauth2_refresh_success_and_rotation(vault, oauth_server):
    cred = build_credential(
        "api",
        "generic",
        {"token": "initial_acc", "refresh_token": "initial_ref"},
        expires_at=time.time() - 10.0,  # expired
        refresh={
            "provider": "oauth2",
            "token_url": oauth_server,
            "client_id": "client_123",
            "client_secret": "secret_abc",
        },
    )
    vault.put_credential(cred)

    refreshed_cred, did_refresh = vault.refresh_credential("api")
    assert did_refresh is True
    assert refreshed_cred.secret["token"] == "acc_refreshed_999"
    assert refreshed_cred.secret["refresh_token"] == "ref_rotated_888"
    assert refreshed_cred.expires_at is not None
    assert refreshed_cred.expires_at > time.time() + 3500

    # Ensure updated secret was persisted in vault
    fetched = vault.get_credential("api", auto_refresh=False)
    assert fetched.secret["token"] == "acc_refreshed_999"
    assert fetched.secret["refresh_token"] == "ref_rotated_888"

    # Verify authorization header sent to token server
    req = _OAuthMockHandler.requests[0]
    expected_basic = base64.b64encode(b"client_123:secret_abc").decode()
    assert req["auth"] == f"Basic {expected_basic}"
    assert "grant_type=refresh_token" in req["body"]
    assert "refresh_token=initial_ref" in req["body"]

    # Verify audit event
    tail = vault.audit_tail(5)
    assert any(e["action"] == "credential.refresh" and e["target"] == "api" for e in tail)


def test_oauth2_refresh_error_handling(vault, oauth_server):
    cred = build_credential(
        "api_fail",
        "generic",
        {"token": "old", "refresh_token": "bad_rt"},
        refresh={"provider": "oauth2", "token_url": oauth_server},
    )
    vault.put_credential(cred)

    _OAuthMockHandler.fail_next = True
    with pytest.raises(RefreshError, match="bad refresh token"):
        vault.refresh_credential("api_fail", force=True)


# ----------------------------------------------------------------- exec
def test_exec_refresh_text_output(vault):
    script = f"{sys.executable} -c 'print(\"fresh_exec_token_456\")'"
    cred = build_credential(
        "cli_cred",
        "generic",
        {"token": "stale"},
        expires_at=time.time() - 5.0,
        refresh={"provider": "exec", "argv": script, "ttl": 1800},
    )
    vault.put_credential(cred)

    refreshed, did = vault.refresh_credential("cli_cred")
    assert did is True
    assert refreshed.secret["token"] == "fresh_exec_token_456"
    assert refreshed.expires_at is not None
    assert refreshed.expires_at > time.time() + 1700


def test_exec_refresh_json_output(vault):
    script = (
        f"{sys.executable} -c 'import json; "
        "print(json.dumps({\"data\": {\"access\": \"tok_json_789\"}, \"expires_in\": 1200}))'"
    )
    cred = build_credential(
        "json_cred",
        "generic",
        {"token": "old"},
        refresh={
            "provider": "exec",
            "argv": script,
            "format": "json",
            "json_path": "data.access",
            "token_field": "token",
        },
    )
    vault.put_credential(cred)

    refreshed, did = vault.refresh_credential("json_cred", force=True)
    assert did is True
    assert refreshed.secret["token"] == "tok_json_789"
    assert refreshed.expires_at is not None
    assert refreshed.expires_at > time.time() + 1100


# --------------------------------------------------------------- custom
def test_custom_refresh_provider_hook(vault):
    def my_custom_hook(cred: Credential, config: dict) -> RefreshResult:
        suffix = config.get("suffix", "custom")
        return RefreshResult(
            secret_updates={"token": f"minted_{suffix}"},
            expires_at=time.time() + 500,
        )

    register_refresh_provider("my_test_hook", my_custom_hook)

    cred = build_credential(
        "custom_cred",
        "generic",
        {"token": "initial"},
        refresh={"provider": "my_test_hook", "suffix": "xyz"},
    )
    vault.put_credential(cred)

    refreshed, did = vault.refresh_credential("custom_cred", force=True)
    assert did is True
    assert refreshed.secret["token"] == "minted_xyz"


# --------------------------------------------- auto-refresh on runner & broker
def test_auto_refresh_on_runner(vault, oauth_server):
    cred = build_credential(
        "auto_gh",
        "github",
        {"token": "ghp_" + "a" * 36, "refresh_token": "rt_initial"},
        expires_at=time.time() - 1.0,  # expired!
        refresh={"provider": "oauth2", "token_url": oauth_server},
    )
    vault.put_credential(cred)
    vault.put_context(Context(name="auto_ctx", credentials=["auto_gh"]))

    # runner runs plan(vault, context) which calls get_credential(auto_refresh=True)
    result = runner.run(vault, "auto_ctx", ["sh", "-c", "echo $GH_TOKEN"])
    assert result.exit_code == 0
    # Child saw the refreshed token (which gets redacted as «baton:redacted»)
    assert "«baton:redacted»" in result.stdout

    # In vault, the token is now the refreshed one
    fresh = vault.get_credential("auto_gh", auto_refresh=False)
    assert fresh.secret["token"] == "acc_refreshed_999"


def test_auto_refresh_on_broker(vault, oauth_server):
    # A second mock server to be the target of the HTTP request
    class _TargetHandler(BaseHTTPRequestHandler):
        last_auth = ""

        def do_GET(self) -> None:  # noqa: N802
            _TargetHandler.last_auth = self.headers.get("Authorization", "")
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b"{\"ok\": true}")

        def log_message(self, *_args: object) -> None:
            return

    target_srv = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
    t = threading.Thread(target=target_srv.serve_forever, daemon=True)
    t.start()
    target_url = f"http://127.0.0.1:{target_srv.server_address[1]}/api"

    cred = build_credential(
        "http_cred",
        "generic",
        {"token": "expired_token", "refresh_token": "rt_initial"},
        expires_at=time.time() - 2.0,
        refresh={"provider": "oauth2", "token_url": oauth_server},
    )
    vault.put_credential(cred)
    vault.put_context(Context(name="http_ctx", credentials=["http_cred"]))

    try:
        resp = broker.request(vault, "http_ctx", "GET", target_url)
        assert resp.status == 200
        assert _TargetHandler.last_auth == "Bearer acc_refreshed_999"
    finally:
        target_srv.shutdown()
        target_srv.server_close()


# ------------------------------------------------------------- CLI and MCP
def test_cli_cred_refresh(vault, oauth_server, capsys):
    cred = build_credential(
        "cli_api",
        "generic",
        {"token": "old", "refresh_token": "rt"},
        refresh={"provider": "oauth2", "token_url": oauth_server},
    )
    vault.put_credential(cred)

    code = main(["cred", "refresh", "cli_api", "--force", "--state-dir", str(vault.state_dir)])
    assert code == 0
    out = capsys.readouterr().out
    assert "refreshed cli_api" in out


def test_mcp_baton_refresh(vault, oauth_server):
    cred = build_credential(
        "mcp_api",
        "generic",
        {"token": "old", "refresh_token": "rt"},
        refresh={"provider": "oauth2", "token_url": oauth_server},
    )
    vault.put_credential(cred)

    server = build(vault)
    payload = asyncio.run(server.call_tool("baton_refresh", {"credential": "mcp_api", "force": True}))

    # Extract structured result
    text = payload.content[0].text if hasattr(payload, "content") else str(payload)
    data = json.loads(text)
    assert data["refreshed"] is True
    assert data["name"] == "mcp_api"
    # Secrets must never appear
    assert "acc_refreshed_999" not in text
    assert "ref_rotated_888" not in text
