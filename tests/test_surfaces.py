import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from baton_auth import broker, runner
from baton_auth.catalog import build_credential
from baton_auth.mcp_server import build
from baton_auth.models import Context, LeaseError
from baton_auth.vault import Vault

KEY = b"k" * 32
GH_TOKEN = "ghp_" + "x" * 36
AWS_SECRET = "s" * 40


@pytest.fixture()
def vault(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    v.put_credential(build_credential("gh", "github", {"token": GH_TOKEN}))
    v.put_credential(
        build_credential(
            "aws",
            "aws",
            {"access_key_id": "AKIA" + "Q" * 16, "secret_access_key": AWS_SECRET},
        )
    )
    v.put_context(Context(name="ghctx", credentials=["gh"]))
    v.put_context(Context(name="awsctx", credentials=["aws"]))
    yield v
    v.close()


# ------------------------------------------------------------------ runner
def test_run_redacts_and_isolates(vault):
    result = runner.run(vault, "ghctx", ["sh", "-c", "echo $GH_TOKEN; echo $HOME"])
    assert GH_TOKEN not in result.stdout
    assert "«baton:redacted»" in result.stdout
    assert result.redactions >= 1

    home = result.stdout.strip().splitlines()[-1]
    assert "run/ghctx-" in home
    assert not Path(home).exists(), "sandbox home must not survive the run"


def test_run_does_not_inherit_other_contexts(vault):
    result = runner.run(
        vault,
        "ghctx",
        ["sh", "-c", "echo ${AWS_SECRET_ACCESS_KEY:-absent}"],
    )
    assert result.stdout.strip() == "absent"


def test_run_timeout_kills_child(vault):
    result = runner.run(vault, "ghctx", ["sh", "-c", "sleep 5"], timeout=0.3)
    assert result.timed_out is True
    assert result.exit_code < 0


def test_run_honours_lease_service_scope(vault):
    lease = vault.issue_lease("ghctx", "agent", services=["aws"], ttl=60)
    with pytest.raises(LeaseError, match="does not grant"):
        runner.run(vault, lease.token, ["true"], service="github")


def test_run_with_lease_token_works(vault):
    lease = vault.issue_lease("ghctx", "agent", services=["github"], ttl=60)
    result = runner.run(vault, lease.token, ["sh", "-c", "echo ok"], service="github")
    assert result.exit_code == 0 and result.lease_id == lease.id


def test_run_audits(vault):
    runner.run(vault, "ghctx", ["true"])
    assert any(e["action"] == "run" for e in vault.audit_tail(10))


# ------------------------------------------------------------------ broker
class _EchoHeaders(BaseHTTPRequestHandler):
    seen: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802
        _EchoHeaders.seen["authorization"] = self.headers.get("Authorization", "")
        body = json.dumps({"auth": self.headers.get("Authorization", "")}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture()
def echo_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHeaders)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/probe"
    server.shutdown()
    server.server_close()


def test_broker_attaches_bearer_and_redacts_echo(vault, echo_server):
    resp = broker.request(vault, "ghctx", "GET", echo_server)
    assert resp.status == 200
    assert _EchoHeaders.seen["authorization"] == f"Bearer {GH_TOKEN}"
    assert GH_TOKEN not in resp.body, "echoed token must be scrubbed before return"
    assert resp.redactions >= 1


def test_broker_audits_request(vault, echo_server):
    broker.request(vault, "ghctx", "GET", echo_server)
    assert any(e["action"] == "http" for e in vault.audit_tail(10))


def test_sigv4_authorization_shape(vault):
    cred = vault.get_credential("aws")
    headers, _ = broker.attach_auth(cred, "GET", "https://example.com/x?a=1", {}, b"")
    auth = headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIA")
    assert "SignedHeaders=" in auth and "Signature=" in auth
    assert "us-east-1" in auth


def test_pick_credential_requires_service_when_ambiguous(vault):
    vault.put_credential(build_credential("gh2", "github", {"token": "ghp_" + "y" * 36}))
    vault.put_context(Context(name="both", credentials=["gh", "gh2"]))
    with pytest.raises(broker.BrokerError, match="several credentials"):
        broker.request(vault, "both", "GET", "http://127.0.0.1:1/x")


# --------------------------------------------------------------------- mcp
def _payload(result: object) -> dict:
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    structured = getattr(result, "structured_content", None)
    if structured:
        return structured
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            return json.loads(text)
    raise AssertionError(f"no payload in {result!r}")


def test_mcp_exposes_tools_without_secrets(vault):
    ctx = vault.get_context("ghctx")
    ctx.env["PRIVATE_VALUE"] = "literal_context_secret_12345"
    vault.put_context(ctx)
    server = build(vault)
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert {
        "baton_contexts",
        "baton_credentials",
        "baton_lease",
        "baton_run",
        "baton_http",
        "baton_audit",
        "baton_revoke",
    } <= names

    for tool in ("baton_info", "baton_contexts", "baton_credentials"):
        text = json.dumps(_payload(asyncio.run(server.call_tool(tool, {}))))
        assert GH_TOKEN not in text
        assert AWS_SECRET not in text
        assert "literal_context_secret_12345" not in text

    info = _payload(asyncio.run(server.call_tool("baton_info", {})))
    assert info["custom_providers"] is True


def test_mcp_lease_then_run_roundtrip(vault):
    server = build(vault)
    lease = _payload(
        asyncio.run(server.call_tool("baton_lease", {"context": "ghctx", "ttl_seconds": 60}))
    )
    result = _payload(
        asyncio.run(
            server.call_tool(
                "baton_run", {"lease_or_context": lease["token"], "argv": ["sh", "-c", "echo $GH_TOKEN"]}
            )
        )
    )
    assert result["exit_code"] == 0
    assert GH_TOKEN not in result["stdout"]


def test_mcp_revoke_blocks_further_use(vault):
    server = build(vault)
    lease = _payload(
        asyncio.run(server.call_tool("baton_lease", {"context": "ghctx", "ttl_seconds": 60}))
    )
    asyncio.run(server.call_tool("baton_revoke", {"lease_id": lease["id"]}))
    with pytest.raises(Exception, match="revoked"):
        asyncio.run(
            server.call_tool(
                "baton_run", {"lease_or_context": lease["token"], "argv": ["true"]}
            )
        )
