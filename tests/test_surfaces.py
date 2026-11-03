import asyncio
import json
import os
import sys
import threading
import time
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


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups")
@pytest.mark.parametrize("parent_waits", [False, True])
def test_run_timeout_stops_descendants_before_cleanup(vault, tmp_path, parent_waits):
    marker = tmp_path / "child-survived"
    child = (
        "import os, time; from pathlib import Path; "
        "print(os.environ['GH_TOKEN'], flush=True); "
        f"time.sleep(2); Path({str(marker)!r}).write_text('survived')"
    )
    parent = (
        "import subprocess, sys, time; "
        f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
        + ("time.sleep(10)" if parent_waits else "pass")
    )

    result = runner.run(vault, "ghctx", [sys.executable, "-c", parent], timeout=1)

    assert result.timed_out
    assert result.exit_code < 0
    assert "«baton:redacted»" in result.stdout
    assert GH_TOKEN not in result.stdout
    time.sleep(2)
    assert not marker.exists(), "a descendant kept running after the timeout"
    assert not list((vault.state_dir / "run").iterdir())


@pytest.mark.parametrize("timeout", [None, 1])
def test_run_keeps_and_redacts_non_utf8_output(vault, timeout):
    command = (
        "import os, time; "
        "os.write(1, b'\\xff' + os.environ['GH_TOKEN'].encode() + b'\\n'); "
        "os.write(2, b'\\xfe' + os.environ['GH_TOKEN'].encode() + b'\\n'); "
        + ("time.sleep(3)" if timeout else "pass")
    )

    result = runner.run(vault, "ghctx", [sys.executable, "-c", command], timeout=timeout)

    assert result.timed_out == (timeout is not None)
    assert result.stdout == "\ufffd«baton:redacted»\n"
    assert result.stderr == "\ufffd«baton:redacted»\n"
    assert result.redactions == 2
    assert GH_TOKEN not in json.dumps(result.as_dict())
    assert not list((vault.state_dir / "run").iterdir())


def test_run_redacts_returned_arguments_without_changing_the_command(vault):
    command = [
        sys.executable, "-c",
        "import os, sys; print(sys.argv[1] == os.environ['GH_TOKEN'])", GH_TOKEN,
    ]

    result = runner.run(vault, "ghctx", command)

    assert result.exit_code == 0
    assert result.stdout == "True\n"
    assert command[-1] == GH_TOKEN
    assert result.argv[-1] == "«baton:redacted»"
    assert result.redactions == 1
    assert GH_TOKEN not in json.dumps(result.as_dict())


@pytest.mark.parametrize("failure", ["missing-command", "permission", "missing-cwd"])
def test_run_redacts_launch_errors_and_cleans_up(vault, tmp_path, failure):
    secret_path = tmp_path / GH_TOKEN
    command = [str(secret_path)]
    cwd = None
    if failure == "permission":
        secret_path.write_text("not executable")
    elif failure == "missing-cwd":
        command = [sys.executable, "-c", "pass"]
        cwd = str(secret_path)

    with pytest.raises(runner.RunError) as caught:
        runner.run(vault, "ghctx", command, cwd=cwd)

    assert GH_TOKEN not in str(caught.value)
    assert "«baton:redacted»" in str(caught.value)
    assert not list((vault.state_dir / "run").iterdir())


def test_run_redacts_executable_paths_in_audit(vault, tmp_path):
    executable = tmp_path / GH_TOKEN
    executable.write_text("#!/bin/sh\nprintf 'done\\n'\n")
    executable.chmod(0o700)

    result = runner.run(vault, "ghctx", [str(executable)])

    assert result.exit_code == 0
    assert result.stdout == "done\n"
    assert GH_TOKEN not in json.dumps(vault.audit_tail(10))


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


def test_run_preserves_caller_cwd_and_validates_explicit_cwd(vault, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    result = runner.run(
        vault,
        "ghctx",
        ["sh", "-c", "pwd; echo $HOME"],
        cwd=str(project),
    )
    lines = result.stdout.strip().splitlines()
    assert Path(lines[0]).resolve() == project.resolve()
    assert Path(lines[1]).resolve() != project.resolve()

    with pytest.raises(runner.RunError, match="working directory not found"):
        runner.run(vault, "ghctx", ["true"], cwd=str(tmp_path / "missing-dir"))


def test_direct_credential_target_and_default_resolution(tmp_path, echo_server):
    v = Vault(master_key=KEY, state_dir=tmp_path / "solo-state")
    try:
        v.put_credential(build_credential("github", "github", {"token": GH_TOKEN}))
        # No context created: credential name works directly for run, http, and lease
        res = runner.run(v, "github", ["sh", "-c", "test -n \"$GH_TOKEN\" && echo ok"])
        assert res.exit_code == 0 and "ok" in res.stdout

        # Omitted target resolves the sole credential automatically
        res_default = runner.run(v, None, ["sh", "-c", "test -n \"$GH_TOKEN\" && echo solo_ok"])
        assert res_default.exit_code == 0 and "solo_ok" in res_default.stdout

        resp = broker.request(v, "github", "GET", echo_server)
        assert resp.status == 200

        lease = v.issue_lease("github", "agent", ttl=60)
        res_lease = runner.run(v, lease.token, ["sh", "-c", "echo lease_ok"])
        assert res_lease.exit_code == 0 and "lease_ok" in res_lease.stdout
    finally:
        v.close()


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


def test_mcp_lease_then_run_roundtrip(vault, tmp_path):
    server = build(vault)
    lease = _payload(
        asyncio.run(server.call_tool("baton_lease", {"context": "ghctx", "ttl_seconds": 60}))
    )
    result = _payload(
        asyncio.run(
            server.call_tool(
                "baton_run",
                {
                    "lease_or_context": lease["token"],
                    "argv": ["sh", "-c", "cat; pwd; echo $GH_TOKEN"],
                    "cwd": str(tmp_path),
                    "stdin": "hello-stdin\n",
                },
            )
        )
    )
    assert result["exit_code"] == 0
    assert "hello-stdin" in result["stdout"]
    assert str(tmp_path.resolve()) in result["stdout"]
    assert GH_TOKEN not in result["stdout"]


def test_mcp_run_redacts_command_metadata(vault):
    server = build(vault)
    result = _payload(asyncio.run(server.call_tool("baton_run", {
        "lease_or_context": "ghctx",
        "argv": [sys.executable, "-c", "pass", GH_TOKEN],
    })))

    assert result["exit_code"] == 0
    assert result["argv"][-1] == "«baton:redacted»"
    assert GH_TOKEN not in json.dumps(result)


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
