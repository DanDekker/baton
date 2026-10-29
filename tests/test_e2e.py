import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from baton_auth.catalog import build_credential
from baton_auth.models import Context
from baton_auth.runner import run
from baton_auth.vault import Vault

MARK = "\u00abbaton:redacted\u00bb"
TOKEN = "ghp_" + "Z" * 36
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture()
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("BATON_STATE_DIR", str(tmp_path / "state"))
    v = Vault(master_key=b"k" * 32, state_dir=tmp_path / "state")
    v.put_credential(build_credential("gh", "github", {"token": TOKEN}))
    v.put_context(Context(name="work", credentials=["gh"]))
    yield v
    v.close()


def test_redaction_marker_shape(vault):
    """The marker must replace the value in place, not eat the line."""
    result = run(vault, "work", ["sh", "-c", "echo $GH_TOKEN; echo NEXT_LINE"])
    assert TOKEN not in result.stdout
    assert MARK in result.stdout
    assert result.stdout.count("\n") == 2
    assert result.stdout.endswith("NEXT_LINE\n")
    assert result.redactions == 1


def test_materialized_file_is_redacted_on_read(vault):
    result = run(vault, "work", ["sh", "-c", "cat ~/.config/gh/hosts.yml"])
    assert TOKEN not in result.stdout
    assert MARK in result.stdout
    assert "git_protocol: https" in result.stdout


def test_child_receives_the_credential(vault):
    """Redaction must not be achieved by withholding the secret from the child."""
    result = run(vault, "work", ["sh", "-c", "test -n \"$GH_TOKEN\" && echo present"])
    assert result.stdout.strip() == "present"


def _server_env(tmp_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["BATON_MASTER_KEY"] = base64.urlsafe_b64encode(b"k" * 32).decode().rstrip("=")
    env["BATON_STATE_DIR"] = str(tmp_path / "mcp-state")
    env["PYTHONPATH"] = str(ROOT / "src")
    return env


def test_mcp_stdio_handshake_and_tool_list(tmp_path):
    env = _server_env(tmp_path)
    # Provision the vault the server will open.
    v = Vault(master_key=b"k" * 32, state_dir=tmp_path / "mcp-state")
    v.put_credential(build_credential("gh", "github", {"token": TOKEN}))
    v.put_context(Context(name="work", credentials=["gh"]))
    v.close()

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "probe", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "baton_credentials", "arguments": {}},
        },
    ]
    stdin = "\n".join(json.dumps(r) for r in requests) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "baton_auth.mcp_server"],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        cwd=ROOT,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr

    messages = []
    for line in proc.stdout.splitlines():
        if line.strip():
            messages.append(json.loads(line))

    assert messages[0]["result"]["serverInfo"]["name"] == "baton"
    tools = {t["name"] for m in messages if "tools" in m.get("result", {}) for t in m["result"]["tools"]}
    assert "baton_run" in tools and "baton_lease" in tools

    payload = json.dumps(messages)
    assert TOKEN not in payload, "MCP surface must never carry a credential value"
    assert TOKEN not in proc.stderr
