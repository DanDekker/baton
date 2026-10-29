import asyncio
import base64
import json
import os
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
import pytest

from baton_auth.catalog import build_credential
from baton_auth.integration import mcp_config
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
    env["PYTHONPATH"] = str(ROOT / "src")
    return env


def test_mcp_stdio_handshake_and_tool_list(tmp_path):
    env = _server_env(tmp_path)
    entry = mcp_config(str(tmp_path / "mcp-state"))["mcpServers"]["baton"]
    # Provision the vault the server will open.
    v = Vault(master_key=b"k" * 32, state_dir=tmp_path / "mcp-state")
    v.put_credential(build_credential("gh", "github", {"token": TOKEN}))
    v.put_context(Context(name="work", credentials=["gh"]))
    v.close()

    stderr_path = tmp_path / "mcp-stderr.log"

    async def exercise():
        # Complete initialization before sending tool requests, and keep stdin
        # open until their responses arrive. EOF can cancel unfinished work.
        with stderr_path.open("w", encoding="utf-8") as errlog:
            async with stdio_client(StdioServerParameters(
                command=entry["command"], args=entry["args"], cwd=ROOT,
                env={**env, **entry["env"]},
            ), errlog=errlog) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    initialized = await session.initialize()
                    assert initialized.server_info.name == "baton"
                    listed = await session.list_tools()
                    names = {tool.name for tool in listed.tools}
                    assert {"baton_run", "baton_lease"} <= names
                    credentials = await session.call_tool("baton_credentials", {})
                    assert not credentials.is_error, credentials
                    metadata = json.loads(credentials.content[0].text)
                    assert metadata["credentials"][0]["name"] == "gh"
                    payload = "\n".join(result.model_dump_json() for result in (
                        initialized, listed, credentials,
                    ))
                    assert TOKEN not in payload, "MCP surface must never carry a credential value"

    asyncio.run(asyncio.wait_for(exercise(), timeout=60))
    assert TOKEN not in stderr_path.read_text()
