"""A broker and two independently running MCP harnesses, with separate identities."""

import asyncio
import base64
from contextlib import AsyncExitStack
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from baton_auth import identity
from baton_auth.catalog import build_credential
from baton_auth.models import Context
from baton_auth.vault import Vault


def test_separate_process_handoff_without_sharing_vault_or_keys(tmp_path):
    root = Path(__file__).resolve().parents[1]
    state = tmp_path / "broker"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    endpoint = f"https://127.0.0.1:{port}"
    with Vault(state, master_key=b"k" * 32) as vault:
        vault.put_credential(build_credential("gh", "github", {"token": "ghp_" + "Z" * 36}))
        vault.put_context(Context("work", credentials=["gh"]))
        for name in ("builder", "reviewer"):
            request = identity.init_agent(name, tmp_path / name)
            bundle = identity.trust_agent(vault, request, endpoint)
            identity.connect(bundle, tmp_path / name)
        lease = vault.issue_lease("work", recipient="builder", ttl=120, max_uses=5, delegatable=True)

    client_env = {k: v for k, v in os.environ.items() if k not in {"BATON_MASTER_KEY", "BATON_PASSPHRASE", "BATON_STATE_DIR"}}
    client_env["PYTHONPATH"] = str(root / "src")
    broker_env = {**client_env, "BATON_MASTER_KEY": base64.urlsafe_b64encode(b"k" * 32).decode()}
    process = subprocess.Popen(
        [sys.executable, "-m", "baton_auth", "serve", "--state-dir", str(state),
         "--url", endpoint, "--port", str(port)],
        env=broker_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                assert process.poll() is None, process.communicate()
                assert time.monotonic() < deadline, "broker did not start"
                time.sleep(0.05)

        async def exercise():
            async with AsyncExitStack() as stack:
                sessions = {}
                for name in ("builder", "reviewer"):
                    streams = await stack.enter_async_context(stdio_client(StdioServerParameters(
                        command=sys.executable,
                        args=["-m", "baton_auth.remote_mcp", "--state-dir", str(tmp_path / name)],
                        env=client_env,
                    )))
                    session = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
                    await session.initialize()
                    sessions[name] = session

                async def call(who, tool, **args):
                    result = await sessions[who].call_tool(tool, args)
                    assert not result.is_error, result
                    return json.loads(result.content[0].text)

                inbox = await call("builder", "baton_inbox")
                assert inbox["leases"][0]["id"] == lease.id
                await call("builder", "baton_accept", lease=lease.id)
                child = await call("builder", "baton_delegate", lease=lease.id, recipient="reviewer",
                                   summary="Review this task", artifacts=["pr:42"], max_uses=2)
                inbox = await call("reviewer", "baton_inbox")
                assert inbox["leases"][0]["task"]["artifacts"] == ["pr:42"]
                await call("reviewer", "baton_accept", lease=child["id"])
                refused = await sessions["builder"].call_tool("baton_accept", {"lease": child["id"]})
                assert refused.is_error
                await call("builder", "baton_revoke", lease=lease.id, child_id=child["id"])
                assert await call("reviewer", "baton_inbox") == {"leases": []}

        asyncio.run(asyncio.wait_for(exercise(), timeout=45))
        for name in ("builder", "reviewer"):
            assert not (tmp_path / name / "baton.db").exists()
            assert not (tmp_path / name / "master.key").exists()
        assert (tmp_path / "builder/identity.key").read_bytes() != (tmp_path / "reviewer/identity.key").read_bytes()
        with Vault(state, master_key=b"k" * 32) as vault:
            assert vault.verify_audit()[0]
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
