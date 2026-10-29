"""Portable stdio MCP configuration for agent clients."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from .models import BatonError
from .vault import default_state_dir


def mcp_entry(state_dir: str | None = None) -> dict[str, Any]:
    """Use the Python environment that is running baton, not a PATH guess."""
    vault_dir = Path(state_dir).expanduser() if state_dir else default_state_dir()
    return {
        "command": sys.executable,
        "args": ["-m", "baton_auth.mcp_server"],
        "env": {"BATON_STATE_DIR": str(vault_dir.resolve())},
    }


def mcp_config(state_dir: str | None = None, root: str = "mcpServers") -> dict[str, Any]:
    if root not in {"mcpServers", "servers"}:
        raise BatonError(f"unsupported MCP config root {root!r}")
    entry = mcp_entry(state_dir)
    if root == "servers":
        entry = {"type": "stdio", **entry}
    return {root: {"baton": entry}}


def client_command(client: str, state_dir: str | None = None) -> list[str]:
    """Use a client's own CLI for formats that are not JSON."""
    entry = mcp_entry(state_dir)
    state_arg = f"BATON_STATE_DIR={entry['env']['BATON_STATE_DIR']}"
    if client == "codex":
        return [
            "codex", "mcp", "add", "baton", "--env", state_arg, "--",
            entry["command"], *entry["args"],
        ]
    if client == "claude-code":
        return [
            "claude", "mcp", "add", "--env", state_arg, "--transport", "stdio",
            "--scope", "user", "baton", "--", entry["command"], *entry["args"],
        ]
    raise BatonError(f"unsupported agent client {client!r}")


def write_mcp_config(path: str | Path, config: dict[str, Any]) -> Path:
    """Merge baton into an existing JSON config without deleting other servers."""
    target = Path(path).expanduser()
    root = next(iter(config))
    if target.exists():
        try:
            current = json.loads(target.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise BatonError(f"cannot read JSON config {target}: {exc}") from exc
        if not isinstance(current, dict):
            raise BatonError(f"JSON config {target} must be an object")
    else:
        current = {}
    servers = current.get(root, {})
    if not isinstance(servers, dict):
        raise BatonError(f"{root} in {target} must be an object")
    current[root] = {**servers, **config[root]}
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    except OSError as exc:
        raise BatonError(f"cannot write JSON config {target}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(current, stream, indent=2)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except OSError as exc:
        raise BatonError(f"cannot write JSON config {target}: {exc}") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target
