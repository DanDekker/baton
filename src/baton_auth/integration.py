"""Portable stdio MCP configuration for agent clients."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from io import StringIO
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
    current = _read_json_object(target)
    _merge_server(current, root, config[root]["baton"], target)
    _atomic_write(target, json.dumps(current, indent=2) + "\n")
    return target


def muse_settings_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "muse" / "settings.json"


def write_muse_config(path: str | Path, state_dir: str | None = None) -> Path:
    """Write the Muse Code settings shape, including its required schema version."""
    target = Path(path).expanduser()
    current = _read_json_object(target)
    if "mcpServers" in current and "mcp_servers" in current:
        raise BatonError(f"{target} has both Muse MCP keys; resolve that first")
    if current.get("schema_version", 1) != 1:
        raise BatonError(f"{target} needs Muse schema_version 1")
    current["schema_version"] = 1
    root = "mcp_servers" if "mcp_servers" in current else "mcpServers"
    type_key = "transport" if root == "mcp_servers" else "type"
    entry = {type_key: "stdio", **mcp_entry(state_dir), "enabled": True}
    _merge_server(current, root, entry, target)
    _atomic_write(target, json.dumps(current, indent=2) + "\n")
    return target


def hermes_config_path() -> Path:
    return Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes") / "config.yaml"


def claude_desktop_config_path() -> Path:
    if sys.platform == "darwin":
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "Claude"
            / "claude_desktop_config.json"
        )
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "Claude" / "claude_desktop_config.json"


def windsurf_config_path() -> Path:
    return Path.home() / ".codeium" / "windsurf" / "mcp_config.json"


def zed_settings_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "zed" / "settings.json"


def write_zed_config(path: str | Path, state_dir: str | None = None) -> Path:
    """Merge baton into Zed's context_servers settings object."""
    target = Path(path).expanduser()
    current = _read_json_object(target)
    _merge_server(current, "context_servers", mcp_entry(state_dir), target)
    _atomic_write(target, json.dumps(current, indent=2) + "\n")
    return target


AGENT_INSTRUCTIONS = """## Baton Authentication Broker

Use `baton` to run authenticated CLI commands or HTTP requests without reading raw secrets:

- List available contexts: `baton ctx list --json`
- Run a command in an isolated auth context: `baton run <context> -- <command> [args...]`
- Make an authenticated HTTP request: `baton http <context> <url> [--method METHOD] [-H Header:Value]`
- Mint a temporary lease for sub-agents: `baton lease new <context> --ttl 600 --uses 20`

Never ask the operator to paste secrets into chat, and never run `baton env --reveal`.
"""


def write_agent_instructions(path: str | Path = "AGENTS.md") -> Path:
    """Add or update the Baton section in an AGENTS.md / CLAUDE.md file."""
    target = Path(path).expanduser()
    marker = "## Baton Authentication Broker"
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    if marker in existing:
        before, _, rest = existing.partition(marker)
        next_heading = rest.find("\n## ")
        after = rest[next_heading + 1 :] if next_heading != -1 else ""
        updated = before.rstrip()
        if updated:
            updated += "\n\n"
        updated += AGENT_INSTRUCTIONS.strip() + "\n"
        if after:
            updated += "\n" + after.lstrip("\n")
    elif existing.strip():
        updated = existing.rstrip() + "\n\n" + AGENT_INSTRUCTIONS.strip() + "\n"
    else:
        updated = AGENT_INSTRUCTIONS.strip() + "\n"
    _atomic_write(target, updated)
    return target


def write_hermes_config(path: str | Path, state_dir: str | None = None) -> Path:
    """Round-trip Hermes YAML so comments and other settings survive setup."""
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap
    from ruamel.yaml.error import YAMLError

    target = Path(path).expanduser()
    yaml = YAML()
    yaml.preserve_quotes = True
    try:
        current = yaml.load(target.read_text()) if target.exists() else CommentedMap()
    except (OSError, YAMLError) as exc:
        raise BatonError(f"cannot read Hermes YAML config {target}: {exc}") from exc
    if current is None:
        current = CommentedMap()
    if not isinstance(current, dict):
        raise BatonError(f"Hermes YAML config {target} must be a mapping")
    servers = current.get("mcp_servers")
    if servers is None:
        servers = CommentedMap()
        current["mcp_servers"] = servers
    if not isinstance(servers, dict):
        raise BatonError(f"mcp_servers in {target} must be a mapping")
    server = servers.get("baton")
    if server is None:
        server = CommentedMap()
        servers["baton"] = server
    if not isinstance(server, dict):
        raise BatonError(f"baton in {target} must be a mapping")
    entry = mcp_entry(state_dir)
    for old_key in ("url", "headers", "auth", "transport"):
        server.pop(old_key, None)
    server["command"] = entry["command"]
    server["args"] = entry["args"]
    server["enabled"] = True
    env = server.get("env")
    if env is None:
        env = CommentedMap()
    if not isinstance(env, dict):
        raise BatonError(f"baton.env in {target} must be a mapping")
    env.update(entry["env"])
    server["env"] = env
    output = StringIO()
    try:
        yaml.dump(current, output)
    except YAMLError as exc:
        raise BatonError(f"cannot render Hermes YAML config {target}: {exc}") from exc
    _atomic_write(target, output.getvalue())
    return target


def _read_json_object(target: Path) -> dict[str, Any]:
    if target.exists():
        try:
            current = json.loads(target.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise BatonError(f"cannot read JSON config {target}: {exc}") from exc
        if not isinstance(current, dict):
            raise BatonError(f"JSON config {target} must be an object")
    else:
        current = {}
    return current


def _merge_server(
    current: dict[str, Any], root: str, entry: dict[str, Any], target: Path
) -> None:
    servers = current.get(root, {})
    if not isinstance(servers, dict):
        raise BatonError(f"{root} in {target} must be an object")
    previous = servers.get("baton", {})
    if not isinstance(previous, dict):
        raise BatonError(f"baton in {target} must be an object")
    old_env = previous.get("env", {})
    if not isinstance(old_env, dict):
        raise BatonError(f"baton.env in {target} must be an object")
    merged = {**previous, **entry, "env": {**old_env, **entry["env"]}}
    if "command" in entry:
        for old_key in ("url", "headers", "auth"):
            merged.pop(old_key, None)
    if "type" in entry:
        merged.pop("transport", None)
    if "transport" in entry:
        merged.pop("type", None)
    current[root] = {**servers, "baton": merged}


def _atomic_write(target: Path, content: str) -> None:
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    except OSError as exc:
        raise BatonError(f"cannot write config {target}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except OSError as exc:
        raise BatonError(f"cannot write config {target}: {exc}") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
