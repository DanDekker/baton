"""MCP surface for baton.

Built against MCP Python SDK 2.x, where `mcp.server.fastmcp.FastMCP` became
`mcp.server.mcpserver.MCPServer` -- most published tutorials still target the
removed path.

The contract is one line: **metadata in, handles out, secrets never cross.**
No tool here returns a credential value. `baton_run` and `baton_http` are the
only ways to *use* a credential, and both run on the broker side of the wall.
"""

from __future__ import annotations

import functools
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__, broker, catalog, runner
from .models import BatonError
from .vault import Vault


def _surfaces_errors(fn):
    """Re-raise broker errors as MCP tool errors.

    MCP 2.x deliberately keeps the text of unexpected exceptions on the server,
    which would leave an agent with "Error executing tool baton_run" and no idea
    whether the lease expired, was revoked, or lacked a service. A refusal an
    agent cannot read is a refusal it will retry forever.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except BatonError as exc:
            raise ToolError(str(exc)) from exc

    return wrapper

INSTRUCTIONS = """
Baton brokers authentication for agents. Credentials live in an encrypted local
vault; you never receive their values.

Typical flow:
  1. baton_contexts()            -- see what auth contexts exist
  2. baton_lease(context=...)    -- get a short-lived handle for your task
  3. baton_run(lease, argv)      -- run a CLI with that auth in an isolated HOME
     baton_http(lease, ...)      -- or make an API call with auth attached

Pass the lease token to another agent to hand over that auth context; pass the
credential itself and you have leaked it. Leases expire, carry a use budget, and
are revocable with baton_revoke(). Every use is recorded in a hash-chained audit
log (baton_audit).

For agents on other machines, pair their identities first and use
baton_lease(recipient=..., services=...) to send a recipient-bound grant to their
inbox. Remote recipients authenticate with their own local private key, accept
the grant, and can delegate narrower child leases only when delegatable=True.
This local server is an administrative interface; remote agents use the
separate restricted remote_mcp adapter.

If there are no contexts, ask the human to add a credential in their terminal
with `baton cred add NAME --provider SERVICE --field token --context CONTEXT`.
Never ask them to paste a secret into chat. Custom service names work too.
"""


def build(vault: Vault) -> MCPServer:
    server = MCPServer(
        name="baton",
        title="Baton auth broker",
        version=__version__,
        instructions=INSTRUCTIONS,
    )

    @server.tool(description="Vault metadata: cipher, key mode, counts. No secrets.")
    @_surfaces_errors
    def baton_info() -> dict[str, Any]:
        return {
            **vault.stats(),
            "provider_presets": sorted(catalog.PRESETS),
            "custom_providers": True,
        }

    @server.tool(description="List auth contexts (named bundles of credentials).")
    @_surfaces_errors
    def baton_contexts() -> dict[str, Any]:
        return {"contexts": vault.list_contexts()}

    @server.tool(
        description="List credentials as metadata only: name, provider, field names, "
        "scope, expiry. Values are never returned."
    )
    @_surfaces_errors
    def baton_credentials() -> dict[str, Any]:
        return {"credentials": vault.list_credentials()}

    @server.tool(description="List paired agent identities for recipient-bound grants (local administration).")
    @_surfaces_errors
    def baton_agents() -> dict[str, Any]:
        rows = vault._conn.execute("SELECT id,name,revoked FROM agents ORDER BY name").fetchall()
        return {"agents": [dict(row) for row in rows]}

    @server.tool(
        description="Issue a lease: a signed, expiring handle to a context or credential. "
        "Pass the returned token to other agents instead of credentials. Empty services "
        "means all services in the context are allowed. Set recipient to a paired agent "
        "for a bound remote HTTP grant; this returns a public ID instead of a bearer token."
    )
    @_surfaces_errors
    def baton_lease(
        context: str = "",
        subject: str = "agent",
        ttl_seconds: int = 900,
        services: list[str] | None = None,
        max_uses: int | None = None,
        recipient: str | None = None,
        delegatable: bool = False,
        http_methods: list[str] | None = None,
        path_prefixes: list[str] | None = None,
    ) -> dict[str, Any]:
        lease = vault.issue_lease(
            context=context or None,
            subject=subject,
            services=services or [],
            ttl=float(ttl_seconds),
            max_uses=max_uses,
            recipient=recipient,
            delegatable=delegatable,
            http_methods=http_methods,
            path_prefixes=path_prefixes,
        )
        return lease.public() if lease.recipient else {"token": lease.token, **lease.public()}

    @server.tool(
        description="Run a command with a context or credential's auth materialized into a "
        "throwaway HOME. Returns exit code and redacted stdout/stderr."
    )
    @_surfaces_errors
    def baton_run(
        lease_or_context: str = "",
        argv: list[str] | None = None,
        timeout_seconds: int = 300,
        service: str | None = None,
        cwd: str | None = None,
        stdin: str | None = None,
    ) -> dict[str, Any]:
        result = runner.run(
            vault,
            lease_or_context or None,
            argv or [],
            cwd=cwd,
            stdin=stdin,
            timeout=float(timeout_seconds) if timeout_seconds else None,
            service=service,
        )
        return result.as_dict()

    @server.tool(
        description="Make an HTTP request with a credential attached by the broker. The "
        "response body is returned redacted; the token never enters your context."
    )
    @_surfaces_errors
    def baton_http(
        lease_or_context: str,
        url: str,
        method: str = "GET",
        service: str | None = None,
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
    ) -> dict[str, Any]:
        resp = broker.request(
            vault,
            lease_or_context or None,
            method,
            url,
            service=service,
            headers=headers,
            json_body=json_body,
        )
        return resp.as_dict()

    @server.tool(description="Recent audit events plus hash-chain integrity.")
    @_surfaces_errors
    def baton_audit(limit: int = 25) -> dict[str, Any]:
        intact, bad_seq = vault.verify_audit()
        return {
            "intact": intact,
            "first_bad_seq": bad_seq,
            "events": vault.audit_tail(limit),
        }

    @server.tool(description="List leases with their remaining TTL and use counts.")
    @_surfaces_errors
    def baton_leases() -> dict[str, Any]:
        return {"leases": vault.list_leases()}

    @server.tool(description="Revoke a lease by id. Use is rejected immediately.")
    @_surfaces_errors
    def baton_revoke(lease_id: str) -> dict[str, Any]:
        return {"revoked": vault.revoke_lease(lease_id)}

    @server.tool(
        description="Refresh a credential using its configured refresh provider. "
        "Updates token and expiry in place. Does not return secret values."
    )
    @_surfaces_errors
    def baton_refresh(credential: str, force: bool = False) -> dict[str, Any]:
        cred, refreshed = vault.refresh_credential(credential, force=force)
        return {"refreshed": refreshed, **cred.public()}

    return server


def main() -> None:
    """Entry point for `baton-mcp`: serve over stdio."""
    try:
        vault = Vault()
    except BatonError as exc:  # pragma: no cover - startup guard
        raise SystemExit(f"baton: cannot open vault: {exc}") from exc
    build(vault).run("stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
