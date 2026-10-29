"""`baton` command line.

Two audiences, two rules:
  * operators (this CLI) may retrieve a value -- but only behind an explicit
    `--reveal`, because terminal scrollback and shell history are leak surfaces;
  * agents (MCP, see mcp_server.py) never can.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__, broker, catalog, integration, runner
from .materialize import plan
from .models import BatonError, Context, Credential, UnknownContext
from .redact import Redactor
from .vault import Vault


def _out(text: str = "") -> None:
    print(text)


def _table(rows: list[list[str]], headers: list[str]) -> None:
    if not rows:
        _out("  (none)")
        return
    widths = [
        max(len(headers[i]), *(len(r[i]) for r in rows)) for i in range(len(headers))
    ]
    _out("  " + "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
    for r in rows:
        _out("  " + "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)))


def _fmt_expiry(expires_at: float | None) -> str:
    if expires_at is None:
        return "-"
    left = int(expires_at - time.time())
    return "expired" if left <= 0 else f"{left // 60}m"


def _parse_fields(pairs: list[str] | None, files: list[str] | None) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in pairs or []:
        if "=" in item:
            name, value = item.split("=", 1)
            values[name] = value
        else:
            values[item] = getpass.getpass(f"{item}: ")
    for item in files or []:
        if "=" not in item:
            raise SystemExit(f"--field-file wants NAME=PATH, got {item!r}")
        name, path = item.split("=", 1)
        values[name] = Path(path).expanduser().read_text()
    return values


def _parse_env_pairs(pairs: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in pairs or []:
        if "=" not in item:
            raise SystemExit(f"--env wants NAME=TEMPLATE, got {item!r}")
        name, value = item.split("=", 1)
        out[name] = value
    return out


def _parse_auth(value: str | None, field: str | None) -> dict[str, str] | None:
    if value is None and field is None:
        return None
    scheme, _, detail = (value or "bearer").partition(":")
    if scheme not in {"bearer", "header", "query", "basic", "none"}:
        raise BatonError(f"unknown auth scheme {scheme!r}")
    if scheme in {"header", "query"}:
        if not detail or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", detail):
            raise BatonError(
                f"--auth {scheme} needs a valid name, for example {scheme}:x-api-key"
            )
    elif detail:
        raise BatonError(f"--auth {scheme} does not take a name")
    if field and scheme in {"basic", "none"}:
        raise BatonError(f"--auth-field cannot be used with {scheme} auth")
    auth = {"scheme": scheme}
    if scheme == "header":
        auth["header"] = detail
    if scheme == "query":
        auth["param"] = detail
    if field:
        auth["field"] = field
    return auth


# ----------------------------------------------------------------- commands
def cmd_status(v: Vault, _args: argparse.Namespace) -> int:
    for key, value in v.stats().items():
        _out(f"  {key:14} {value}")
    return 0


def cmd_cred_add(v: Vault, args: argparse.Namespace) -> int:
    values = _parse_fields(args.field, args.field_file)
    refresh_config: dict[str, Any] = {}
    if (
        getattr(args, "refresh_provider", None)
        or getattr(args, "refresh_token_url", None)
        or getattr(args, "refresh_cmd", None)
    ):
        p = args.refresh_provider or ("oauth2" if args.refresh_token_url else "exec")
        refresh_config["provider"] = p
        if getattr(args, "refresh_token_url", None):
            refresh_config["token_url"] = args.refresh_token_url
        if getattr(args, "refresh_client_id", None):
            refresh_config["client_id"] = args.refresh_client_id
        if getattr(args, "refresh_client_secret", None):
            values["client_secret"] = args.refresh_client_secret
        if getattr(args, "refresh_token", None):
            values["refresh_token"] = args.refresh_token
        if getattr(args, "refresh_scope", None):
            refresh_config["scope"] = args.refresh_scope
        if getattr(args, "refresh_cmd", None):
            refresh_config["argv"] = args.refresh_cmd
        if getattr(args, "refresh_ttl", None):
            refresh_config["ttl"] = args.refresh_ttl

    cred = catalog.build_credential(
        args.name,
        args.provider,
        values,
        expires_at=time.time() + args.expires_days * 86400 if args.expires_days else None,
        notes=args.notes or "",
        env_map=_parse_env_pairs(args.env),
        refresh=refresh_config if refresh_config else None,
        auth=_parse_auth(args.auth, args.auth_field),
        allowed_hosts=args.allow_host,
    )
    v.put_credential(cred)
    _out(f"stored {cred.name} ({cred.provider}), fields: {', '.join(sorted(cred.secret))}")
    if cred.provider not in catalog.PRESETS:
        _out(f"custom provider {cred.provider}: {cred.auth['scheme']} HTTP auth")
    if args.context:
        try:
            ctx = v.get_context(args.context)
        except UnknownContext:
            ctx = Context(name=args.context)
        if cred.name not in ctx.credentials:
            ctx.credentials.append(cred.name)
            v.put_context(ctx)
        _out(f"context {ctx.name}: {', '.join(ctx.credentials)}")
    return 0


def cmd_cred_refresh(v: Vault, args: argparse.Namespace) -> int:
    cred, did_refresh = v.refresh_credential(args.name, force=args.force, skew=args.skew)
    if did_refresh:
        _out(f"refreshed {cred.name} ({cred.provider}), expires: {_fmt_expiry(cred.expires_at)}")
    else:
        _out(f"{cred.name} is still fresh, expires: {_fmt_expiry(cred.expires_at)}")
    return 0


def cmd_cred_list(v: Vault, args: argparse.Namespace) -> int:
    rows = v.list_credentials()
    if args.json:
        _out(json.dumps(rows, indent=2))
        return 0
    _table(
        [
            [
                r["name"],
                r["provider"],
                ",".join(r["fields"]),
                _fmt_expiry(r["expires_at"]),
                r.get("refresh_provider") or ("yes" if r.get("refreshable") else "-"),
            ]
            for r in rows
        ],
        ["NAME", "PROVIDER", "FIELDS", "EXPIRES", "REFRESH"],
    )
    return 0


def cmd_cred_rm(v: Vault, args: argparse.Namespace) -> int:
    removed = v.delete_credential(args.name)
    _out("deleted" if removed else "not found")
    return 0 if removed else 1


def cmd_ctx_add(v: Vault, args: argparse.Namespace) -> int:
    ctx = Context(
        name=args.name,
        credentials=list(args.cred or []),
        description=args.desc or "",
        passthrough=list(args.passthrough or []),
        env=_parse_env_pairs(args.env),
        inherit_paths=list(args.inherit or []),
    )
    v.put_context(ctx)
    _out(f"context {ctx.name}: {', '.join(ctx.credentials) or '(empty)'}")
    return 0


def cmd_ctx_list(v: Vault, args: argparse.Namespace) -> int:
    rows = v.list_contexts()
    if args.json:
        _out(json.dumps(rows, indent=2))
        return 0
    _table(
        [[r["name"], ",".join(r["credentials"]), r["description"]] for r in rows],
        ["NAME", "CREDENTIALS", "DESCRIPTION"],
    )
    return 0


def cmd_ctx_rm(v: Vault, args: argparse.Namespace) -> int:
    _out("deleted" if v.delete_context(args.name) else "not found")
    return 0


def cmd_lease_new(v: Vault, args: argparse.Namespace) -> int:
    lease = v.issue_lease(
        args.context,
        args.subject,
        services=list(args.service or []),
        ttl=args.ttl,
        max_uses=args.uses,
    )
    _out(lease.token)
    return 0


def cmd_lease_list(v: Vault, args: argparse.Namespace) -> int:
    rows = v.list_leases()
    if args.json:
        _out(json.dumps(rows, indent=2))
        return 0
    _table(
        [
            [
                r["id"],
                r["context"],
                r["subject"],
                _fmt_expiry(r["expires_at"]),
                str(r["uses"]),
                "revoked" if r["revoked"] else "live",
            ]
            for r in rows
        ],
        ["ID", "CONTEXT", "SUBJECT", "EXPIRES", "USES", "STATE"],
    )
    return 0


def cmd_lease_revoke(v: Vault, args: argparse.Namespace) -> int:
    _out("revoked" if v.revoke_lease(args.lease_id) else "not found")
    return 0


def cmd_run(v: Vault, args: argparse.Namespace) -> int:
    argv = list(args.argv)
    if argv and argv[0] == "--":
        argv.pop(0)
    result = runner.run(
        v,
        args.target,
        argv,
        cwd=args.cwd,
        timeout=args.timeout,
        service=args.service,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.redactions:
        print(
            f"baton: {result.redactions} secret occurrence(s) redacted", file=sys.stderr
        )
    return result.exit_code if result.exit_code >= 0 else 1


def cmd_env(v: Vault, args: argparse.Namespace) -> int:
    p = plan(v, args.target)
    redactor = Redactor(p.secrets)
    if args.reveal:
        _out(f"# context {p.context.name} -- values revealed on explicit request")
        for key, value in sorted(p.env.items()):
            _out(f"export {key}={json.dumps(value)}")
        return 0
    _table(
        [[k, p.sources.get(k, "-"), "yes" if v_ else "-"] for k, v_ in sorted(p.env.items())],
        ["VARIABLE", "FROM", "SET"],
    )
    _out(redactor.redact("\n  (values withheld; add --reveal to print them)"))
    return 0


def cmd_audit(v: Vault, args: argparse.Namespace) -> int:
    intact, bad = v.verify_audit()
    _out(f"chain: {'intact' if intact else f'BROKEN at seq {bad}'}")
    for e in v.audit_tail(args.limit):
        _out(
            f"  {time.strftime('%H:%M:%S', time.localtime(e['ts']))} "
            f"{e['action']:14} {e['target'] or '-':24} {'ok' if e['ok'] else 'FAIL'}"
        )
    return 0 if intact else 2


def cmd_mcp(v: Vault, _args: argparse.Namespace) -> int:
    from .mcp_server import build

    build(v).run("stdio")
    return 0


def cmd_http(v: Vault, args: argparse.Namespace) -> int:
    try:
        json_body = json.loads(args.body) if args.body else None
    except json.JSONDecodeError as exc:
        raise BatonError(f"--body must be valid JSON ({exc.msg} at column {exc.colno})") from exc
    resp = broker.request(
        v,
        args.target,
        args.method,
        args.url,
        service=args.service,
        json_body=json_body,
        allow_private=args.allow_private,
        allow_loopback=not args.disallow_loopback,
    )
    _out(f"{resp.status} {resp.url}")
    _out(resp.body)
    return 0 if 200 <= resp.status < 300 else 1


def cmd_info(v: Vault, _args: argparse.Namespace) -> int:
    _out(f"baton {__version__}")
    for p in catalog.PRESETS.values():
        _out(f"  {p.provider:8} {', '.join(p.fields)}  -- {p.hint}")
    _out("  other provider names use bearer token auth by default")
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    if args.client in {"muse-code", "hermes-agent"}:
        if args.root:
            raise BatonError("--root is only for generic JSON config")
        if args.client == "muse-code":
            target = args.output or integration.muse_settings_path()
            path = integration.write_muse_config(target, args.state_dir)
        else:
            target = args.output or integration.hermes_config_path()
            path = integration.write_hermes_config(target, args.state_dir)
        _out(f"added baton to {path}")
    elif args.client in {"codex", "claude-code"}:
        if args.output or args.root:
            raise BatonError("--output and --root apply only to JSON client configs")
        command = integration.client_command(args.client, args.state_dir)
        try:
            subprocess.run(command, check=True)
        except FileNotFoundError as exc:
            raise BatonError(
                f"{args.client} CLI not found; use `baton setup` for portable MCP config"
            ) from exc
        except subprocess.CalledProcessError as exc:
            raise BatonError(f"{args.client} could not add baton (exit {exc.returncode})") from exc
    else:
        if args.client != "generic" and args.root:
            raise BatonError("--root is only for generic JSON config")
        root = args.root or ("servers" if args.client == "vscode" else "mcpServers")
        config = integration.mcp_config(args.state_dir, root)
        target = args.output
        if target is None and args.client == "cursor":
            target = str(Path.home() / ".cursor" / "mcp.json")
        if target is None and args.client == "vscode":
            target = str(Path.cwd() / ".vscode" / "mcp.json")
        if target:
            path = integration.write_mcp_config(target, config)
            _out(f"added baton to {path}")
        else:
            _out(json.dumps(config, indent=2))
    if "BATON_MASTER_KEY" in os.environ or "BATON_PASSPHRASE" in os.environ:
        print(
            "baton: your MCP client also needs the vault key environment; "
            "no secret was written to config",
            file=sys.stderr,
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state-dir", help="vault directory (default: ~/.local/state/baton)")

    p = argparse.ArgumentParser(
        prog="baton",
        description="Use stored credentials in agent tasks without handing over the secrets.",
        epilog=(
            "First steps:\n"
            "  baton cred add gh-work --provider github --field token --context work\n"
            "  baton run work -- gh api /user\n"
            "  baton setup  # connect an MCP client\n"
            "Guide: https://github.com/DanDekker/baton/blob/main/docs/guide.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"baton {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", parents=[common], help="show vault status")
    sub.add_parser("info", parents=[common], help="show supported credential types")

    setup = sub.add_parser(
        "setup", parents=[common], help="create MCP config for an agent client"
    )
    setup.add_argument(
        "--client", choices=[
            "generic", "codex", "claude-code", "cursor", "vscode",
            "muse-code", "hermes-agent",
        ],
        default="generic", help="install for a known client or print portable JSON",
    )
    setup.add_argument(
        "--root", choices=["mcpServers", "servers"], help="JSON key used by your client"
    )
    setup.add_argument("--output", help="merge baton into a client JSON config file")

    cred = sub.add_parser("cred", parents=[common], help="store and refresh credentials")
    cred_sub = cred.add_subparsers(dest="cred_cmd", required=True)
    a = cred_sub.add_parser(
        "add",
        parents=[common],
        description="Store a credential. A bare --field name prompts for its value privately.",
        epilog="Example: baton cred add gh-work --provider github --field token",
    )
    a.add_argument("name")
    a.add_argument("--provider", required=True)
    a.add_argument("--field", action="append", help="bare NAME prompts privately; NAME=VALUE is visible in shell history")
    a.add_argument("--field-file", action="append", help="NAME=PATH for file/blob fields")
    a.add_argument("--env", action="append", help="NAME={field} extra env mapping")
    a.add_argument("--context", help="create or update this context with the credential")
    a.add_argument("--auth", help="HTTP auth: bearer, header:NAME, query:NAME, basic, or none")
    a.add_argument("--auth-field", help="secret field for bearer, header, or query auth (default: token)")
    a.add_argument("--allow-host", action="append", help="restrict HTTP requests to this host or *.domain (repeatable)")
    a.add_argument("--expires-days", type=float)
    a.add_argument("--notes")
    a.add_argument("--refresh-provider", help="refresh provider (oauth2, exec, ...)")
    a.add_argument("--refresh-token-url", help="OAuth2 token endpoint URL")
    a.add_argument("--refresh-client-id", help="OAuth2 client ID")
    a.add_argument("--refresh-client-secret", help="OAuth2 client secret (prefer --field client_secret)")
    a.add_argument("--refresh-token", help="OAuth2 refresh token (prefer --field refresh_token)")
    a.add_argument("--refresh-scope", help="OAuth2 scope")
    a.add_argument("--refresh-cmd", help="exec refresh command string")
    a.add_argument("--refresh-ttl", type=float, help="TTL in seconds for exec refresh")
    cred_list = cred_sub.add_parser("list", parents=[common])
    cred_list.add_argument("--json", action="store_true", help="print JSON")
    crf = cred_sub.add_parser("refresh", parents=[common], help="refresh a credential")
    crf.add_argument("name")
    crf.add_argument("--force", action="store_true", help="refresh even if not expired")
    crf.add_argument("--skew", type=float, default=60.0, help="expiry skew in seconds")
    r = cred_sub.add_parser("rm", parents=[common])
    r.add_argument("name")

    ctx = sub.add_parser("ctx", parents=[common], help="group credentials into contexts")
    ctx_sub = ctx.add_subparsers(dest="ctx_cmd", required=True)
    c = ctx_sub.add_parser("add", parents=[common])
    c.add_argument("name")
    c.add_argument("--cred", action="append")
    c.add_argument("--desc")
    c.add_argument("--env", action="append")
    c.add_argument("--passthrough", action="append")
    c.add_argument("--inherit", action="append")
    ctx_list = ctx_sub.add_parser("list", parents=[common])
    ctx_list.add_argument("--json", action="store_true", help="print JSON")
    cr = ctx_sub.add_parser("rm", parents=[common])
    cr.add_argument("name")

    lease = sub.add_parser("lease", parents=[common], help="create and revoke temporary access")
    lease_sub = lease.add_subparsers(dest="lease_cmd", required=True)
    ln = lease_sub.add_parser("new", parents=[common])
    ln.add_argument("context")
    ln.add_argument("--subject", default="cli")
    ln.add_argument("--ttl", type=float, default=900.0)
    ln.add_argument("--uses", type=int)
    ln.add_argument("--service", action="append")
    lease_list = lease_sub.add_parser("list", parents=[common])
    lease_list.add_argument("--json", action="store_true", help="print JSON")
    lr = lease_sub.add_parser("revoke", parents=[common])
    lr.add_argument("lease_id")

    run_p = sub.add_parser(
        "run",
        parents=[common],
        help="run a command with stored credentials",
        description="Run a command with credentials from a context or lease.",
        epilog=(
            "Example: baton run work -- gh api /user\n"
            "Put baton options before TARGET. Everything after -- goes to the command."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_p.add_argument("target", help="context name or lease token")
    run_p.add_argument("--timeout", type=float)
    run_p.add_argument("--cwd")
    run_p.add_argument("--service")
    run_p.add_argument("argv", nargs=argparse.REMAINDER, help="command and its arguments")

    env_p = sub.add_parser("env", parents=[common], help="show a context's environment variables")
    env_p.add_argument("target")
    env_p.add_argument("--reveal", action="store_true", help="print secret values")

    http_p = sub.add_parser(
        "http",
        parents=[common],
        help="send an HTTP request with stored credentials",
        description="Send an HTTP request with auth attached by baton.",
        epilog="Example: baton http work https://api.github.com/user",
    )
    http_p.add_argument("target", help="context name or lease token")
    http_p.add_argument("url", help="request URL")
    http_p.add_argument("--method", default="GET")
    http_p.add_argument("--service")
    http_p.add_argument("--body", help="JSON request body, for example '{\"name\":\"demo\"}'")
    http_p.add_argument(
        "--allow-private",
        action="store_true",
        help="allow requests to private RFC1918/RFC4193 subnets",
    )
    http_p.add_argument(
        "--disallow-loopback",
        action="store_true",
        help="block requests to loopback/localhost",
    )

    audit_p = sub.add_parser("audit", parents=[common], help="show access history")
    audit_p.add_argument("--limit", type=int, default=20)

    sub.add_parser("mcp", parents=[common], help="start the MCP server")
    return p


_HANDLERS = {
    ("status", None): cmd_status,
    ("info", None): cmd_info,
    ("cred", "add"): cmd_cred_add,
    ("cred", "list"): cmd_cred_list,
    ("cred", "refresh"): cmd_cred_refresh,
    ("cred", "rm"): cmd_cred_rm,
    ("ctx", "add"): cmd_ctx_add,
    ("ctx", "list"): cmd_ctx_list,
    ("ctx", "rm"): cmd_ctx_rm,
    ("lease", "new"): cmd_lease_new,
    ("lease", "list"): cmd_lease_list,
    ("lease", "revoke"): cmd_lease_revoke,
    ("run", None): cmd_run,
    ("env", None): cmd_env,
    ("http", None): cmd_http,
    ("audit", None): cmd_audit,
    ("mcp", None): cmd_mcp,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    sub = getattr(args, f"{args.cmd}_cmd", None)
    try:
        if args.cmd == "setup":
            return cmd_setup(args)
        handler = _HANDLERS[(args.cmd, sub)]
        with Vault(state_dir=args.state_dir) as v:
            return handler(v, args)
    except BatonError as exc:
        print(f"baton: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"baton: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
