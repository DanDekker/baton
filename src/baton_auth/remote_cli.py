"""Pairing and handoff commands; remote clients never open the broker's vault."""

from __future__ import annotations

import json
from pathlib import Path
import shlex

from cryptography.exceptions import InvalidSignature

from . import identity
from .models import BatonError
from .remote import RemoteClient, serve
from .vault import Vault


def add_parsers(sub, common):
    agent = sub.add_parser("agent", parents=[common], help="pair and revoke harness identities")
    agents = agent.add_subparsers(dest="agent_cmd", required=True)
    init = agents.add_parser("init", parents=[common], help="create an identity here and a public pairing request")
    init.add_argument("name")
    init.add_argument("--output")
    trust = agents.add_parser("trust", parents=[common], help="approve a public pairing request on the broker")
    trust.add_argument("request")
    trust.add_argument("--url", required=True, help="HTTPS broker address")
    trust.add_argument("--output")
    agents.add_parser("list", parents=[common])
    revoke = agents.add_parser("revoke", parents=[common])
    revoke.add_argument("name")

    connect = sub.add_parser("connect", parents=[common], help="install a pairing bundle for this machine's identity")
    connect.add_argument("bundle")
    connect.add_argument("--name", default="default", help="connection name")

    grant = sub.add_parser("grant", parents=[common], help="send a bound grant to a paired agent's inbox")
    grant.add_argument("context", nargs="?")
    grant.add_argument("--to", required=True)
    grant.add_argument("--ttl", type=float, default=900)
    grant.add_argument("--uses", type=int)
    grant.add_argument("--service", action="append")
    grant.add_argument("--delegate", action="store_true")
    grant.add_argument("--method", action="append", help="default: GET and HEAD")
    grant.add_argument("--path-prefix", action="append")
    grant.add_argument("--summary", default="")

    server = sub.add_parser("serve", parents=[common], help="serve a mutual-TLS, lease-only remote broker")
    server.add_argument("--url", required=True, help="HTTPS address clients use to reach this broker")
    server.add_argument("--host", default="127.0.0.1", help="listen address (use 0.0.0.0 for other machines)")
    server.add_argument("--port", type=int, default=8765)

    remote = sub.add_parser("remote", parents=[common], help="use a paired broker from this machine")
    remote.add_argument("--connection", default="default")
    commands = remote.add_subparsers(dest="remote_cmd", required=True)
    commands.add_parser("identity")
    commands.add_parser("inbox")
    accept = commands.add_parser("accept")
    accept.add_argument("lease")
    http = commands.add_parser("http")
    http.add_argument("lease")
    http.add_argument("url")
    http.add_argument("--method", default="GET")
    http.add_argument("--service")
    http.add_argument("--body", help="JSON request body")
    http.add_argument("-H", "--header", action="append")
    delegate = commands.add_parser("delegate")
    delegate.add_argument("lease")
    delegate.add_argument("--to", required=True)
    delegate.add_argument("--ttl", type=float, default=300)
    delegate.add_argument("--uses", type=int)
    delegate.add_argument("--service", action="append")
    delegate.add_argument("--method", action="append")
    delegate.add_argument("--path-prefix", action="append")
    delegate.add_argument("--delegate", action="store_true")
    delegate.add_argument("--summary", default="")
    delegate.add_argument("--artifact", action="append")
    delegate.add_argument("--task-id", default="")
    revoke = commands.add_parser("revoke")
    revoke.add_argument("lease")
    revoke.add_argument("--child")


def _output(value, output=None):
    text = json.dumps(value, indent=2) + "\n"
    if output:
        identity.write_private(Path(output).expanduser(), text.encode())
        print(f"wrote {output}")
    else:
        print(text, end="")


def execute(args):
    try:
        return _execute(args)
    except (InvalidSignature, ValueError, KeyError, TypeError) as exc:
        raise BatonError("invalid pairing file or remote arguments") from exc


def _execute(args):
    if args.cmd == "agent" and args.agent_cmd == "init":
        _output(identity.init_agent(args.name, args.state_dir), args.output)
        return 0
    if args.cmd == "connect":
        bundle = json.loads(Path(args.bundle).expanduser().read_text())
        directory = identity.connect(bundle, args.state_dir, args.name)
        print(f"configured {bundle['name']} for {bundle['endpoint']} ({directory})")
        state = f" --state-dir {shlex.quote(args.state_dir)}" if args.state_dir else ""
        print(f"Next: baton setup --remote {args.name} --auto{state}")
        return 0
    if args.cmd == "remote":
        return _remote(args)
    with Vault(state_dir=args.state_dir) as vault:
        if args.cmd == "agent":
            if args.agent_cmd == "trust":
                request = json.loads(Path(args.request).expanduser().read_text())
                _output(identity.trust_agent(vault, request, args.url), args.output)
            elif args.agent_cmd == "list":
                rows = vault._conn.execute("SELECT id,name,revoked,created_at FROM agents ORDER BY name").fetchall()
                _output([dict(row) for row in rows])
            else:
                _output({"revoked": identity.revoke_agent(vault, args.name)})
        elif args.cmd == "grant":
            lease = vault.issue_lease(
                args.context, recipient=args.to, services=args.service, ttl=args.ttl,
                max_uses=args.uses, delegatable=args.delegate,
                http_methods=args.method, path_prefixes=args.path_prefix,
                task={"summary": args.summary},
            )
            _output(lease.public())
        elif args.cmd == "serve":
            if not 1 <= args.port <= 65535:
                raise BatonError("port must be between 1 and 65535")
            serve(vault, args.url, args.host, args.port)
    return 0


def _remote(args):
    options = {}
    op = args.remote_cmd
    if op in {"accept", "http", "delegate", "revoke"}:
        options["lease"] = args.lease
    if op == "http":
        from .cli import _parse_headers
        options.update(url=args.url, method=args.method, service=args.service,
                       headers=_parse_headers(args.header),
                       json_body=json.loads(args.body) if args.body else None)
    elif op == "delegate":
        options.update(recipient=args.to, ttl=args.ttl, max_uses=args.uses,
                       services=args.service, http_methods=args.method, path_prefixes=args.path_prefix,
                       delegatable=args.delegate,
                       task={"summary": args.summary, "artifacts": args.artifact or [], "task_id": args.task_id})
    elif op == "revoke":
        options["child_id"] = args.child
    with RemoteClient(args.state_dir, args.connection) as client:
        result = client.call(op, **options)
    _output(result)
    return 1 if op == "http" and not 200 <= result["status"] < 300 else 0
