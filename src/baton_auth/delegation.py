"""Recipient-bound capabilities with atomic, shared ancestor budgets.

Remote callers authenticate with mutual TLS. Lease IDs are public handles, not
bearer credentials: every operation verifies the authenticated recipient.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import math
import secrets
import time
from typing import Any, TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from . import crypto
from .models import Lease, LeaseError

if TYPE_CHECKING:
    from .vault import Vault

MAX_DEPTH = 8
METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
SPEC_FIELDS = (
    "services", "recipient", "parent_id", "delegatable", "credential_ids",
    "host_policies", "http_methods", "path_prefixes", "accepted_at", "task",
)


@contextmanager
def transaction(vault: Vault):
    with vault._lock:
        vault._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            vault._conn.rollback()
            raise
        else:
            vault._conn.commit()


def agent(vault: Vault, name: str) -> dict[str, Any]:
    row = vault._conn.execute(
        "SELECT * FROM agents WHERE id=? OR name=?", (name, name)
    ).fetchone()
    if row is None or row["revoked"]:
        raise LeaseError("recipient is unknown or revoked")
    return dict(row)


def _row(vault: Vault, handle: str):
    if not isinstance(handle, str) or len(handle) > 4096:
        raise LeaseError("invalid lease handle")
    if handle.startswith("btn_"):
        try:
            body, signature = handle[4:].split(".", 1)
            if not secrets.compare_digest(signature, vault._sign(body)):
                raise ValueError()
            lease_id = json.loads(crypto.b64u_decode(body))["i"]
            if not isinstance(lease_id, str):
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise LeaseError("invalid lease token") from None
        row = vault._conn.execute("SELECT * FROM leases WHERE id=?", (lease_id,)).fetchone()
        if row is not None and not secrets.compare_digest(
            row["token_hash"], crypto.digest(handle.encode(), 32).hex()
        ):
            raise LeaseError("invalid lease token")
    else:
        row = vault._conn.execute("SELECT * FROM leases WHERE id=?", (handle,)).fetchone()
    if row is None:
        raise LeaseError("lease unavailable")
    return row


def _chain(
    vault: Vault, handle: str, recipient: str, *, pending: bool = False,
    inactive: bool = False,
) -> list[Lease]:
    leaf = vault._lease_from_row(_row(vault, handle))
    if not leaf.recipient or leaf.recipient != recipient:
        raise LeaseError("lease is not bound to this recipient")
    chain, seen = [], set()
    current = leaf
    while True:
        if current.id in seen or len(chain) >= MAX_DEPTH:
            raise LeaseError("invalid delegation chain")
        seen.add(current.id)
        agent(vault, current.recipient or "")
        if not inactive:
            current.ensure_valid()
            if current.accepted_at is None and not (pending and current.id == leaf.id):
                raise LeaseError("lease must be accepted before use")
        chain.append(current)
        if current.parent_id is None:
            return chain
        current = vault._lease_from_row(_row(vault, current.parent_id))


def _limits(ttl: float, max_uses: int | None) -> None:
    if isinstance(ttl, bool) or not isinstance(ttl, (float, int)) or not math.isfinite(ttl) or ttl <= 0:
        raise LeaseError("TTL must be a positive finite number")
    if max_uses is not None and (type(max_uses) is not int or max_uses <= 0):
        raise LeaseError("use budget must be a positive integer")


def _methods(values: list[str]) -> list[str]:
    if not isinstance(values, list) or not values or any(v not in METHODS for v in values):
        raise LeaseError("HTTP methods must be a nonempty list of supported uppercase methods")
    return sorted(set(values))


def normalized_path(value: str) -> str:
    path = value
    # Refuse ambiguous/double-encoded traversal instead of guessing how a server normalizes it.
    for _ in range(4):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if "%" in path or "\\" in path or ";" in path or any(ord(c) < 32 for c in path):
        raise LeaseError("ambiguous URL path")
    if not path.startswith("/") or "//" in path or any(p in {".", ".."} for p in path.split("/")):
        raise LeaseError("unsafe URL path")
    return path


def path_matches(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")


def _paths(values: list[str]) -> list[str]:
    if not isinstance(values, list) or not values or any(not isinstance(v, str) for v in values):
        raise LeaseError("path prefixes must be a nonempty list")
    return sorted({normalized_path(value) for value in values})


def _task(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - {"summary", "artifacts", "task_id"}:
        raise LeaseError("task accepts summary, artifacts, and task_id only")
    if any(not isinstance(value[k], str) for k in {"summary", "task_id"} & value.keys()):
        raise LeaseError("task summary and task_id must be strings")
    if "artifacts" in value and (
        not isinstance(value["artifacts"], list)
        or any(not isinstance(item, str) for item in value["artifacts"])
    ):
        raise LeaseError("artifacts must be a list of references")
    if len(json.dumps(value)) > 16000:
        raise LeaseError("task metadata is too large")
    return value


def _store(vault: Vault, lease: Lease) -> None:
    body = crypto.b64u_encode(json.dumps({"i": lease.id, "n": secrets.token_hex(16)}).encode())
    lease.token = f"btn_{body}.{vault._sign(body)}"
    vault._conn.execute(
        "INSERT INTO leases(id,token_hash,context_name,subject,spec,issued_at,expires_at,max_uses)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (lease.id, crypto.digest(lease.token.encode(), 32).hex(), lease.context, lease.subject,
         json.dumps({key: getattr(lease, key) for key in SPEC_FIELDS}), lease.issued_at,
         lease.expires_at, lease.max_uses),
    )


def issue(
    vault: Vault, context: str | None, recipient: str, *, services=None, ttl=900.0,
    max_uses=None, delegatable=False, http_methods=None, path_prefixes=None, task=None,
) -> Lease:
    _limits(ttl, max_uses)
    with transaction(vault):
        target = agent(vault, recipient)
        ctx = vault.resolve_context(context)
        selected = {}
        hosts = {}
        for name in ctx.credentials:
            row = vault.get_credential_row(name)
            if row is None or (services and name not in services and row["provider"] not in services):
                continue
            policies = [p.strip().lower() for p in json.loads(row["meta"]).get("allowed_hosts", [])]
            if not policies or "*" in policies:
                raise LeaseError(f"credential {name!r} needs explicit allowed hosts for remote use")
            selected[name] = row["id"]
            hosts[name] = policies
        if not selected:
            raise LeaseError("no credentials match the requested services")
        lease = Lease(
            context=ctx.name, subject=target["name"], recipient=target["id"],
            services=sorted(selected), credential_ids=selected, host_policies=hosts,
            ttl=float(ttl), max_uses=max_uses, delegatable=bool(delegatable),
            http_methods=_methods(http_methods if http_methods is not None else ["GET", "HEAD"]),
            path_prefixes=_paths(path_prefixes if path_prefixes is not None else ["/"]),
            task=_task(task),
        )
        _store(vault, lease)
    vault.audit(lease.id, lease.recipient, "lease.grant", lease.context, True, lease.public())
    return lease


def resolve(vault: Vault, handle: str, recipient: str, *, consume=True) -> Lease:
    with transaction(vault):
        chain = _chain(vault, handle, recipient)
        if consume:
            for lease in chain:
                vault._conn.execute("UPDATE leases SET uses=uses+1 WHERE id=?", (lease.id,))
                lease.uses += 1
        return chain[0]


def accept(vault: Vault, handle: str, recipient: str) -> Lease:
    with transaction(vault):
        lease = _chain(vault, handle, recipient, pending=True)[0]
        if lease.accepted_at is None:
            lease.accepted_at = time.time()
            vault._conn.execute("UPDATE leases SET spec=? WHERE id=?", (
                json.dumps({key: getattr(lease, key) for key in SPEC_FIELDS}), lease.id,
            ))
    vault.audit(lease.id, recipient, "lease.accept", lease.context, True, {})
    return lease


def delegate(
    vault: Vault, handle: str, actor: str, recipient: str, *, services=None,
    ttl=300.0, max_uses=None, delegatable=False, http_methods=None, path_prefixes=None, task=None,
) -> Lease:
    _limits(ttl, max_uses)
    with transaction(vault):
        chain = _chain(vault, handle, actor)
        parent = chain[0]
        if not parent.delegatable or len(chain) >= MAX_DEPTH:
            raise LeaseError("lease does not permit further delegation")
        target = agent(vault, recipient)
        if vault._conn.execute(
            "SELECT COUNT(*) FROM leases WHERE json_extract(spec,'$.parent_id')=?", (parent.id,)
        ).fetchone()[0] >= 128:
            raise LeaseError("delegation limit reached")
        selected = dict(parent.credential_ids)
        if services is not None:
            if not isinstance(services, list) or not services:
                raise LeaseError("services must be a nonempty list")
            selected = {name: cid for name, cid in selected.items()
                        if name in services or vault.get_credential_provider(name) in services}
            if not selected or any(s not in selected and s not in {
                vault.get_credential_provider(n) for n in selected
            } for s in services):
                raise LeaseError("delegation cannot widen services")
        methods = _methods(parent.http_methods if http_methods is None else http_methods)
        paths = _paths(parent.path_prefixes if path_prefixes is None else path_prefixes)
        if not set(methods) <= set(parent.http_methods) or any(
            not any(path_matches(p, allowed) for allowed in parent.path_prefixes) for p in paths
        ):
            raise LeaseError("delegation cannot widen HTTP permissions")
        remaining = min(p.expires_at for p in chain) - time.time()
        if remaining <= 0:
            raise LeaseError("parent lease expired")
        budgets = [p.max_uses - p.uses for p in chain if p.max_uses is not None]
        budget = min(budgets) if budgets else None
        if max_uses is not None:
            budget = min(budget, max_uses) if budget is not None else max_uses
        lease = Lease(
            context=parent.context, subject=target["name"], recipient=target["id"],
            parent_id=parent.id, services=sorted(selected), credential_ids=selected,
            host_policies={name: parent.host_policies[name] for name in selected},
            ttl=min(float(ttl), remaining), max_uses=budget, delegatable=bool(delegatable),
            http_methods=methods, path_prefixes=paths, task=_task(task),
        )
        # Account for time between computing the remaining TTL and constructing the lease.
        lease.ttl = min(lease.ttl, min(p.expires_at for p in chain) - lease.issued_at)
        _store(vault, lease)
    vault.audit(lease.id, actor, "lease.delegate", target["id"], True, {"parent_id": parent.id})
    return lease


def revoke(vault: Vault, handle: str, actor: str, child_id: str | None = None) -> bool:
    with transaction(vault):
        parent = _chain(vault, handle, actor, inactive=True)[0]
        target = parent
        if child_id is not None:
            target = vault._lease_from_row(_row(vault, child_id))
            current = target
            seen = set()
            while current.id != parent.id:
                if current.id in seen or current.parent_id is None or len(seen) >= MAX_DEPTH:
                    raise LeaseError("lease is not a descendant of this delegation")
                seen.add(current.id)
                current = vault._lease_from_row(_row(vault, current.parent_id))
        vault._conn.execute("UPDATE leases SET revoked=1 WHERE id=?", (target.id,))
    vault.audit(target.id, actor, "lease.revoke", target.context, True, {})
    return True


def inbox(vault: Vault, recipient: str) -> list[dict[str, Any]]:
    agent(vault, recipient)
    rows = vault._conn.execute(
        "SELECT * FROM leases WHERE json_extract(spec,'$.recipient')=? ORDER BY issued_at DESC LIMIT 100",
        (recipient,),
    ).fetchall()
    result = []
    for row in rows:
        try:
            with transaction(vault):
                lease = _chain(vault, row["id"], recipient, pending=True)[0]
            result.append(lease.public())
        except LeaseError:
            continue
    return result


def check_http(lease: Lease, method: str, url: str, credential: str) -> None:
    from .broker import host_matches
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.username is not None or parts.password is not None or parts.fragment:
        raise LeaseError("remote credential requests require an HTTPS URL without userinfo or fragment")
    if parts.port not in (None, 443):
        raise LeaseError("remote credential requests require HTTPS port 443")
    if method not in lease.http_methods:
        raise LeaseError("HTTP method is not allowed by this lease")
    if not any(path_matches(normalized_path(parts.path or "/"), p) for p in lease.path_prefixes):
        raise LeaseError("URL path is not allowed by this lease")
    if not any(host_matches(parts.hostname or "", host) for host in lease.host_policies.get(credential, [])):
        raise LeaseError("host is not allowed by this lease")
