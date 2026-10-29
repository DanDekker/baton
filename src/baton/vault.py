"""Encrypted-at-rest store: SQLite + AES-GCM envelope, key in the OS keyring.

Design notes:
  * Secrets are encrypted per record with AAD = record identity, so ciphertext
    cannot be swapped between records.
  * The master key lives in the OS keyring (macOS Keychain / Secret Service /
    Windows Credential Locker). Headless hosts fall back to BATON_MASTER_KEY,
    then to a 0600 keyfile next to the DB. The DB alone is never enough.
  * Leases store only a hash of their token; the token itself is never at rest.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import (
    Context,
    Credential,
    Lease,
    LeaseError,
    UnknownContext,
    UnknownCredential,
    VaultLocked,
)

KEYRING_SERVICE = "baton"
ENV_MASTER_KEY = "BATON_MASTER_KEY"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS credentials(
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  provider TEXT NOT NULL,
  nonce BLOB NOT NULL,
  blob BLOB NOT NULL,
  meta TEXT NOT NULL,          -- public, unencrypted (expiry, scopes, notes)
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS contexts(
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  spec TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS leases(
  id TEXT PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  context_name TEXT NOT NULL,
  subject TEXT NOT NULL,
  spec TEXT NOT NULL,
  issued_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  max_uses INTEGER,
  uses INTEGER NOT NULL DEFAULT 0,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  lease_id TEXT,
  subject TEXT,
  action TEXT NOT NULL,
  target TEXT,
  ok INTEGER NOT NULL,
  detail TEXT
);
"""


def default_state_dir() -> Path:
    env = os.environ.get("BATON_STATE_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "baton"


def _hardened_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _load_master_key(state_dir: Path, create: bool = True) -> bytes:
    env_key = os.environ.get(ENV_MASTER_KEY)
    if env_key:
        raw = base64.urlsafe_b64decode(env_key.encode() + b"=" * (-len(env_key) % 4))
        if len(raw) != 32:
            raise VaultLocked(f"{ENV_MASTER_KEY} must be 32 bytes, base64-encoded")
        return raw

    try:
        import keyring
        import keyring.errors

        stored = keyring.get_password(KEYRING_SERVICE, str(state_dir))
        if stored:
            return base64.urlsafe_b64decode(stored.encode())
        if not create:
            raise VaultLocked("no master key in OS keyring")
        raw = secrets.token_bytes(32)
        keyring.set_password(
            KEYRING_SERVICE, str(state_dir), base64.urlsafe_b64encode(raw).decode()
        )
        return raw
    except VaultLocked:
        raise
    except Exception:
        pass  # no usable keyring backend -> keyfile fallback

    keyfile = state_dir / "master.key"
    if keyfile.exists():
        return base64.urlsafe_b64decode(keyfile.read_bytes().strip())
    if not create:
        raise VaultLocked(f"no master key at {keyfile}")
    raw = secrets.token_bytes(32)
    _hardened_write(keyfile, base64.urlsafe_b64encode(raw))
    return raw


class Vault:
    def __init__(self, state_dir: str | Path | None = None, master_key: bytes | None = None):
        self.state_dir = Path(state_dir).expanduser() if state_dir else default_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.chmod(0o700)
        self.db_path = self.state_dir / "baton.db"
        self._key = master_key or _load_master_key(self.state_dir)
        self._aead = AESGCM(self._key)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        os.chmod(self.db_path, 0o600)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Vault:
        return self

    def __enter__(self) -> "Vault":  # type: ignore[no-redef]
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------------------------------------------------------- crypto
    def _seal(self, ident: str, name: str, payload: dict[str, Any]) -> tuple[bytes, bytes]:
        nonce = secrets.token_bytes(12)
        aad = f"{ident}\x00{name}".encode()
        blob = self._aead.encrypt(nonce, json.dumps(payload).encode(), aad)
        return nonce, blob

    def _open(self, ident: str, name: str, nonce: bytes, blob: bytes) -> dict[str, Any]:
        aad = f"{ident}\x00{name}".encode()
        return json.loads(self._aead.decrypt(nonce, blob, aad).decode())

    # ----------------------------------------------------------- credentials
    def put_credential(self, cred: Credential) -> Credential:
        existing = self.get_credential_row(cred.name)
        if existing:
            cred.id = existing["id"]
            cred.created_at = existing["created_at"]
        cred.updated_at = time.time()
        public = {
            "scopes": cred.scopes,
            "expires_at": cred.expires_at,
            "notes": cred.notes,
            "meta": cred.meta,
            "auth": cred.auth,
            "materialize": cred.materialize,
            "fields": sorted(cred.secret),
        }
        nonce, blob = self._seal(cred.id, cred.name, cred.secret)
        self._conn.execute(
            "INSERT INTO credentials(id,name,provider,nonce,blob,meta,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET provider=excluded.provider,"
            " nonce=excluded.nonce, blob=excluded.blob, meta=excluded.meta,"
            " updated_at=excluded.updated_at",
            (
                cred.id,
                cred.name,
                cred.provider,
                nonce,
                blob,
                json.dumps(public),
                cred.created_at,
                cred.updated_at,
            ),
        )
        self._conn.commit()
        return cred

    def get_credential_row(self, name: str) -> sqlite3.Row | None:
        cur = self._conn.execute("SELECT * FROM credentials WHERE name=?", (name,))
        return cur.fetchone()

    def get_credential(self, name: str) -> Credential:
        row = self.get_credential_row(name)
        if row is None:
            raise UnknownCredential(name)
        pub = json.loads(row["meta"])
        secret = self._open(row["id"], row["name"], row["nonce"], row["blob"])
        return Credential(
            name=row["name"],
            provider=row["provider"],
            secret=secret,
            materialize=pub.get("materialize", []),
            auth=pub.get("auth", {}),
            scopes=pub.get("scopes", []),
            expires_at=pub.get("expires_at"),
            notes=pub.get("notes", ""),
            meta=pub.get("meta", {}),
            id=row["id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list_credentials(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, provider, meta, created_at, updated_at FROM credentials ORDER BY name"
        ).fetchall()
        out = []
        for r in rows:
            pub = json.loads(r["meta"])
            out.append(
                {
                    "name": r["name"],
                    "provider": r["provider"],
                    "fields": pub.get("fields", []),
                    "scopes": pub.get("scopes", []),
                    "expires_at": pub.get("expires_at"),
                    "expired": pub.get("expires_at") is not None
                    and pub["expires_at"] <= time.time(),
                    "notes": pub.get("notes", ""),
                }
            )
        return out

    def delete_credential(self, name: str) -> bool:
        cur = self._conn.execute("DELETE FROM credentials WHERE name=?", (name,))
        self._conn.commit()
        return cur.rowcount > 0

    # -------------------------------------------------------------- contexts
    def put_context(self, ctx: Context) -> Context:
        existing = self._conn.execute(
            "SELECT id, created_at FROM contexts WHERE name=?", (ctx.name,)
        ).fetchone()
        if existing:
            ctx.id = existing["id"]
            ctx.created_at = existing["created_at"]
        ctx.updated_at = time.time()
        for name in ctx.credentials:
            if self.get_credential_row(name) is None:
                raise UnknownCredential(f"context {ctx.name} references unknown {name}")
        spec = {
            "credentials": ctx.credentials,
            "description": ctx.description,
            "passthrough": ctx.passthrough,
            "env": ctx.env,
            "inherit_paths": ctx.inherit_paths,
        }
        self._conn.execute(
            "INSERT INTO contexts(id,name,spec,created_at,updated_at) VALUES(?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET spec=excluded.spec, updated_at=excluded.updated_at",
            (ctx.id, ctx.name, json.dumps(spec), ctx.created_at, ctx.updated_at),
        )
        self._conn.commit()
        return ctx

    def get_context(self, name: str) -> Context:
        row = self._conn.execute("SELECT * FROM contexts WHERE name=?", (name,)).fetchone()
        if row is None:
            raise UnknownContext(name)
        spec = json.loads(row["spec"])
        return Context(
            name=row["name"],
            credentials=spec.get("credentials", []),
            description=spec.get("description", ""),
            passthrough=spec.get("passthrough", []),
            env=spec.get("env", {}),
            inherit_paths=spec.get("inherit_paths", []),
            id=row["id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list_contexts(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM contexts ORDER BY name").fetchall()
        out = []
        for r in rows:
            spec = json.loads(r["spec"])
            out.append(
                {
                    "name": r["name"],
                    "description": spec.get("description", ""),
                    "credentials": spec.get("credentials", []),
                    "env": spec.get("env", {}),
                }
            )
        return out

    def delete_context(self, name: str) -> bool:
        cur = self._conn.execute("DELETE FROM contexts WHERE name=?", (name,))
        self._conn.commit()
        return cur.rowcount > 0

    # ---------------------------------------------------------------- leases
    def _lease_sign_key(self) -> bytes:
        return hmac.new(self._key, b"baton/lease/v1", hashlib.sha256).digest()

    def _sign(self, body: str) -> str:
        sig = hmac.new(self._lease_sign_key(), body.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(sig).decode().rstrip("=")

    def issue_lease(
        self,
        context: str,
        subject: str,
        services: list[str] | None = None,
        ttl: float = 900.0,
        max_uses: int | None = None,
    ) -> Lease:
        ctx = self.get_context(context)  # raises if unknown
        lease = Lease(
            context=ctx.name,
            subject=subject,
            services=list(services or []),
            ttl=float(ttl),
            max_uses=max_uses,
        )
        body = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "i": lease.id,
                    "c": lease.context,
                    "e": int(lease.expires_at),
                    "n": secrets.token_hex(8),
                },
                separators=(",", ":"),
            ).encode()
        ).decode().rstrip("=")
        lease.token = f"btn_{body}.{self._sign(body)}"
        self._conn.execute(
            "INSERT INTO leases(id,token_hash,context_name,subject,spec,issued_at,"
            "expires_at,max_uses,uses,revoked) VALUES(?,?,?,?,?,?,?,?,0,0)",
            (
                lease.id,
                hashlib.sha256(lease.token.encode()).hexdigest(),
                lease.context,
                lease.subject,
                json.dumps({"services": lease.services}),
                lease.issued_at,
                lease.expires_at,
                lease.max_uses,
            ),
        )
        self._conn.commit()
        self.audit(lease.id, lease.subject, "lease.issue", lease.context, True, {
            "services": lease.services, "ttl": ttl
        })
        return lease

    def _lease_from_row(self, row: sqlite3.Row) -> Lease:
        spec = json.loads(row["spec"])
        lease = Lease(
            context=row["context_name"],
            subject=row["subject"],
            services=spec.get("services", []),
            ttl=row["expires_at"] - row["issued_at"],
            max_uses=row["max_uses"],
            id=row["id"],
            issued_at=row["issued_at"],
            uses=row["uses"],
            revoked=bool(row["revoked"]),
        )
        return lease

    def resolve_lease(self, token: str, consume: bool = True) -> Lease:
        """Verify signature, then DB state (revocation, TTL, use budget)."""
        try:
            body, sig = token.strip().split(".", 1)
        except ValueError:
            raise LeaseError("malformed lease token")
        if not hmac.compare_digest(sig, self._sign(body)):
            raise LeaseError("lease signature invalid")
        try:
            payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except Exception:
            raise LeaseError("malformed lease payload")
        row = self._conn.execute(
            "SELECT * FROM leases WHERE id=?", (payload.get("i"),)
        ).fetchone()
        if row is None:
            raise LeaseError("lease not found")
        lease = self._lease_from_row(row)
        lease.ensure_valid()
        if consume:
            self._conn.execute("UPDATE leases SET uses=uses+1 WHERE id=?", (lease.id,))
            self._conn.commit()
            lease.uses += 1
        return lease

    def revoke_lease(self, lease_id: str) -> bool:
        cur = self._conn.execute("UPDATE leases SET revoked=1 WHERE id=?", (lease_id,))
        self._conn.commit()
        if cur.rowcount:
            self.audit(lease_id, None, "lease.revoke", lease_id, True, {})
        return cur.rowcount > 0

    def list_leases(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM leases ORDER BY issued_at DESC").fetchall()
        return [self._lease_from_row(r).public() for r in rows]

    # ----------------------------------------------------------------- audit
    def audit(
        self,
        lease_id: str | None,
        subject: str | None,
        action: str,
        target: str | None,
        ok: bool,
        detail: dict[str, Any] | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO audit(ts,lease_id,subject,action,target,ok,detail)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                time.time(),
                lease_id,
                subject,
                action,
                target,
                int(ok),
                json.dumps(detail or {}),
            ),
        )
        self._conn.commit()

    def audit_tail(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            {
                "seq": r["seq"],
                "ts": r["ts"],
                "lease_id": r["lease_id"],
                "subject": r["subject"],
                "action": r["action"],
                "target": r["target"],
                "ok": bool(r["ok"]),
                "detail": json.loads(r["detail"] or "{}"),
            }
            for r in rows
        ]
