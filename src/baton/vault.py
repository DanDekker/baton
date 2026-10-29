"""Encrypted-at-rest store: SQLite + committed AEAD envelope, BLAKE3 everywhere.

See `baton.crypto` for the primitive choices. This module is only storage policy:

  * one subkey per purpose (storage / lease / audit / commit), derived from a
    32-byte master seed;
  * AAD = `cred:<id>:<name>`, so a ciphertext cannot be relocated between
    records, let alone between databases;
  * an append-only BLAKE3 hash chain over the audit log, so credential use is
    tamper-evident;
  * master seed from BATON_MASTER_KEY, then passphrase+Argon2id, then the OS
    keyring, then a 0600 keyfile. The database alone is never sufficient.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from typing import Any

from . import crypto
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
ENV_PASSPHRASE = "BATON_PASSPHRASE"
SCHEMA_VERSION = 2

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS credentials(
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  provider TEXT NOT NULL,
  envelope BLOB NOT NULL,      -- committed AEAD envelope of the secret payload
  meta TEXT NOT NULL,          -- public: fields, expiry, scopes, notes, plan
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
  token_hash TEXT UNIQUE NOT NULL,   -- BLAKE3(token); token itself never at rest
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
  detail TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
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


class Vault:
    def __init__(
        self,
        state_dir: str | Path | None = None,
        master_key: bytes | None = None,
        passphrase: str | None = None,
    ):
        self.state_dir = Path(state_dir).expanduser() if state_dir else default_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.chmod(0o700)
        self.db_path = self.state_dir / "baton.db"
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        os.chmod(self.db_path, 0o600)

        self.mode = "unknown"
        self._master = self._resolve_master_key(master_key, passphrase)
        self._k_storage = crypto.subkey(self._master, "storage")
        self._k_lease = crypto.subkey(self._master, "lease")
        self._k_audit = crypto.subkey(self._master, "audit")
        self._k_commit = crypto.subkey(self._master, "commit")
        self._set_meta("schema_version", str(SCHEMA_VERSION))

    # ------------------------------------------------------------- lifecycle
    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def _get_meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._conn.commit()

    def _resolve_master_key(self, master_key: bytes | None, passphrase: str | None) -> bytes:
        if master_key is not None:
            if len(master_key) != crypto.KEY_LEN:
                raise VaultLocked("master key must be 32 bytes")
            self.mode = "provided"
            return master_key

        env_key = os.environ.get(ENV_MASTER_KEY)
        if env_key:
            self.mode = "env"
            return crypto.key_from_b64(env_key)

        passphrase = passphrase or os.environ.get(ENV_PASSPHRASE)
        if passphrase:
            import base64

            salt_b64 = self._get_meta("kdf_salt")
            if salt_b64:
                salt = base64.urlsafe_b64decode(salt_b64)
            else:
                salt = crypto.new_salt()
                self._set_meta("kdf_salt", base64.urlsafe_b64encode(salt).decode())
            self.mode = "passphrase"
            return crypto.derive_key_argon2id(passphrase, salt)

        try:
            import keyring

            stored = keyring.get_password(KEYRING_SERVICE, str(self.state_dir))
            if stored:
                self.mode = "keyring"
                return crypto.key_from_b64(stored)
            raw = crypto.new_master_key()
            keyring.set_password(KEYRING_SERVICE, str(self.state_dir), crypto.key_to_b64(raw))
            self.mode = "keyring"
            return raw
        except Exception:
            pass  # no usable backend -> keyfile

        keyfile = self.state_dir / "master.key"
        if keyfile.exists():
            self.mode = "keyfile"
            return crypto.key_from_b64(keyfile.read_text())
        raw = crypto.new_master_key()
        _hardened_write(keyfile, (crypto.key_to_b64(raw) + "\n").encode())
        self.mode = "keyfile"
        return raw

    # ----------------------------------------------------------- credentials
    @staticmethod
    def _cred_aad(ident: str, name: str) -> bytes:
        return f"cred:{ident}:{name}".encode()

    def get_credential_row(self, name: str) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM credentials WHERE name=?", (name,)).fetchone()

    def put_credential(self, cred: Credential) -> Credential:
        row = self.get_credential_row(cred.name)
        if row is not None:
            cred.id = row["id"]
            cred.created_at = row["created_at"]
        cred.updated_at = time.time()
        public = {
            "provider": cred.provider,
            "fields": sorted(cred.secret),
            "scopes": cred.scopes,
            "expires_at": cred.expires_at,
            "notes": cred.notes,
            "meta": cred.meta,
            "auth": cred.auth,
            "materialize": cred.materialize,
        }
        envelope = crypto.seal(
            self._k_storage,
            json.dumps(cred.secret).encode(),
            self._cred_aad(cred.id, cred.name),
            commit_key=self._k_commit,
        )
        self._conn.execute(
            "INSERT INTO credentials(id,name,provider,envelope,meta,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET provider=excluded.provider,"
            " envelope=excluded.envelope, meta=excluded.meta,"
            " updated_at=excluded.updated_at",
            (
                cred.id,
                cred.name,
                cred.provider,
                envelope,
                json.dumps(public),
                cred.created_at,
                cred.updated_at,
            ),
        )
        self._conn.commit()
        self.audit(
            None, None, "credential.put", cred.name, True, {"fields": sorted(cred.secret)}
        )
        return cred

    def get_credential(self, name: str) -> Credential:
        row = self.get_credential_row(name)
        if row is None:
            raise UnknownCredential(name)
        pub = json.loads(row["meta"])
        secret = json.loads(
            crypto.open_envelope(
                self._k_storage,
                row["envelope"],
                self._cred_aad(row["id"], row["name"]),
                commit_key=self._k_commit,
            )
        )
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
            "SELECT name, provider, meta FROM credentials ORDER BY name"
        ).fetchall()
        out = []
        for r in rows:
            pub = json.loads(r["meta"])
            exp = pub.get("expires_at")
            out.append(
                {
                    "name": r["name"],
                    "provider": r["provider"],
                    "fields": pub.get("fields", []),
                    "scopes": pub.get("scopes", []),
                    "expires_at": exp,
                    "expired": exp is not None and exp <= time.time(),
                    "notes": pub.get("notes", ""),
                }
            )
        return out

    def delete_credential(self, name: str) -> bool:
        cur = self._conn.execute("DELETE FROM credentials WHERE name=?", (name,))
        self._conn.commit()
        if cur.rowcount:
            self.audit(None, None, "credential.delete", name, True, {})
        return cur.rowcount > 0

    # -------------------------------------------------------------- contexts
    def put_context(self, ctx: Context) -> Context:
        row = self._conn.execute(
            "SELECT id, created_at FROM contexts WHERE name=?", (ctx.name,)
        ).fetchone()
        if row is not None:
            ctx.id = row["id"]
            ctx.created_at = row["created_at"]
        for name in ctx.credentials:
            if self.get_credential_row(name) is None:
                raise UnknownCredential(f"context {ctx.name} references unknown {name}")
        ctx.updated_at = time.time()
        spec = {
            "credentials": ctx.credentials,
            "description": ctx.description,
            "passthrough": ctx.passthrough,
            "env": ctx.env,
            "inherit_paths": ctx.inherit_paths,
        }
        self._conn.execute(
            "INSERT INTO contexts(id,name,spec,created_at,updated_at) VALUES(?,?,?,?,?)"
            " ON CONFLICT(name) DO UPDATE SET spec=excluded.spec,"
            " updated_at=excluded.updated_at",
            (ctx.id, ctx.name, json.dumps(spec), ctx.created_at, ctx.updated_at),
        )
        self._conn.commit()
        self.audit(None, None, "context.put", ctx.name, True, {"credentials": ctx.credentials})
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
        if cur.rowcount:
            self.audit(None, None, "context.delete", name, True, {})
        return cur.rowcount > 0

    # ---------------------------------------------------------------- leases
    def _sign(self, body: str) -> str:
        return crypto.mac_hex(self._k_lease, body.encode(), 32)

    def issue_lease(
        self,
        context: str,
        subject: str,
        services: list[str] | None = None,
        ttl: float = 900.0,
        max_uses: int | None = None,
    ) -> Lease:
        self.get_context(context)  # raises UnknownContext
        lease = Lease(
            context=context,
            subject=subject,
            services=list(services or []),
            ttl=float(ttl),
            max_uses=max_uses,
        )
        body = crypto.b64u_encode(
            json.dumps(
                {
                    "i": lease.id,
                    "c": lease.context,
                    "e": int(lease.expires_at),
                    "n": secrets.token_hex(8),
                },
                separators=(",", ":"),
            ).encode()
        )
        lease.token = f"btn_{body}.{self._sign(body)}"
        self._conn.execute(
            "INSERT INTO leases(id,token_hash,context_name,subject,spec,issued_at,"
            "expires_at,max_uses,uses,revoked) VALUES(?,?,?,?,?,?,?,?,0,0)",
            (
                lease.id,
                crypto.digest(lease.token.encode(), 32).hex(),
                lease.context,
                lease.subject,
                json.dumps({"services": lease.services}),
                lease.issued_at,
                lease.expires_at,
                lease.max_uses,
            ),
        )
        self._conn.commit()
        self.audit(
            lease.id,
            lease.subject,
            "lease.issue",
            lease.context,
            True,
            {"services": lease.services, "ttl": ttl, "max_uses": max_uses},
        )
        return lease

    @staticmethod
    def _lease_from_row(row: sqlite3.Row) -> Lease:
        spec = json.loads(row["spec"])
        return Lease(
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

    def resolve_lease(self, token: str, consume: bool = True) -> Lease:
        """Verify signature, then DB state (revocation, TTL, use budget)."""
        try:
            body, sig = token.strip().split(".", 1)
        except ValueError:
            raise LeaseError("malformed lease token")
        body = body.removeprefix("btn_")
        if not secrets.compare_digest(sig, self._sign(body)):
            raise LeaseError("lease signature invalid")
        try:
            payload = json.loads(crypto.b64u_decode(body))
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

    # ----------------------------------------------------------- audit chain
    def _last_hash(self) -> str:
        row = self._conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return row["hash"] if row else "00" * 32

    def audit(
        self,
        lease_id: str | None,
        subject: str | None,
        action: str,
        target: str | None,
        ok: bool,
        detail: dict[str, Any] | None = None,
    ) -> None:
        ts = time.time()
        detail = detail or {}
        prev = self._last_hash()
        entry = self._entry(ts, lease_id, subject, action, target, ok, detail)
        h = crypto.chain(bytes.fromhex(prev), entry).hex()
        self._conn.execute(
            "INSERT INTO audit(ts,lease_id,subject,action,target,ok,detail,prev_hash,hash)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (
                ts,
                lease_id,
                subject,
                action,
                target,
                int(ok),
                json.dumps(detail, sort_keys=True, separators=(",", ":")),
                prev,
                h,
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
                "hash": r["hash"],
            }
            for r in rows
        ]

    @staticmethod
    def _entry(
        ts: float,
        lease_id: str | None,
        subject: str | None,
        action: str,
        target: str | None,
        ok: bool,
        detail: dict[str, Any],
    ) -> bytes:
        """Canonical bytes hashed into the chain: every column, so rewriting any
        field (not just the detail blob) invalidates it."""
        return json.dumps(
            {
                "ts": ts,
                "lease_id": lease_id,
                "subject": subject,
                "action": action,
                "target": target,
                "ok": bool(ok),
                "detail": detail,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def verify_audit(self) -> tuple[bool, int]:
        """Recompute the chain. Returns (intact, first_bad_seq)."""
        prev = b"\x00" * 32
        rows = self._conn.execute("SELECT * FROM audit ORDER BY seq ASC").fetchall()
        for r in rows:
            entry = self._entry(
                r["ts"],
                r["lease_id"],
                r["subject"],
                r["action"],
                r["target"],
                bool(r["ok"]),
                json.loads(r["detail"] or "{}"),
            )
            if crypto.chain(prev, entry).hex() != r["hash"] or r["prev_hash"] != prev.hex():
                return False, r["seq"]
            prev = bytes.fromhex(r["hash"])
        return True, 0

    # ----------------------------------------------------------------- misc
    def stats(self) -> dict[str, Any]:
        def count(table: str) -> int:
            return self._conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]

        return {
            "state_dir": str(self.state_dir),
            "key_mode": self.mode,
            "cipher": "aes-256-gcm-siv"
            if crypto.DEFAULT_CIPHER == crypto.CIPHER_GCM_SIV
            else "chacha20-poly1305",
            "hash": "blake3",
            "schema": SCHEMA_VERSION,
            "credentials": count("credentials"),
            "contexts": count("contexts"),
            "leases": count("leases"),
            "audit_events": count("audit"),
        }
