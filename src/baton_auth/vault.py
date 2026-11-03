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

import functools
import json
import os
import secrets
import sqlite3
import stat
import threading
import tempfile
import time
from pathlib import Path
from typing import Any

from . import crypto
from .models import (
    BatonError,
    Context,
    Credential,
    Lease,
    LeaseError,
    RefreshError,
    UnknownContext,
    UnknownCredential,
    VaultLocked,
    validate_lease_limits,
)

KEYRING_SERVICE = "baton"
ENV_MASTER_KEY = "BATON_MASTER_KEY"
ENV_PASSPHRASE = "BATON_PASSPHRASE"
SCHEMA_VERSION = 4

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
CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
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
    fd, tmp = tempfile.mkstemp(prefix=".baton-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


class _LockedConn:
    """Serializes access to one sqlite connection.

    MCP runs synchronous tool functions on worker threads, so a single Vault is
    touched from several threads over its lifetime. sqlite refuses that unless
    check_same_thread=False, and a shared connection still needs serialization.
    """

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock):
        self._conn = conn
        self._lock = lock

    def execute(self, sql: str, params: object = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, params)

    def executescript(self, script: str) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.executescript(script)

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def rollback(self) -> None:
        with self._lock:
            self._conn.rollback()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _atomic(method):
    """Hold the vault lock for a whole read-modify-write sequence."""

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


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
        self._lock = threading.RLock()
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        self._conn = _LockedConn(conn, self._lock)
        try:
            self._conn.execute("PRAGMA busy_timeout=5000;")
            deadline = time.monotonic() + 5
            while True:
                try:
                    self._conn.execute("PRAGMA journal_mode=WAL;")
                    break
                except sqlite3.OperationalError as exc:
                    # Switching a new database to WAL can return BUSY without
                    # invoking SQLite's busy handler during concurrent opens.
                    if str(exc) != "database is locked" or time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
            self._conn.execute("PRAGMA synchronous=FULL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA secure_delete=ON;")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            os.chmod(self.db_path, 0o600)
        except sqlite3.DatabaseError:
            self._conn.close()
            raise VaultLocked("cannot open vault database; check for damage or another writer") from None
        except BaseException:
            self._conn.close()
            raise

        self.mode = "unknown"
        try:
            # Keyring and keyfile creation must share the database's process lock.
            self._conn.execute("BEGIN IMMEDIATE")
            self._master = bytearray(self._resolve_master_key(master_key, passphrase))
            self._k_storage = bytearray(crypto.subkey(self._master, "storage"))
            self._k_lease = bytearray(crypto.subkey(self._master, "lease"))
            self._k_audit = bytearray(crypto.subkey(self._master, "audit"))
            self._k_commit = bytearray(crypto.subkey(self._master, "commit"))
            self._verify_master_key()
            self._conn.commit()
            self._migrate_credentials()
        except BaseException:
            self._conn.rollback()
            self.close()
            raise

    # ------------------------------------------------------------- lifecycle
    def _verify_master_key(self) -> None:
        check = crypto.mac_hex(self._k_commit, b"baton/vault-key-check", 32)
        stored = self._get_meta("key_check")
        if stored is not None:
            if not isinstance(stored, str) or not stored.isascii() or not secrets.compare_digest(stored, check):
                raise VaultLocked("master key does not match this vault")
            return
        row = self._conn.execute("SELECT * FROM credentials LIMIT 1").fetchone()
        if row is not None:
            crypto.open_envelope(
                self._k_storage, row["envelope"],
                self._cred_aad(row["id"], row["name"]), commit_key=self._k_commit,
            )
        self._conn.execute("INSERT INTO meta(key,value) VALUES('key_check',?)", (check,))

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()
        for k in (
            getattr(self, "_master", None),
            getattr(self, "_k_storage", None),
            getattr(self, "_k_lease", None),
            getattr(self, "_k_audit", None),
            getattr(self, "_k_commit", None),
        ):
            if k is not None:
                crypto.zeroize(k)

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
                self._conn.execute(
                    "INSERT INTO meta(key,value) VALUES('kdf_salt',?)",
                    (base64.urlsafe_b64encode(salt).decode(),),
                )
            self.mode = "passphrase"
            return crypto.derive_key_argon2id(passphrase, salt)

        try:
            import keyring

            stored = keyring.get_password(KEYRING_SERVICE, str(self.state_dir))
            if stored:
                self.mode = "keyring"
                return crypto.key_from_b64(stored)
            keyfile = self.state_dir / "master.key"
            if keyfile.exists():
                self.mode = "keyfile"
                return crypto.key_from_b64(keyfile.read_text())
            if self._get_meta("schema_version") is not None:
                raise VaultLocked("vault key is unavailable; unlock the keyring or provide the original key")
            raw = crypto.new_master_key()
            keyring.set_password(KEYRING_SERVICE, str(self.state_dir), crypto.key_to_b64(raw))
            self.mode = "keyring"
            return raw
        except VaultLocked:
            raise
        except Exception:
            pass  # no usable backend -> keyfile

        keyfile = self.state_dir / "master.key"
        if keyfile.exists():
            self.mode = "keyfile"
            return crypto.key_from_b64(keyfile.read_text())
        if self._get_meta("schema_version") is not None:
            raise VaultLocked("vault key is unavailable; unlock the keyring or provide the original key")
        raw = crypto.new_master_key()
        _hardened_write(keyfile, (crypto.key_to_b64(raw) + "\n").encode())
        self.mode = "keyfile"
        return raw

    # ----------------------------------------------------------- credentials
    def _migrate_credentials(self) -> None:
        """Move legacy refresh settings into the authenticated payload atomically."""
        if self._get_meta("schema_version") == str(SCHEMA_VERSION):
            return
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            version = int(self._get_meta("schema_version") or 0)
            if version > SCHEMA_VERSION:
                raise VaultLocked(
                    "vault was written by a newer baton version; upgrade baton"
                )
            if version < 4:
                rows = self._conn.execute("SELECT * FROM credentials ORDER BY id")
                for row in rows:
                    public = json.loads(row["meta"])
                    payload = json.loads(
                        crypto.open_envelope(
                            self._k_storage, row["envelope"],
                            self._cred_aad(row["id"], row["name"]),
                            commit_key=self._k_commit,
                        )
                    )
                    if payload.get("format") == "baton.credential.v4":
                        secret, refresh = payload["secret"], payload["refresh"]
                    else:
                        secret, refresh = payload, public.get("refresh", {})
                    envelope = self._seal_credential(row["id"], row["name"], secret, refresh)
                    public["refresh"] = self._public_refresh(refresh)
                    self._conn.execute(
                        "UPDATE credentials SET envelope=?,meta=? WHERE id=?",
                        (envelope, json.dumps(public), row["id"]),
                    )
                self._conn.execute(
                    "INSERT OR REPLACE INTO meta(key,value) VALUES('schema_version',?)",
                    (str(SCHEMA_VERSION),),
                )
            self._conn.commit()
        except BaseException:
            self._conn.rollback()
            raise
        if version < 4:
            # Retire old WAL frames when no other connection is holding them.
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    @staticmethod
    def _public_refresh(refresh: dict[str, Any]) -> dict[str, Any]:
        if not refresh:
            return {}
        return {"provider": refresh.get("provider") or refresh.get("type") or "oauth2"}

    def _seal_credential(
        self, ident: str, name: str, secret: dict[str, str], refresh: dict[str, Any]
    ) -> bytes:
        return crypto.seal(
            self._k_storage,
            json.dumps({"format": "baton.credential.v4", "secret": secret, "refresh": refresh}).encode(),
            self._cred_aad(ident, name),
            commit_key=self._k_commit,
        )

    @staticmethod
    def _cred_aad(ident: str, name: str) -> bytes:
        return f"cred:{ident}:{name}".encode()

    def get_credential_row(self, name: str) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM credentials WHERE name=?", (name,)).fetchone()

    def get_credential_provider(self, name: str) -> str | None:
        """Look up public metadata without loading the encrypted payload."""
        row = self._conn.execute(
            "SELECT provider FROM credentials WHERE name=?", (name,)
        ).fetchone()
        return row["provider"] if row else None

    @_atomic
    def put_credential(self, cred: Credential) -> Credential:
        self._check_name(cred.name)
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
            "refresh": self._public_refresh(cred.refresh),
            "allowed_hosts": cred.allowed_hosts,
        }
        envelope = self._seal_credential(cred.id, cred.name, cred.secret, cred.refresh)
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

    def get_credential(
        self,
        name: str,
        *,
        auto_refresh: bool = False,
        skew: float = 60.0,
    ) -> Credential:
        if auto_refresh:
            cred, _ = self.refresh_credential(name, force=False, skew=skew)
            return cred

        row = self.get_credential_row(name)
        if row is None:
            raise UnknownCredential(f"unknown credential {name!r} (see `baton cred list`)")
        pub = json.loads(row["meta"])
        private = json.loads(
            crypto.open_envelope(
                self._k_storage,
                row["envelope"],
                self._cred_aad(row["id"], row["name"]),
                commit_key=self._k_commit,
            )
        )
        if private.get("format") != "baton.credential.v4":
            raise VaultLocked("credential format is outdated; stop older baton processes and upgrade the vault")
        return Credential(
            name=row["name"],
            provider=row["provider"],
            secret=private["secret"],
            materialize=pub.get("materialize", []),
            auth=pub.get("auth", {}),
            refresh=private["refresh"],
            allowed_hosts=pub.get("allowed_hosts", []),
            scopes=pub.get("scopes", []),
            expires_at=pub.get("expires_at"),
            notes=pub.get("notes", ""),
            meta=pub.get("meta", {}),
            id=row["id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def refresh_credential(
        self,
        name: str,
        *,
        force: bool = False,
        skew: float = 60.0,
    ) -> tuple[Credential, bool]:
        """Refresh a credential if it is expired or expiring within `skew` seconds.

        Returns (credential, did_refresh: bool).
        """
        with self._lock:
            cred = self.get_credential(name, auto_refresh=False)
            if not cred.refresh:
                return cred, False
            if not force and not cred.expired(skew=skew):
                return cred, False

            try:
                self._conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError:
                raise RefreshError("vault is busy; retry credential refresh") from None
            try:
                cred = self.get_credential(name, auto_refresh=False)
                if not cred.refresh:
                    return cred, False
                if not force and not cred.expired(skew=skew):
                    return cred, False

                from .refresh import execute_refresh

                result = execute_refresh(cred)
                cred.secret.update(result.secret_updates)
                # A replacement token without a lifetime must not inherit the old
                # token's expired deadline and trigger a refresh on every request.
                cred.expires_at = result.expires_at
                if result.notes is not None:
                    cred.notes = result.notes
                if result.meta_updates:
                    cred.meta.update(result.meta_updates)

                self.put_credential(cred)
                self.audit(
                    None,
                    None,
                    "credential.refresh",
                    cred.name,
                    True,
                    {
                        "expires_at": cred.expires_at,
                        "provider": cred.refresh.get("provider") or cred.refresh.get("type"),
                        "updated_fields": sorted(result.secret_updates),
                    },
                )
                return cred, True
            finally:
                # put_credential commits successful rotations; failures and early
                # returns must release the lock without changing the old record.
                self._conn.rollback()

    def list_credentials(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, provider, meta FROM credentials ORDER BY name"
        ).fetchall()
        out = []
        for r in rows:
            pub = json.loads(r["meta"])
            exp = pub.get("expires_at")
            ref = pub.get("refresh") or {}
            out.append(
                {
                    "name": r["name"],
                    "provider": r["provider"],
                    "fields": pub.get("fields", []),
                    "scopes": pub.get("scopes", []),
                    "expires_at": exp,
                    "expired": exp is not None and exp <= time.time(),
                    "refreshable": bool(ref),
                    "refresh_provider": ref.get("provider") or ref.get("type"),
                    "allowed_hosts": pub.get("allowed_hosts", []),
                    "notes": pub.get("notes", ""),
                }
            )
        return out

    @_atomic
    def delete_credential(self, name: str) -> bool:
        cur = self._conn.execute("DELETE FROM credentials WHERE name=?", (name,))
        self._conn.commit()
        if cur.rowcount:
            self.audit(None, None, "credential.delete", name, True, {})
        return cur.rowcount > 0

    # -------------------------------------------------------------- contexts
    @staticmethod
    def _check_name(name: str) -> None:
        if not isinstance(name, str) or not name or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise BatonError("record name must be nonempty and contain no control characters")

    @_atomic
    def put_context(self, ctx: Context) -> Context:
        self._check_name(ctx.name)
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
            raise UnknownContext(f"unknown context {name!r} (see `baton ctx list`)")
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

    def resolve_context(self, name: str | None = None) -> Context:
        """Resolve an explicit context, a standalone credential, or the default context."""
        if name:
            row = self._conn.execute("SELECT * FROM contexts WHERE name=?", (name,)).fetchone()
            if row is not None:
                return self.get_context(name)
            if self.get_credential_row(name) is not None:
                return Context(
                    name=name,
                    credentials=[name],
                    description=f"credential {name}",
                )
            if name == "default":
                creds = [c["name"] for c in self.list_credentials()]
                if creds:
                    return Context(
                        name="default",
                        credentials=creds,
                        description="all stored credentials",
                    )
            raise UnknownContext(f"unknown context or credential {name!r} (see `baton list`)")

        default_row = self._conn.execute(
            "SELECT name FROM contexts WHERE name='default'"
        ).fetchone()
        if default_row is not None:
            return self.get_context("default")
        ctxs = self.list_contexts()
        if len(ctxs) == 1:
            return self.get_context(ctxs[0]["name"])
        creds = self.list_credentials()
        if len(creds) == 1:
            cname = creds[0]["name"]
            return Context(
                name=cname,
                credentials=[cname],
                description=f"credential {cname}",
            )
        if creds and not ctxs:
            return Context(
                name="default",
                credentials=[c["name"] for c in creds],
                description="all stored credentials",
            )
        raise UnknownContext("specify a context or credential name (see `baton list`)")

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
                    "env_names": sorted(spec.get("env", {})),
                }
            )
        return out

    @_atomic
    def delete_context(self, name: str) -> bool:
        cur = self._conn.execute("DELETE FROM contexts WHERE name=?", (name,))
        self._conn.commit()
        if cur.rowcount:
            self.audit(None, None, "context.delete", name, True, {})
        return cur.rowcount > 0

    # ---------------------------------------------------------------- leases
    def _sign(self, body: str) -> str:
        return crypto.mac_hex(self._k_lease, body.encode(), 32)

    @_atomic
    def issue_lease(
        self,
        context: str | None = None,
        subject: str = "cli",
        services: list[str] | None = None,
        ttl: float = 900.0,
        max_uses: int | None = None,
        *,
        recipient: str | None = None,
        delegatable: bool = False,
        http_methods: list[str] | None = None,
        path_prefixes: list[str] | None = None,
        task: dict[str, Any] | None = None,
    ) -> Lease:
        validate_lease_limits(ttl, max_uses)
        if recipient is not None:
            from .delegation import issue
            return issue(
                self, context, recipient, services=services, ttl=ttl, max_uses=max_uses,
                delegatable=delegatable, http_methods=http_methods,
                path_prefixes=path_prefixes, task=task,
            )
        resolved = self.resolve_context(context)
        context = resolved.name
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
            **{key: spec[key] for key in (
                "recipient", "parent_id", "delegatable", "credential_ids",
                "host_policies", "http_methods", "path_prefixes", "accepted_at", "task",
            ) if key in spec},
        )

    def _lease_token_id(self, token: str) -> str:
        if not isinstance(token, str) or len(token) > 4096 or not token.startswith("btn_") or not token.isascii():
            raise LeaseError("malformed lease token")
        try:
            body, sig = token[4:].split(".", 1)
        except ValueError:
            raise LeaseError("malformed lease token") from None
        if not secrets.compare_digest(sig, self._sign(body)):
            raise LeaseError("lease signature invalid")
        try:
            payload = json.loads(crypto.b64u_decode(body))
        except (ValueError, TypeError, RecursionError):
            raise LeaseError("malformed lease payload") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("i"), str) or not payload["i"]:
            raise LeaseError("malformed lease payload")
        return payload["i"]

    @_atomic
    def resolve_lease(
        self, token: str, consume: bool = True, *, recipient: str | None = None,
    ) -> Lease:
        """Verify signature, then DB state (revocation, TTL, use budget)."""
        if recipient is not None:
            from .delegation import resolve
            return resolve(self, token, recipient, consume=consume)
        lease_id = self._lease_token_id(token)
        row = self._conn.execute(
            "SELECT * FROM leases WHERE id=?", (lease_id,)
        ).fetchone()
        if row is None:
            raise LeaseError("lease not found")
        if not secrets.compare_digest(row["token_hash"], crypto.digest(token.encode(), 32).hex()):
            raise LeaseError("lease token does not match stored grant")
        lease = self._lease_from_row(row)
        if lease.recipient is not None:
            raise LeaseError("recipient-bound leases require an authenticated remote identity")
        lease.ensure_valid()
        if consume:
            cur = self._conn.execute(
                "UPDATE leases SET uses=uses+1 WHERE id=? AND revoked=0 "
                "AND uses < 9223372036854775807 "
                "AND (max_uses IS NULL OR uses < max_uses) "
                "AND expires_at > (julianday('now') - 2440587.5) * 86400.0",
                (lease.id,),
            )
            self._conn.commit()
            if cur.rowcount == 0:
                fresh = self._conn.execute(
                    "SELECT * FROM leases WHERE id=?", (lease.id,)
                ).fetchone()
                if fresh is not None:
                    self._lease_from_row(fresh).ensure_valid()
                raise LeaseError("lease could not be consumed")
            lease.uses += 1
        return lease

    @_atomic
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

    @_atomic
    def audit(
        self,
        lease_id: str | None,
        subject: str | None,
        action: str,
        target: str | None,
        ok: bool,
        detail: dict[str, Any] | None = None,
    ) -> None:
        from .delegation import transaction

        with transaction(self):
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
