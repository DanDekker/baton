"""Core data model: credentials, contexts, leases.

A credential is a secret payload plus the plan for how to make it usable by a
CLI (env vars, config files) or by the brokered HTTP layer (auth scheme).
A context is a named bundle of credentials = "one auth situation".
A lease is a signed, expiring handle to a context that agents pass to each
other instead of passing secrets.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class BatonError(Exception):
    """Base error."""


class VaultLocked(BatonError):
    """Master key unavailable."""


class UnknownCredential(BatonError):
    """Credential name not in vault."""


class UnknownContext(BatonError):
    """Context name not in vault."""


class LeaseError(BatonError):
    """Lease invalid, expired, revoked, or out of uses."""


class RefreshError(BatonError):
    """Credential refresh failed."""


def _now() -> float:
    return time.time()


def _nid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


@dataclass(slots=True)
class Credential:
    """A named secret + how to deploy it.

    secret:      field -> value. e.g. {"token": "..."} or
                 {"access_key_id": "...", "secret_access_key": "..."}
    materialize: list of deployment steps, e.g.
                 [{"kind": "env", "map": {"GH_TOKEN": "token"}}, ...]
    auth:        how the brokered HTTP layer attaches it, e.g.
                 {"scheme": "bearer", "field": "token"} or
                 {"scheme": "header", "header": "x-api-key", "field": "token"}
    """

    name: str
    provider: str = "generic"
    secret: dict[str, str] = field(default_factory=dict)
    materialize: list[dict[str, Any]] = field(default_factory=list)
    auth: dict[str, Any] = field(default_factory=dict)
    refresh: dict[str, Any] = field(default_factory=dict)
    allowed_hosts: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    expires_at: float | None = None
    notes: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: _nid("cred"))
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)

    def expired(self, skew: float = 0.0) -> bool:
        return self.expires_at is not None and self.expires_at - skew <= _now()

    def public(self) -> dict[str, Any]:
        """Agent-safe view. Never includes secret values."""
        return {
            "name": self.name,
            "provider": self.provider,
            "fields": sorted(self.secret),
            "scopes": self.scopes,
            "expires_at": self.expires_at,
            "expires_in": None
            if self.expires_at is None
            else max(0, int(self.expires_at - _now())),
            "expired": self.expired(),
            "refreshable": bool(self.refresh),
            "refresh_provider": self.refresh.get("provider") or self.refresh.get("type"),
            "allowed_hosts": self.allowed_hosts,
            "notes": self.notes,
        }


@dataclass(slots=True)
class Context:
    """A named auth situation: which credentials, plus env policy."""

    name: str
    credentials: list[str] = field(default_factory=list)
    description: str = ""
    # Env vars allowed to pass through from the caller untouched.
    passthrough: list[str] = field(default_factory=list)
    # Extra literal env vars for this context.
    env: dict[str, str] = field(default_factory=dict)
    # Copy these paths from the real HOME into the sandbox HOME (e.g. ".gitconfig").
    inherit_paths: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: _nid("ctx"))
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)


@dataclass(slots=True)
class Lease:
    """A signed handle to a context, scoped and expiring."""

    context: str
    subject: str
    services: list[str] = field(default_factory=list)
    ttl: float = 900.0
    max_uses: int | None = None
    token: str = ""
    id: str = field(default_factory=lambda: _nid("lease"))
    issued_at: float = field(default_factory=_now)
    uses: int = 0
    revoked: bool = False
    recipient: str | None = None
    parent_id: str | None = None
    delegatable: bool = False
    credential_ids: dict[str, str] = field(default_factory=dict)
    host_policies: dict[str, list[str]] = field(default_factory=dict)
    http_methods: list[str] = field(default_factory=list)
    path_prefixes: list[str] = field(default_factory=list)
    accepted_at: float | None = None
    task: dict[str, Any] = field(default_factory=dict)

    @property
    def expires_at(self) -> float:
        return self.issued_at + self.ttl

    def allows(self, service: str | None) -> bool:
        if not self.services or "*" in self.services:
            return True
        return service is not None and service in self.services

    def ensure_valid(self) -> None:
        if self.revoked:
            raise LeaseError("lease revoked")
        if _now() >= self.expires_at:
            raise LeaseError("lease expired")
        if self.max_uses is not None and self.uses >= self.max_uses:
            raise LeaseError("lease exhausted")

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "context": self.context,
            "subject": self.subject,
            "services": self.services,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "expires_in": max(0, int(self.expires_at - _now())),
            "max_uses": self.max_uses,
            "uses": self.uses,
            "revoked": self.revoked,
            "recipient": self.recipient,
            "parent_id": self.parent_id,
            "delegatable": self.delegatable,
            "http_methods": self.http_methods,
            "path_prefixes": self.path_prefixes,
            "accepted_at": self.accepted_at,
            "task": self.task,
        }
