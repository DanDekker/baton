"""Credential refresh engine and provider registry.

Supports pluggable refresh hooks and built-in providers:
  * "oauth2": RFC 6749 Section 6 refresh token grant with optional rotation
  * "exec" / "command": external process execution to mint/fetch a fresh token
  * custom providers registered via `register_refresh_provider`
"""

from __future__ import annotations

import base64
import ipaddress
import json
import math
import shlex
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from .models import Credential, RefreshError
from .redact import Redactor, collect_values

MAX_REFRESH_BYTES = 1024 * 1024


@dataclass(slots=True)
class RefreshResult:
    """Outcome of a successful refresh."""

    secret_updates: dict[str, str]
    expires_at: float | None = None
    notes: str | None = None
    meta_updates: dict[str, Any] = field(default_factory=dict)


RefreshHandler = Callable[[Credential, dict[str, Any]], RefreshResult]

_REGISTRY: dict[str, RefreshHandler] = {}


def register_refresh_provider(name: str, handler: RefreshHandler) -> None:
    """Register a custom refresh provider hook."""
    _REGISTRY[name.lower()] = handler


def get_refresh_provider(name: str) -> RefreshHandler:
    """Look up a registered refresh provider."""
    key = name.lower()
    if key not in _REGISTRY:
        raise RefreshError(
            f"unknown refresh provider {name!r} (available: {', '.join(sorted(_REGISTRY))})"
        )
    return _REGISTRY[key]


def _number(value: Any, field: str, *, positive: bool = False) -> float:
    try:
        result = float(value)
    except (ValueError, TypeError, OverflowError):
        raise RefreshError(f"refresh {field} must be a finite number") from None
    if (
        isinstance(value, bool)
        or not math.isfinite(result)
        or result < 0
        or (positive and result == 0)
    ):
        raise RefreshError(
            f"refresh {field} must be {'positive' if positive else 'nonnegative'} and finite"
        )
    if field == "timeout" and result > threading.TIMEOUT_MAX:
        raise RefreshError("refresh timeout exceeds the platform limit")
    return result


def _token(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise RefreshError(
            "refresh token must be a nonempty string without control characters"
        )
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise RefreshError("refresh token must be valid UTF-8") from None
    return value


def _expiry(doc: dict[str, Any], ttl: Any = None) -> float | None:
    if "expires_in" in doc:
        return time.time() + _number(doc["expires_in"], "expires_in")
    if "expires_at" in doc:
        return _number(doc["expires_at"], "expires_at")
    return time.time() + _number(ttl, "ttl") if ttl is not None else None


# ------------------------------------------------------------------- oauth2
def refresh_oauth2(cred: Credential, config: dict[str, Any]) -> RefreshResult:
    """RFC 6749 Section 6 OAuth 2.0 refresh token grant."""
    token_url = config.get("token_url")
    if not token_url:
        raise RefreshError(
            f"credential {cred.name}: oauth2 refresh missing 'token_url'"
        )
    from .broker import BrokerError, validate_target_url

    try:
        addresses = validate_target_url(
            str(token_url),
            allow_private=bool(config.get("allow_private", False)),
            allow_loopback=bool(config.get("allow_loopback", True)),
        )
    except BrokerError as exc:
        raise RefreshError(f"credential {cred.name}: invalid token_url: {exc}") from exc
    parsed = urlsplit(str(token_url))
    if parsed.scheme.lower() != "https":
        try:
            local = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            local = parsed.hostname in ("localhost", "localhost.") and all(
                ipaddress.ip_address(address).is_loopback for address in addresses
            )
        if not local:
            raise RefreshError("oauth2 token_url must use HTTPS outside loopback")

    rt_field = str(config.get("refresh_token_field", "refresh_token"))
    access_field = str(config.get("access_token_field", "token"))

    refresh_token = cred.secret.get(rt_field) or config.get("refresh_token")
    if not refresh_token:
        raise RefreshError(
            f"credential {cred.name}: missing refresh token in secret field {rt_field!r}"
        )

    client_id = config.get("client_id") or cred.secret.get("client_id")
    client_secret = config.get("client_secret") or cred.secret.get("client_secret")
    auth_style = str(config.get("auth_style", "auto")).lower()
    timeout = _number(config.get("timeout", 30.0), "timeout", positive=True)

    headers: dict[str, str] = {
        "Accept": "application/json",
        **config.get("headers", {}),
    }
    headers = {k: v for k, v in headers.items() if k.lower() != "accept-encoding"}
    headers["Accept-Encoding"] = "identity"
    data: dict[str, str] = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    if config.get("scope"):
        data["scope"] = str(config["scope"])
    if config.get("extra_params"):
        data.update(config["extra_params"])

    # Client authentication: Basic header or body parameters
    if client_id and client_secret and auth_style in ("basic", "auto"):
        userpass = f"{client_id}:{client_secret}".encode()
        headers["Authorization"] = f"Basic {base64.b64encode(userpass).decode()}"
    elif client_id:
        data["client_id"] = client_id
        if client_secret:
            data["client_secret"] = client_secret

    try:
        deadline = time.monotonic() + timeout
        from .transport import pinned_stream

        with pinned_stream(
            "POST", token_url, addresses, headers=headers, data=data, timeout=timeout
        ) as resp:
            if not resp.is_success:
                # Error bodies can echo submitted or freshly minted credentials.
                raise RefreshError(
                    f"credential {cred.name}: oauth2 refresh failed: HTTP {resp.status_code}"
                )
            if resp.headers.get("content-encoding", "identity").lower() != "identity":
                raise RefreshError("oauth2 refresh response must use identity encoding")
            raw = bytearray()
            for chunk in resp.iter_raw():
                if time.monotonic() >= deadline:
                    raise RefreshError("oauth2 refresh response timed out")
                if len(raw) + len(chunk) > MAX_REFRESH_BYTES:
                    raise RefreshError("oauth2 refresh response exceeds 1 MiB")
                raw.extend(chunk)
        body = json.loads(raw)
    except httpx.HTTPError:
        raise RefreshError(f"credential {cred.name}: oauth2 request failed") from None
    except (ValueError, UnicodeError):
        raise RefreshError(
            f"credential {cred.name}: oauth2 response was not JSON"
        ) from None

    if not isinstance(body, dict):
        raise RefreshError("oauth2 refresh response must be a JSON object")

    new_access_token = body.get("access_token")
    if not new_access_token:
        raise RefreshError(
            f"credential {cred.name}: oauth2 response missing 'access_token'"
        )

    secret_updates: dict[str, str] = {access_field: _token(new_access_token)}

    # Refresh token rotation (RFC 6749 Section 6)
    new_refresh_token = body.get("refresh_token")
    if "refresh_token" in body:
        secret_updates[rt_field] = _token(new_refresh_token)

    # Expiry calculation
    expires_at = _expiry(body)
    token_type = body.get("token_type", "Bearer")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise RefreshError("oauth2 refresh response has an unsupported token_type")

    return RefreshResult(
        secret_updates=secret_updates,
        expires_at=expires_at,
        meta_updates={"token_type": "Bearer"},
    )


# --------------------------------------------------------------------- exec
def _command_output(argv: list[str], timeout: float) -> bytes:
    from .process import CaptureError, capture

    try:
        result = capture(argv, timeout=timeout)
    except CaptureError as exc:
        raise RefreshError(f"refresh {exc}") from None
    if result.timed_out:
        raise subprocess.TimeoutExpired(argv, timeout)
    if result.returncode:
        raise RefreshError(f"refresh command failed with exit code {result.returncode}")
    return result.stdout


def refresh_exec(cred: Credential, config: dict[str, Any]) -> RefreshResult:
    """Execute an external command to fetch a fresh token."""
    raw_argv = config.get("argv") or config.get("command")
    if not raw_argv:
        raise RefreshError(f"credential {cred.name}: exec refresh missing 'argv'")

    if isinstance(raw_argv, str):
        argv = shlex.split(raw_argv)
    elif isinstance(raw_argv, list) and all(isinstance(x, str) for x in raw_argv):
        argv = raw_argv
    else:
        raise RefreshError("refresh argv must be a command string or list of strings")
    if not argv or not argv[0]:
        raise RefreshError("refresh command must not be empty")

    timeout = _number(config.get("timeout", 30.0), "timeout", positive=True)
    token_field = str(config.get("token_field", "token"))
    fmt = str(config.get("format", "text")).lower()
    if fmt not in ("text", "json"):
        raise RefreshError("refresh format must be text or json")
    ttl = config.get("ttl")
    if ttl is not None:
        ttl = _number(ttl, "ttl")

    try:
        output = _command_output(argv, timeout).decode("utf-8").strip()
    except FileNotFoundError:
        raise RefreshError(
            f"credential {cred.name}: refresh command not found"
        ) from None
    except subprocess.TimeoutExpired:
        raise RefreshError(
            f"credential {cred.name}: refresh command timed out after {timeout}s"
        ) from None
    except UnicodeError:
        raise RefreshError("refresh command output is not valid UTF-8") from None
    if fmt == "json":
        try:
            doc = json.loads(output)
        except ValueError:
            raise RefreshError(
                f"credential {cred.name}: exec refresh expected JSON output"
            ) from None
        if not isinstance(doc, dict):
            raise RefreshError("exec refresh response must be a JSON object")

        json_path = str(config.get("json_path", token_field))
        val = doc
        for part in json_path.split("."):
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                raise RefreshError(
                    f"credential {cred.name}: JSON key {json_path!r} not found in output"
                )
        token_str = _token(val)
        expires_at = _expiry(doc, ttl)
    else:
        token_str = _token(output)
        expires_at = _expiry({}, ttl)

    return RefreshResult(
        secret_updates={token_field: token_str},
        expires_at=expires_at,
    )


# Register default providers
register_refresh_provider("oauth2", refresh_oauth2)
register_refresh_provider("exec", refresh_exec)
register_refresh_provider("command", refresh_exec)


def execute_refresh(cred: Credential) -> RefreshResult:
    """Execute the configured refresh provider for a credential."""
    if not cred.refresh:
        raise RefreshError(f"credential {cred.name} has no refresh configuration")

    p_name = cred.refresh.get("provider") or cred.refresh.get("type") or "oauth2"
    redactor = Redactor(collect_values([cred.secret, cred.refresh]))
    try:
        handler = get_refresh_provider(str(p_name))
        result = handler(cred, cred.refresh)
        if (
            not isinstance(result, RefreshResult)
            or not isinstance(result.secret_updates, dict)
            or not result.secret_updates
        ):
            raise RefreshError("refresh provider returned no credential updates")
        for key, value in result.secret_updates.items():
            _token(key)
            _token(value)
        if result.expires_at is not None:
            result.expires_at = _number(result.expires_at, "expires_at")
        if not isinstance(result.meta_updates, dict) or (
            result.notes is not None and not isinstance(result.notes, str)
        ):
            raise RefreshError("refresh provider returned invalid metadata")
        return result
    except RefreshError as exc:
        raise RefreshError(redactor(str(exc))) from None
    except Exception:
        # Exception messages from libraries and hooks can include credentials.
        raise RefreshError(f"credential {cred.name}: refresh provider failed") from None
