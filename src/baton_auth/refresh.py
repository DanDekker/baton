"""Credential refresh engine and provider registry.

Supports pluggable refresh hooks and built-in providers:
  * "oauth2": RFC 6749 Section 6 refresh token grant with optional rotation
  * "exec" / "command": external process execution to mint/fetch a fresh token
  * custom providers registered via `register_refresh_provider`
"""

from __future__ import annotations

import base64
import json
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

from .models import Credential, RefreshError


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


# ------------------------------------------------------------------- oauth2
def refresh_oauth2(cred: Credential, config: dict[str, Any]) -> RefreshResult:
    """RFC 6749 Section 6 OAuth 2.0 refresh token grant."""
    token_url = config.get("token_url")
    if not token_url:
        raise RefreshError(f"credential {cred.name}: oauth2 refresh missing 'token_url'")

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
    timeout = float(config.get("timeout", 30.0))

    headers: dict[str, str] = {"Accept": "application/json", **config.get("headers", {})}
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
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(token_url, data=data, headers=headers)
    except Exception as exc:
        raise RefreshError(f"credential {cred.name}: oauth2 request failed: {exc}") from exc

    if not resp.is_success:
        err_msg = f"HTTP {resp.status_code}"
        try:
            err_json = resp.json()
            err_msg = (
                err_json.get("error_description")
                or err_json.get("error")
                or err_json.get("message")
                or err_msg
            )
        except Exception:
            err_msg = resp.text[:200] or err_msg
        raise RefreshError(f"credential {cred.name}: oauth2 refresh failed: {err_msg}")

    try:
        body = resp.json()
    except Exception as exc:
        raise RefreshError(
            f"credential {cred.name}: oauth2 response was not JSON: {exc}"
        ) from exc

    new_access_token = body.get("access_token")
    if not new_access_token:
        raise RefreshError(
            f"credential {cred.name}: oauth2 response missing 'access_token'"
        )

    secret_updates: dict[str, str] = {access_field: str(new_access_token)}

    # Refresh token rotation (RFC 6749 Section 6)
    new_refresh_token = body.get("refresh_token")
    if new_refresh_token:
        secret_updates[rt_field] = str(new_refresh_token)

    # Expiry calculation
    expires_at = None
    if "expires_in" in body:
        try:
            expires_at = time.time() + float(body["expires_in"])
        except (ValueError, TypeError):
            pass

    return RefreshResult(
        secret_updates=secret_updates,
        expires_at=expires_at,
        meta_updates={"token_type": body.get("token_type", "Bearer")},
    )


# --------------------------------------------------------------------- exec
def refresh_exec(cred: Credential, config: dict[str, Any]) -> RefreshResult:
    """Execute an external command to fetch a fresh token."""
    raw_argv = config.get("argv") or config.get("command")
    if not raw_argv:
        raise RefreshError(f"credential {cred.name}: exec refresh missing 'argv'")

    if isinstance(raw_argv, str):
        argv = shlex.split(raw_argv)
    else:
        argv = [str(x) for x in raw_argv]

    timeout = float(config.get("timeout", 30.0))
    token_field = str(config.get("token_field", "token"))
    fmt = str(config.get("format", "text")).lower()
    ttl = config.get("ttl")

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RefreshError(
            f"credential {cred.name}: refresh command not found: {argv[0]}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RefreshError(
            f"credential {cred.name}: refresh command timed out after {timeout}s"
        ) from exc
    except Exception as exc:
        raise RefreshError(f"credential {cred.name}: refresh command failed: {exc}") from exc

    if proc.returncode != 0:
        err = proc.stderr.strip() or f"exit code {proc.returncode}"
        raise RefreshError(f"credential {cred.name}: refresh command error: {err}")

    output = proc.stdout.strip()
    if fmt == "json":
        try:
            doc = json.loads(output)
        except Exception as exc:
            raise RefreshError(
                f"credential {cred.name}: exec refresh expected JSON output: {exc}"
            ) from exc

        json_path = str(config.get("json_path", token_field))
        val = doc
        for part in json_path.split("."):
            if isinstance(val, dict) and part in val:
                val = val[part]
            else:
                raise RefreshError(
                    f"credential {cred.name}: JSON key {json_path!r} not found in output"
                )
        token_str = str(val)
        expires_at = None
        if "expires_in" in doc:
            expires_at = time.time() + float(doc["expires_in"])
        elif "expires_at" in doc:
            expires_at = float(doc["expires_at"])
        elif ttl:
            expires_at = time.time() + float(ttl)
    else:
        token_str = output
        expires_at = time.time() + float(ttl) if ttl else None

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

    p_name = (
        cred.refresh.get("provider")
        or cred.refresh.get("type")
        or "oauth2"
    )
    handler = get_refresh_provider(str(p_name))
    return handler(cred, cred.refresh)
