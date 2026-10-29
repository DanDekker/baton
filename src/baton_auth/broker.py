"""Brokered HTTP: the agent asks for a URL, the broker attaches the credential.

This is the second half of the never-hand-over-the-secret rule. Egress for APIs
goes through here so the token is used by the tool layer, not pasted into a
prompt. Signing schemes live with the credential, not with the caller.

SigV4 uses SHA-256 because the AWS specification fixes it; everything else in
baton uses BLAKE3.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .models import BatonError, Credential, LeaseError, UnknownCredential
from .redact import Redactor
from .vault import Vault

MAX_BODY = 200_000

_SAFE_HEADERS = {
    "content-type",
    "content-length",
    "date",
    "etag",
    "last-modified",
    "location",
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-request-id",
}

# Cloud metadata and internal link-local endpoints blocked by default
_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "metadata.google.internal",
    "metadata.azure.com",
    "metadata.local",
    "fd00:ec2::254",
})


def validate_target_url(
    url: str,
    *,
    allow_private: bool = False,
    allow_loopback: bool = True,
) -> None:
    """SSRF guard: reject non-http schemes, metadata services, and internal/private IPs."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise BrokerError(f"unsupported URL scheme {scheme!r} (must be http or https)")

    host = parsed.hostname
    if not host:
        raise BrokerError("missing host in URL")

    host_lower = host.lower()
    if host_lower in _METADATA_HOSTS:
        raise BrokerError(f"SSRF protection: access to metadata endpoint {host!r} is blocked")

    try:
        addr_infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BrokerError(f"could not resolve host {host!r}: {exc}") from exc

    for _, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
            ip_str = str(ip)

        if ip_str in _METADATA_HOSTS:
            raise BrokerError(f"SSRF protection: access to metadata endpoint {ip_str} is blocked")

        if ip.is_unspecified or ip.is_multicast:
            raise BrokerError(f"SSRF protection: non-unicast address {ip_str} is blocked")

        if not allow_loopback and ip.is_loopback:
            raise BrokerError(f"SSRF protection: loopback address {ip_str} is blocked")

        if ip.is_link_local:
            raise BrokerError(f"SSRF protection: link-local address {ip_str} is blocked")

        if not allow_private and ip.is_private and not ip.is_loopback:
            raise BrokerError(f"SSRF protection: private network address {ip_str} is blocked")



class BrokerError(BatonError):
    """Request could not be attributed to a credential."""


def host_matches(host: str, pattern: str) -> bool:
    h = host.strip().lower().rstrip(".")
    p = pattern.strip().lower().rstrip(".")
    if not h or not p:
        return False
    if p == "*":
        return True
    if p.startswith("*."):
        root = p[2:]
        return h == root or h.endswith("." + root)
    return h == p


def validate_credential_host(
    cred: Credential,
    url: str,
    *,
    allow_loopback: bool = True,
) -> None:
    """Ensure a host-scoped credential is never sent to an unauthorized domain."""
    if not cred.allowed_hosts or "*" in cred.allowed_hosts:
        return
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    if not host:
        raise BrokerError("missing host in URL")
    if any(host_matches(host, pat) for pat in cred.allowed_hosts):
        return
    if allow_loopback and host in {"localhost", "127.0.0.1", "::1"}:
        return
    allowed = ", ".join(cred.allowed_hosts)
    raise BrokerError(
        f"credential {cred.name!r} ({cred.provider}) is not allowed for host {host!r} "
        f"(allowed: {allowed})"
    )


@dataclass(slots=True)
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    truncated: bool = False
    service: str = ""
    credential: str = ""
    redactions: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "body": self.body,
            "truncated": self.truncated,
            "service": self.service,
            "credential": self.credential,
            "redactions": self.redactions,
        }


def pick_credential(creds: list[Credential], service: str | None) -> Credential:
    if service:
        for c in creds:
            if c.name == service or c.provider == service:
                return c
        raise UnknownCredential(f"no credential for service {service!r} in context")
    if len(creds) == 1:
        return creds[0]
    raise BrokerError(
        "context has several credentials; name one with service=" + str([c.name for c in creds])
    )


def _pick_credential_name(vault: Vault, names: list[str], service: str | None) -> str:
    """Select using public metadata before decrypting or refreshing a credential."""
    if service:
        for name in names:
            provider = vault.get_credential_provider(name)
            if provider is None:
                raise UnknownCredential(f"unknown credential {name!r} (see `baton cred list`)")
            if name == service or provider == service:
                return name
        raise UnknownCredential(f"no credential for service {service!r} in context")
    if len(names) == 1:
        return names[0]
    raise BrokerError(
        "context has several credentials; name one with service=" + str(names)
    )


def _sigv4(
    cred: Credential, method: str, url: str, headers: dict[str, str], body: bytes
) -> dict[str, str]:
    """AWS Signature Version 4 for a single request."""
    akid = cred.secret.get("access_key_id", "")
    secret = cred.secret.get("secret_access_key", "")
    if not akid or not secret:
        raise BrokerError(f"credential {cred.name} lacks AWS key material")
    region = cred.secret.get("region") or "us-east-1"
    service = str(cred.auth.get("service") or "execute-api")

    parsed = urlparse(url)
    host = parsed.netloc
    now = datetime.now(timezone.utc)
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    signed = {k.lower(): v for k, v in headers.items()}
    signed["host"] = host
    signed["x-amz-date"] = amzdate
    if cred.secret.get("session_token"):
        signed["x-amz-security-token"] = cred.secret["session_token"]

    canonical_uri = quote(parsed.path or "/", safe="/-_.~")
    canonical_query = "&".join(
        sorted(
            quote(k, safe="-_.~") + "=" + quote(v, safe="-_.~")
            for k, v in (httpx.QueryParams(parsed.query).multi_items() if parsed.query else [])
        )
    )
    keys = sorted(signed)
    canonical_headers = "".join(f"{k}:{signed[k].strip()}\n" for k in keys)
    signed_headers = ";".join(keys)
    payload_hash = hashlib.sha256(body).hexdigest()

    canonical_request = "\n".join(
        [method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash]
    )
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amzdate,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _hmac(b"AWS4" + secret.encode(), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    k_signing = _hmac(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    out = dict(headers)
    for k in ("host", "x-amz-date", "x-amz-security-token"):
        if k in signed and k not in {h.lower() for h in out}:
            out[k] = signed[k]
    out["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={akid}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return out


def attach_auth(
    cred: Credential, method: str, url: str, headers: dict[str, str], body: bytes
) -> tuple[dict[str, str], dict[str, str]]:
    """Return (headers, query overrides) with the credential applied."""
    scheme = str(cred.auth.get("scheme", "bearer"))
    field_name = str(cred.auth.get("field", "token"))
    secret = cred.secret.get(field_name, "")
    out = dict(headers)
    query: dict[str, str] = {}

    if scheme == "sigv4":
        return _sigv4(cred, method, url, out, body), query
    if scheme == "bearer":
        if not secret:
            raise BrokerError(f"credential {cred.name} has no {field_name}")
        out["Authorization"] = f"Bearer {secret}"
    elif scheme == "header":
        header_name = str(cred.auth.get("header", "x-api-key"))
        if not secret:
            raise BrokerError(f"credential {cred.name} has no {field_name}")
        out[header_name] = secret
    elif scheme == "basic":
        user = cred.secret.get(str(cred.auth.get("user", "username")), "")
        password = cred.secret.get(str(cred.auth.get("password", "password")), "")
        out["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    elif scheme == "query":
        if not secret:
            raise BrokerError(f"credential {cred.name} has no {field_name}")
        query[str(cred.auth.get("param", "key"))] = secret
    elif scheme == "none":
        pass
    else:
        raise BrokerError(f"unsupported auth scheme {scheme!r}")
    return out, query


def request(
    vault: Vault,
    target: str | None,
    method: str,
    url: str,
    *,
    service: str | None = None,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    json_body: Any | None = None,
    timeout: float = 30.0,
    allow_private: bool = False,
    allow_loopback: bool = True,
) -> HttpResponse:
    validate_target_url(url, allow_private=allow_private, allow_loopback=allow_loopback)
    lease = None
    if target and target.startswith("btn_"):
        lease = vault.resolve_lease(target)
        if service is not None and not lease.allows(service):
            raise LeaseError(f"lease does not grant {service!r}")
        context_name: str | None = lease.context
    else:
        context_name = target

    ctx = vault.resolve_context(context_name)
    context_name = ctx.name
    if not ctx.credentials:
        raise BrokerError(f"context {context_name} has no credentials")
    if lease is not None and lease.services and "*" not in lease.services:
        allowed_set = set(lease.services)
        candidates = [
            name
            for name in ctx.credentials
            if name in allowed_set or vault.get_credential_provider(name) in allowed_set
        ]
        if not candidates:
            raise LeaseError(f"lease does not grant any service in context {context_name!r}")
    else:
        candidates = ctx.credentials
    cred_name = _pick_credential_name(vault, candidates, service)
    cred = vault.get_credential(cred_name, auto_refresh=True)
    validate_credential_host(cred, url, allow_loopback=allow_loopback)

    payload = body if body is not None else b""
    if json_body is not None:
        import json as _json

        payload = _json.dumps(json_body).encode()
        headers = {**(headers or {}), "content-type": "application/json"}

    public_url = url
    final_headers, query = attach_auth(cred, method.upper(), url, dict(headers or {}), payload)
    if query:
        sep = "&" if "?" in url else "?"
        url = url + sep + "&".join(f"{k}={quote(v, safe='')}" for k, v in query.items())

    # A redirect destination has not passed the SSRF guard. Return the 3xx
    # response so the caller can explicitly make a separately validated request.
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        resp = client.request(method.upper(), url, headers=final_headers, content=payload or None)

    # Query auth percent-encodes values. Echoes in bodies or Location headers
    # need to be scrubbed in both their original and wire representations.
    secret_values = list(cred.secret.values())
    redactor = Redactor([*secret_values, *(quote(value, safe="") for value in secret_values)])
    raw = resp.text
    truncated = len(raw) > MAX_BODY
    clean, hits = redactor.redact_counted(raw[:MAX_BODY])
    safe_headers = {
        k: v for k, v in resp.headers.items() if k.lower() in _SAFE_HEADERS
    }
    clean_headers = {}
    for k, v in safe_headers.items():
        clean_headers[k], n = redactor.redact_counted(v)
        hits += n
    # Never return the URL after query authentication has added a secret.
    safe_url, n = redactor.redact_counted(public_url)
    hits += n

    vault.audit(
        lease.id if lease else None,
        None,
        "http",
        f"{method.upper()} {urlparse(url).netloc}{urlparse(url).path}",
        resp.is_success,
        {"status": resp.status_code, "credential": cred.name},
    )
    return HttpResponse(
        url=safe_url,
        status=resp.status_code,
        headers=clean_headers,
        body=clean,
        truncated=truncated,
        service=service or cred.provider,
        credential=cred.name,
        redactions=hits,
    )
