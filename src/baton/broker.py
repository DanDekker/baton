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
from dataclasses import dataclass, field
from datetime import UTC, datetime
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


class BrokerError(BatonError):
    """Request could not be attributed to a credential."""


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
    now = datetime.now(UTC)
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
    target: str,
    method: str,
    url: str,
    *,
    service: str | None = None,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    json_body: Any | None = None,
    timeout: float = 30.0,
) -> HttpResponse:
    lease = None
    if target.startswith("btn_"):
        lease = vault.resolve_lease(target)
        if not lease.allows(service):
            raise LeaseError(f"lease does not grant {service!r}")
        context_name = lease.context
    else:
        context_name = target

    ctx = vault.get_context(context_name)
    creds = [vault.get_credential(name, auto_refresh=True) for name in ctx.credentials]
    if not creds:
        raise BrokerError(f"context {context_name} has no credentials")
    cred = pick_credential(creds, service)

    payload = body if body is not None else b""
    if json_body is not None:
        import json as _json

        payload = _json.dumps(json_body).encode()
        headers = {**(headers or {}), "content-type": "application/json"}

    final_headers, query = attach_auth(cred, method.upper(), url, dict(headers or {}), payload)
    if query:
        sep = "&" if "?" in url else "?"
        url = url + sep + "&".join(f"{k}={quote(v, safe='')}" for k, v in query.items())

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.request(method.upper(), url, headers=final_headers, content=payload or None)

    redactor = Redactor(list(cred.secret.values()))
    raw = resp.text
    truncated = len(raw) > MAX_BODY
    clean, hits = redactor.redact_counted(raw[:MAX_BODY])
    safe_headers = {
        k: v for k, v in resp.headers.items() if k.lower() in _SAFE_HEADERS
    }
    clean_headers = {k: redactor.redact(v) for k, v in safe_headers.items()}

    vault.audit(
        lease.id if lease else None,
        None,
        "http",
        f"{method.upper()} {urlparse(url).netloc}{urlparse(url).path}",
        resp.is_success,
        {"status": resp.status_code, "credential": cred.name},
    )
    return HttpResponse(
        url=url,
        status=resp.status_code,
        headers=clean_headers,
        body=clean,
        truncated=truncated,
        service=service or cred.provider,
        credential=cred.name,
        redactions=hits,
    )
