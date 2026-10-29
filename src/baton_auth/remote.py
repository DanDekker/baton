"""A small, mutual-TLS, lease-only broker API and its client.

This API deliberately has no shell, context-selection, credential-management,
or root-grant endpoint. MCP harnesses use the local stdio adapter in remote_mcp.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
import threading
from typing import Any

from cryptography import x509
import httpx

from . import broker, delegation, identity
from .models import BatonError, LeaseError

MAX_REQUEST = 65536
FIELDS = {
    "identity": set(), "inbox": set(), "accept": {"lease"},
    "http": {"lease", "url", "method", "service", "headers", "json_body"},
    "delegate": {"lease", "recipient", "services", "ttl", "max_uses", "delegatable",
                 "http_methods", "path_prefixes", "task"},
    "revoke": {"lease", "child_id"},
}


def _string(data, key, *, optional=False):
    value = data.get(key)
    if optional and value is None:
        return value
    if not isinstance(value, str) or not value or len(value) > 8192:
        raise BatonError(f"{key} must be a nonempty string")
    return value


def dispatch(vault, actor: str, message: dict) -> dict:
    who = delegation.agent(vault, actor)
    if not isinstance(message, dict) or set(message) != {"operation", "arguments"}:
        raise BatonError("request requires operation and arguments")
    op, args = message["operation"], message["arguments"]
    if not isinstance(op, str) or op not in FIELDS or not isinstance(args, dict) or set(args) - FIELDS[op]:
        raise BatonError("unsupported remote operation or arguments")
    if op == "identity":
        return {"id": actor, "name": who["name"], "protocol_version": 1,
                "operations": sorted(FIELDS)}
    if op == "inbox":
        return {"leases": delegation.inbox(vault, actor)}
    lease = _string(args, "lease")
    if op == "accept":
        return delegation.accept(vault, lease, actor).public()
    if op == "revoke":
        child = _string(args, "child_id", optional=True)
        return {"revoked": delegation.revoke(vault, lease, actor, child)}
    if op == "delegate":
        recipient = _string(args, "recipient")
        for key in ("services", "http_methods", "path_prefixes"):
            if key in args and args[key] is not None and (
                not isinstance(args[key], list) or any(not isinstance(x, str) for x in args[key])
            ):
                raise BatonError(f"{key} must be a list of strings")
        if "delegatable" in args and type(args["delegatable"]) is not bool:
            raise BatonError("delegatable must be a boolean")
        options = {k: v for k, v in args.items() if k not in {"lease", "recipient"}}
        return delegation.delegate(vault, lease, actor, recipient, **options).public()
    url = _string(args, "url")
    method = args.get("method", "GET")
    if not isinstance(method, str):
        raise BatonError("method must be a string")
    service = _string(args, "service", optional=True)
    headers = args.get("headers")
    if headers is not None and (not isinstance(headers, dict) or len(headers) > 32 or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()
    )):
        raise BatonError("headers must be an object with at most 32 string values")
    return broker.request(vault, lease, method.upper(), url, recipient=actor,
                          service=service, headers=headers, json_body=args.get("json_body")).as_dict()


class RemoteServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, vault, context: ssl.SSLContext):
        self.vault, self.tls = vault, context
        self.slots = threading.BoundedSemaphore(32)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, _Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        timer = None
        try:
            request.settimeout(10)
            connection = self.tls.wrap_socket(request, server_side=True)
            connection.settimeout(30)
            def expire():
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(60, expire)
            timer.daemon = True
            timer.start()
            super().process_request_thread(connection, client_address)
        except (OSError, ssl.SSLError):
            request.close()
        finally:
            if timer is not None:
                timer.cancel()
            self.slots.release()

    def handle_error(self, request, client_address):
        # Never dump request bodies, credential-bearing upstream URLs, or tokens.
        pass


class _Handler(BaseHTTPRequestHandler):
    server_version = "Baton"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    def _send(self, status: int, value: dict):
        body = json.dumps(value, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):
        if self.path != "/v1":
            self._send(404, {"error": "unknown endpoint"})
            return
        actor = None
        try:
            cert = x509.load_der_x509_certificate(self.connection.getpeercert(binary_form=True))
            actor = identity.public_id(cert.public_key())
            delegation.agent(self.server.vault, actor)
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                raise BatonError("a single Content-Length is required")
            length = int(lengths[0])
            if not 0 < length <= MAX_REQUEST:
                self._send(413, {"error": "request body is too large or empty"})
                return
            if self.headers.get_content_type() != "application/json":
                raise BatonError("Content-Type must be application/json")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise BatonError("incomplete request body")
            def reject_constant(value):
                raise ValueError("non-finite JSON number")
            message = json.loads(raw, parse_constant=reject_constant)
            result = dispatch(self.server.vault, actor, message)
        except LeaseError as exc:
            self.server.vault.audit(None, actor, "remote.reject", None, False, {})
            self._send(403, {"error": str(exc)})
        except BatonError as exc:
            self._send(400, {"error": str(exc)})
        except (ValueError, TypeError, KeyError, RecursionError):
            self._send(400, {"error": "invalid request"})
        except httpx.HTTPError:
            self._send(502, {"error": "upstream request failed"})
        except Exception:
            self._send(500, {"error": "broker operation failed"})
        else:
            self._send(200, {"result": result})


def serve(vault, endpoint: str, host="127.0.0.1", port=8765):
    context = identity.server_context(vault, endpoint)
    with RemoteServer((host, port), vault, context) as server:
        print(f"Baton broker listening on {host}:{server.server_port}; address {endpoint}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


class RemoteClient:
    def __init__(self, state_dir=None, connection="default"):
        self.config, context = identity.client_context(state_dir, connection)
        self._client = httpx.Client(verify=context, trust_env=False, follow_redirects=False, timeout=45)

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def call(self, operation: str, **arguments: Any) -> dict:
        body = json.dumps({"operation": operation, "arguments": arguments}, allow_nan=False).encode()
        if len(body) > MAX_REQUEST:
            raise BatonError("remote request is too large")
        try:
            with self._client.stream("POST", self.config["endpoint"] + "/v1",
                                     content=body, headers={"Content-Type": "application/json"}) as response:
                data = bytearray()
                for chunk in response.iter_bytes(chunk_size=16384):
                    data.extend(chunk)
                    if len(data) > 2_000_000:
                        raise BatonError("remote response is too large")
                payload = json.loads(data)
                if response.status_code != 200:
                    raise BatonError(payload.get("error", "remote request refused"))
                return payload["result"]
        except httpx.HTTPError:
            raise BatonError("cannot connect to broker; check its address, trust bundle, and agent status") from None
        except (KeyError, ValueError, TypeError):
            raise BatonError("invalid response from broker") from None
