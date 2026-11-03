"""Exercise hostname verification through a real pinned TLS connection."""

import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from baton_auth import broker
from baton_auth.catalog import build_credential
from baton_auth.vault import Vault


def test_pinned_connection_verifies_original_hostname(tmp_path, monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "upstream.example")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("upstream.example")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = tmp_path / "server.pem", tmp_path / "server.key"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keyfile.chmod(0o600)
    server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_tls.load_cert_chain(certfile, keyfile)
    names, requests = [], []
    server_tls.set_servername_callback(
        lambda _socket, host, _context: names.append(host)
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(dict(self.headers))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = server_tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    trusted = ssl.create_default_context(cafile=str(certfile))
    original = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: original(verify=trusted, **kw))
    monkeypatch.setattr(broker, "validate_target_url", lambda *a, **kw: ["127.0.0.1"])
    try:
        with Vault(state_dir=tmp_path / "vault", master_key=b"k" * 32) as vault:
            vault.put_credential(
                build_credential("api", "generic", {"token": "fake-tls-token"})
            )
            result = broker.request(
                vault, "api", "GET", f"https://upstream.example:{server.server_port}/"
            )
            assert result.body == "ok"
            assert requests[0]["Host"] == f"upstream.example:{server.server_port}"
            assert names[0] == "upstream.example"
            with pytest.raises(broker.BrokerError, match="upstream request failed"):
                broker.request(
                    vault, "api", "GET", f"https://wrong.example:{server.server_port}/"
                )
            assert len(requests) == 1, (
                "credentials reached a server with the wrong certificate"
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
