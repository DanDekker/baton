"""Local pairing and mutual-TLS identities. Private keys never leave their host."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import time
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .delegation import transaction
from .models import BatonError
from .vault import default_state_dir


def state_path(state_dir=None) -> Path:
    path = Path(state_dir).expanduser() if state_dir else default_state_dir()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def write_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".baton-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def name_check(name: str) -> str:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise BatonError("names must be 1–64 letters, digits, dots, underscores, or hyphens")
    return name


def endpoint_check(value: str) -> str:
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
        or parts.password is not None or parts.query or parts.fragment or parts.path not in ("", "/")):
        raise BatonError("broker address must be an HTTPS origin, such as https://broker.example:8765")
    try:
        parts.port
    except ValueError:
        raise BatonError("invalid broker port") from None
    return value.rstrip("/")


def public_id(key) -> str:
    raw = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "agent_" + hashlib.sha256(raw).hexdigest()


def _key_bytes(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def init_agent(name: str, state_dir=None) -> dict:
    name_check(name)
    root = state_path(state_dir)
    path = root / "identity.key"
    metadata = root / "identity.json"
    if metadata.exists() and json.loads(metadata.read_text())["name"] != name:
        raise BatonError("this state directory already belongs to another identity; use a separate --state-dir")
    if not path.exists():
        # Exclusive creation avoids replacing an identity when two clients initialize together.
        key = ec.generate_private_key(ec.SECP256R1())
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "wb") as stream:
                stream.write(_key_bytes(key))
                stream.flush()
                os.fsync(stream.fileno())
    key = _load_key(path)
    write_private(metadata, json.dumps({"name": name, "id": public_id(key.public_key())}).encode())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    ).sign(key, hashes.SHA256())
    return {"version": 1, "name": name, "id": public_id(key.public_key()), "csr": _pem(csr)}


def _certificate(key, subject, issuer, signer, *, ca=False, host=None, client=False):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5))
               .not_valid_after(now + timedelta(days=1825 if ca else 365))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=True, content_commitment=False, key_encipherment=False,
                   data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                   crl_sign=ca, encipher_only=False, decipher_only=False,
               ), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False))
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH
        ]), critical=False)
    if host:
        try:
            san = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host.encode("idna").decode("ascii"))
        builder = builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
    return builder.sign(signer, hashes.SHA256())


def authority(vault):
    root = vault.state_dir / "authority"
    with transaction(vault):
        if not (root / "ca.key").exists():
            key = ec.generate_private_key(ec.SECP256R1())
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Baton broker authority")])
            cert = _certificate(key, subject, subject, key, ca=True)
            write_private(root / "ca.key", _key_bytes(key))
            write_private(root / "ca.pem", cert.public_bytes(serialization.Encoding.PEM))
        key = _load_key(root / "ca.key")
        cert = x509.load_pem_x509_certificate((root / "ca.pem").read_bytes())
    return root, key, cert


def trust_agent(vault, request: dict, endpoint: str) -> dict:
    endpoint = endpoint_check(endpoint)
    if request.get("version") != 1:
        raise BatonError("unsupported pairing request version")
    name = name_check(request["name"])
    csr = x509.load_pem_x509_csr(request["csr"].encode("ascii"))
    public_key = csr.public_key()
    if (not csr.is_signature_valid or not isinstance(public_key, ec.EllipticCurvePublicKey)
        or public_key.key_size < 256):
        raise BatonError("invalid identity signing request")
    identity = public_id(public_key)
    if request.get("id") != identity:
        raise BatonError("pairing request identity does not match its public key")
    _, signer, ca = authority(vault)
    # The certificate builder only needs public_key(); the recipient's private key is never supplied.
    class PublicKey:
        def public_key(self):
            return public_key
    cert = _certificate(PublicKey(), x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]),
                        ca.subject, signer, client=True)
    with transaction(vault):
        existing = vault._conn.execute("SELECT * FROM agents WHERE name=? OR id=?", (name, identity)).fetchall()
        if any(row["id"] != identity or row["name"] != name for row in existing):
            raise BatonError("agent name or identity already registered; use its original name")
        if any(row["revoked"] for row in existing):
            raise BatonError("this identity was revoked; initialize a new identity in a new state directory")
        vault._conn.execute(
            "INSERT OR IGNORE INTO agents(id,name,public_key,created_at) VALUES(?,?,?,?)",
            (identity, name, public_key.public_bytes(serialization.Encoding.PEM,
             serialization.PublicFormat.SubjectPublicKeyInfo).decode(), time.time()),
        )
    vault.audit(None, identity, "agent.trust", name, True, {})
    return {"version": 1, "name": name, "id": identity, "endpoint": endpoint,
            "ca": _pem(ca), "certificate": _pem(cert)}


def revoke_agent(vault, name: str) -> bool:
    with transaction(vault):
        cur = vault._conn.execute("UPDATE agents SET revoked=1 WHERE name=? OR id=?", (name, name))
    vault.audit(None, None, "agent.revoke", name, True, {})
    return bool(cur.rowcount)


def connect(bundle: dict, state_dir=None, name="default") -> Path:
    name_check(name)
    root = state_path(state_dir)
    if bundle.get("version") != 1:
        raise BatonError("unsupported connection version")
    endpoint = endpoint_check(bundle["endpoint"])
    key = _load_key(root / "identity.key")
    cert = x509.load_pem_x509_certificate(bundle["certificate"].encode("ascii"))
    ca = x509.load_pem_x509_certificate(bundle["ca"].encode("ascii"))
    if public_id(key.public_key()) != public_id(cert.public_key()) or bundle["id"] != public_id(key.public_key()):
        raise BatonError("connection certificate belongs to a different local identity")
    cert.verify_directly_issued_by(ca)
    if ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
        raise BatonError("certificate cannot authenticate a client")
    target = root / "connections" / name
    config = {"version": 1, "id": bundle["id"], "name": name_check(bundle["name"]), "endpoint": endpoint}
    write_private(target / "ca.pem", bundle["ca"].encode("ascii"))
    write_private(target / "client.pem", bundle["certificate"].encode("ascii"))
    write_private(target / "connection.json", (json.dumps(config, indent=2) + "\n").encode())
    return target


def client_context(state_dir=None, name="default") -> tuple[dict, ssl.SSLContext]:
    name_check(name)
    root = state_path(state_dir)
    directory = root / "connections" / name
    config = json.loads((directory / "connection.json").read_text())
    endpoint_check(config["endpoint"])
    context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(directory / "client.pem"), str(root / "identity.key"))
    return config, context


def server_context(vault, endpoint: str) -> ssl.SSLContext:
    host = urlsplit(endpoint_check(endpoint)).hostname
    root, ca_key, ca = authority(vault)
    with transaction(vault):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Baton broker")])
        cert = _certificate(key, subject, ca.subject, ca_key, host=host)
        write_private(root / "server.key", _key_bytes(key))
        write_private(root / "server.pem", cert.public_bytes(serialization.Encoding.PEM))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(root / "ca.pem"))
        context.load_cert_chain(str(root / "server.pem"), str(root / "server.key"))
    return context
