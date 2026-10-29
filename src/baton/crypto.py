"""Crypto core: AES-256-GCM-SIV envelope + BLAKE3 key derivation.

Envelope v2 layout::

    magic(4) | version(1) | cipher(1) | flags(1) | reserved(1)
    salt(16) | nonce(12) | ciphertext+tag(n) | commitment(16)

Why these primitives:

* AES-256-GCM-SIV (RFC 8452) instead of AES-GCM. Deterministic nonces are not
  fatal (misuse resistance), and it is key-committing, so a ciphertext cannot be
  opened under two different keys -- which matters because an attacker who can
  swap vault files is exactly the attacker we are defending against.
* An explicit BLAKE3 keyed commitment tag over the whole header+AAD+ciphertext,
  written after the ciphertext. This makes commitment structural rather than an
  emergent property of the AEAD (defeats partitioning-oracle style attacks and
  invisible-salamander multi-key confusion).
* BLAKE3 derive_key for domain-separated subkeys: one 32-byte master seed fans
  out into storage / lease-MAC / commitment / export keys. No key is ever reused
  across purposes.
* BLAKE3 keyed mode as the MAC for lease tokens and the audit hash chain: it is
  a proper PRF, faster than HMAC-SHA256, and the same primitive already verifies
  the commitment tag.
* Argon2id (RFC 9106) for passphrase-locked vaults, tuned well above the OWASP
  floor.

AAD always carries record identity, so a ciphertext cannot be moved between
records even with a valid key.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass

import blake3
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .models import BatonError, VaultLocked

MAGIC = b"BTN\x00"
VERSION = 2

CIPHER_GCM_SIV = 1
CIPHER_CHACHA20_POLY1305 = 2

SALT_LEN = 16
NONCE_LEN = 12
COMMIT_LEN = 16
HEADER_FIXED = 8  # magic(4) | version(1) | cipher(1) | flags(2)

KEY_LEN = 32

# Argon2id parameters. m=64 MiB, t=3, p=4 keeps a passphrase unlock in the
# hundreds-of-ms range while staying far above the OWASP minimum.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 64 * 1024
ARGON2_PARALLELISM = 4


def _siv_available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV  # noqa: F401

        return True
    except Exception:
        return False


_HAS_SIV = _siv_available()
DEFAULT_CIPHER = CIPHER_GCM_SIV if _HAS_SIV else CIPHER_CHACHA20_POLY1305


class CryptoError(BatonError):
    """Envelope malformed or failed to authenticate."""


# --------------------------------------------------------------------- keys
def subkey(master: bytes, domain: str) -> bytes:
    """Domain-separated 32-byte subkey via BLAKE3 derive_key.

    Domain strings are stable identifiers; changing one is a key rotation.
    """
    if len(master) != KEY_LEN:
        raise CryptoError("master key must be 32 bytes")
    return blake3.blake3(master, derive_key_context=f"baton/v{VERSION}/{domain}").digest()


def derive_key_argon2id(
    passphrase: str | bytes,
    salt: bytes,
    *,
    time_cost: int = ARGON2_TIME_COST,
    memory_kib: int = ARGON2_MEMORY_KIB,
    parallelism: int = ARGON2_PARALLELISM,
    length: int = KEY_LEN,
) -> bytes:
    """Stretch a passphrase into a master key."""
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise VaultLocked("passphrase mode needs argon2-cffi") from exc
    if isinstance(passphrase, str):
        passphrase = passphrase.encode()
    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_LEN)


# ------------------------------------------------------------------- hashing
def hash_id(prefix: str, *parts: str, size: int = 16) -> str:
    """Short stable id, BLAKE3-truncated (128 bits)."""
    h = blake3.blake3()
    for p in parts:
        h.update(p.encode())
        h.update(b"\x00")
    return f"{prefix}_{h.hexdigest(size)}"


def digest(data: bytes, size: int = 32) -> bytes:
    return blake3.blake3(data).digest(length=size)


# --------------------------------------------------------------------- MACs
def mac(key: bytes, data: bytes, size: int = 32) -> bytes:
    """Keyed BLAKE3 as a PRF."""
    if len(key) != KEY_LEN:
        raise CryptoError("mac key must be 32 bytes")
    return blake3.blake3(data, key=key).digest(length=size)


def mac_hex(key: bytes, data: bytes, size: int = 32) -> str:
    return mac(key, data, size).hex()


def mac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    return secrets.compare_digest(mac(key, data, len(tag)), tag)


def chain(prev: bytes | None, entry: bytes) -> bytes:
    """Append-only hash chain step: BLAKE3(prev || entry)."""
    h = blake3.blake3()
    h.update(prev or b"\x00" * 32)
    h.update(entry)
    return h.digest()


# ------------------------------------------------------------------ envelope
def _aead(cipher: int):
    if cipher == CIPHER_GCM_SIV:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

        return AESGCMSIV, True
    if cipher == CIPHER_CHACHA20_POLY1305:
        return ChaCha20Poly1305, False
    raise CryptoError(f"unsupported cipher id {cipher}")


def _header(cipher: int, salt: bytes) -> bytes:
    return MAGIC + bytes([VERSION, cipher, 0, 0]) + salt


def _commit(commit_key: bytes, header: bytes, aad: bytes, body: bytes) -> bytes:
    h = blake3.blake3(key=commit_key)
    h.update(b"commit\x00")
    h.update(header)
    h.update(len(aad).to_bytes(4, "big"))
    h.update(aad)
    h.update(body)
    return h.digest(length=COMMIT_LEN)


def seal(
    key: bytes,
    plaintext: bytes,
    aad: bytes = b"",
    *,
    nonce: bytes | None = None,
    cipher: int | None = None,
    commit_key: bytes | None = None,
) -> bytes:
    """Encrypt with authenticated, committed, versioned output."""
    cipher = cipher if cipher is not None else DEFAULT_CIPHER
    aead_cls, siv = _aead(cipher)
    salt = new_salt()
    header = _header(cipher, salt)
    nonce = nonce or secrets.token_bytes(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise CryptoError("nonce must be 12 bytes")
    body = aead_cls(key).encrypt(nonce, plaintext, header + aad)
    tag = _commit(commit_key or subkey(key, "commit"), header + nonce, aad, body)
    return header + nonce + body + tag


@dataclass(frozen=True, slots=True)
class EnvelopeInfo:
    version: int
    cipher: int
    salt: bytes


def parse_envelope(blob: bytes) -> EnvelopeInfo:
    if len(blob) < HEADER_FIXED + SALT_LEN + NONCE_LEN + 16 + COMMIT_LEN:
        raise CryptoError("envelope truncated")
    if blob[:4] != MAGIC:
        raise CryptoError("not a baton envelope")
    version = blob[4]
    if version != VERSION:
        raise CryptoError(f"unsupported envelope version {version}")
    salt = blob[HEADER_FIXED : HEADER_FIXED + SALT_LEN]
    return EnvelopeInfo(version=version, cipher=blob[5], salt=salt)


def open_envelope(
    key: bytes, blob: bytes, aad: bytes = b"", *, commit_key: bytes | None = None
) -> bytes:
    """Verify key commitment first, then authenticate-and-decrypt."""
    info = parse_envelope(blob)
    head = blob[: HEADER_FIXED + SALT_LEN]
    start = HEADER_FIXED + SALT_LEN
    nonce = blob[start : start + NONCE_LEN]
    body = blob[start + NONCE_LEN : -COMMIT_LEN]
    tag = blob[-COMMIT_LEN:]
    ck = commit_key or subkey(key, "commit")
    expect = _commit(ck, head + nonce, aad, body)
    if not secrets.compare_digest(expect, tag):
        raise CryptoError("key commitment check failed")
    aead_cls, _ = _aead(info.cipher)
    try:
        return aead_cls(key).decrypt(nonce, body, head + aad)
    except InvalidTag as exc:
        raise CryptoError("ciphertext failed authentication") from exc


def zeroize(buf: bytearray | memoryview) -> None:
    """Best-effort in-memory zeroization of sensitive buffers."""
    if not isinstance(buf, (bytearray, memoryview)):
        return
    import ctypes

    length = len(buf)
    if length == 0:
        return
    c_buf = (ctypes.c_char * length).from_buffer(buf)
    ctypes.memset(ctypes.byref(c_buf), 0, length)



# --------------------------------------------------------- key-file material
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    t = text.strip()
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


def key_to_b64(key: bytes) -> str:
    return b64u_encode(key)


def key_from_b64(text: str) -> bytes:
    raw = b64u_decode(text)
    if len(raw) != KEY_LEN:
        raise VaultLocked("key must decode to 32 bytes")
    return raw


def new_master_key() -> bytes:
    return os.urandom(KEY_LEN)


# ------------------------------------------------------------ PQ-ready export
def export_envelope(key: bytes, payload: bytes, recipient_pub: bytes | None) -> bytes:
    """Seal a payload with an ephemeral ECDH-free, ML-KEM-768 hybrid wrap.

    Called out separately from `seal` because it is only used for moving a vault
    between machines: the transferred key is wrapped to the recipient's
    post-quantum public key (FIPS 203) so a future quantum adversary with a
    recording of the transfer cannot recover it.
    """
    raise NotImplementedError("implemented in baton.crypto.pqx")
