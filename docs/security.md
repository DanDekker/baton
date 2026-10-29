# Security and limits

[Back to overview](../README.md) · [User guide](guide.md)

baton keeps stored credential values away from MCP tools. Agents can see context names and use a temporary lease, while baton applies the real credential to a command or HTTP request. The returned output is checked for known secret values and recognized token shapes.

## What baton protects

| Area | How it works |
| --- | --- |
| Vault | Credential records are encrypted and tied to their record identity. The database file alone cannot decrypt them. |
| Leases | Handles expire, can be revoked or limited by service and use count, and are stored only as token digests. |
| CLI commands | Each run gets a temporary `0700` home with its context's auth files. Common inherited code injection variables are removed. |
| HTTP requests | baton attaches bearer, header, basic, query, or AWS SigV4 auth. Preset and `--allow-host` credentials are bound to their allowed domains. baton rejects disallowed URL schemes, metadata endpoints, link-local addresses, and private networks by default. Redirects are returned without being followed. |
| Results | Known secret values and common provider token patterns are redacted before a broker result is returned. |
| Audit | Actions are recorded in a BLAKE3 hash chain. SQLite uses WAL and atomic lease use updates. |

The master seed is resolved in this order: `BATON_MASTER_KEY` → `BATON_PASSPHRASE` with Argon2id → OS keyring → a `0600` keyfile. Mutable key buffers are wiped when the vault closes.

## Where the boundary ends

- baton is local to one user on one machine. It does not sync vaults between hosts.
- A temporary `HOME` separates CLI settings; it is not an operating-system sandbox. Child processes keep their normal filesystem permissions.
- A lease is a bearer token. Share it only with the intended agent and revoke it when it is no longer needed.
- Redaction is based on known values and token patterns. It cannot undo a leak that happened through another tool or guarantee that every possible encoding is caught.
- Hostnames are checked before HTTP connections. DNS can change between validation and connection; use network-level egress controls for untrusted destinations.
- `baton env --reveal` prints values when an operator explicitly asks for them. MCP has no reveal tool.

## Cryptographic construction

| Purpose | Primitive |
| --- | --- |
| Record encryption | AES-256-GCM-SIV (RFC 8452) when available; ChaCha20-Poly1305 fallback |
| Envelope commitment | BLAKE3 keyed tag over header, associated data, and ciphertext |
| Subkeys | BLAKE3 `derive_key`, separated by purpose |
| Lease MACs and audit chain | BLAKE3 keyed mode |
| Passphrase derivation | Argon2id, 64 MiB memory, 3 iterations, parallelism 4 |
| Record identity | Associated data `cred:<id>:<name>` |

AWS SigV4 uses SHA-256 as required by that protocol. The implementation lives in [`src/baton_auth/crypto.py`](../src/baton_auth/crypto.py), [`src/baton_auth/vault.py`](../src/baton_auth/vault.py), and [`src/baton_auth/broker.py`](../src/baton_auth/broker.py).
