# Security and limits

[Back to overview](../README.md) · [User guide](guide.md)

baton keeps stored credential values away from MCP tools. Agents can see context names and use a temporary lease, while baton applies the real credential to a command or HTTP request. The returned output is checked for known secret values and recognized token shapes.

## What baton protects

| Area | How it works |
| --- | --- |
| Vault | Credential values and full refresh settings are encrypted together and tied to their record identity. Public metadata includes field names, expiry, and the refresh provider, but no refresh arguments, headers, or client secrets. |
| Refresh | Invalid tokens and expiry values leave the stored credential unchanged. HTTP responses and each command output stream are limited to 1 MiB. Server error bodies and command stderr are not returned to callers. |
| Leases | Handles expire, can be revoked or limited by service and use count, and are stored only as token digests. Limits reject non-finite values and integer overflow. Consumption checks expiry again after acquiring the database write lock. Service-scoped leases only decrypt and materialize the permitted service's credentials. |
| CLI commands | Each run gets an exclusively created `0700` home. Context names cannot select its path. Materialized, inherited, and home-relative auth paths are checked for escape. Output is capped at 1 MiB per stream; exceeding it stops the command. Common inherited code injection variables are removed. |
| HTTP requests | Credentials stay bound to their allowed domains. Connections pin validated IP addresses while preserving the original TLS name and Host header. Requests ignore proxy environment variables, reject URL userinfo, replace conflicting auth headers, and return redirects without following them. Cloud metadata, link-local, and private addresses are blocked by default. Upstream bodies are streamed with a 200,000-byte limit; compressed responses are rejected. |
| Results | Known secret values (raw, URL-encoded, and base64-encoded) and common provider token patterns are redacted before a broker result is returned. |
| Audit | Actions are recorded in a BLAKE3 hash chain. SQLite uses WAL, FULL synchronization, and atomic lease use updates. Credential values in HTTP audit paths are redacted. |

The master seed is resolved in this order: `BATON_MASTER_KEY` → `BATON_PASSPHRASE` with Argon2id → OS keyring → a `0600` keyfile. Mutable key buffers are wiped when the vault closes.

First-time key creation is serialized across processes. An existing keyfile is retained if the keyring later becomes available without an entry for the vault. A key check rejects the wrong master key before records can be overwritten. Refreshes recheck expiry under a database write lock, so concurrent callers do not rotate the same token twice. Other writers may wait or receive a busy error during a slow refresh.

Opening an older vault moves its refresh settings into encrypted storage in one transaction. Failed upgrades leave the original records intact. Upgrade every baton process using that vault before reopening it; older releases cannot read the new credential format. Old backups may still contain plaintext refresh settings.

## Where the boundary ends

- The vault stays on one broker machine. Remote agents use a separate mutual-TLS API and do not receive the vault or its master key; see [remote pairing](remote.md).
- Remote grants bind to a paired public-key identity, require acceptance, snapshot credential identities and host limits, and restrict HTTP methods and path subtrees. Delegated use charges every ancestor atomically; expiry, revocation, exhausted budgets, and revoked identities block descendants.
- The remote API has no shell, credential-management, context-selection, or root-grant operation. Remote destinations must use HTTPS on port 443 and public addresses. Validated addresses are pinned for the outgoing connection; redirects and forwarding/routing header overrides are blocked.
- A temporary `HOME` separates CLI settings; it is not an operating-system sandbox. Child processes keep their normal filesystem permissions.
- Command deadlines cover the process and its output pipes. On POSIX systems, timeout and output-limit cleanup kills the command's process group. This does not contain a process that deliberately escapes that group. Known secret prefixes cut off by a timeout are redacted too.
- Existing unbound local leases are bearer tokens. Remote lease IDs are public handles that require the intended recipient's paired private key. Never copy a harness's private key to share a grant.
- Redaction is based on known values and token patterns. It cannot undo a leak that happened through another tool or guarantee that every possible encoding is caught.
- Connection failures can try another already-validated IP address. Requests are not retried after a response or read failure, since a write may already have happened. A revocation does not cancel a request that already started.
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
