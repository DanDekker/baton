# baton

Auth contexts for agents. **Pass the baton, never the secret.**

An agent that pastes an API key into a tool call has leaked it into the transcript,
the logs, and every later context window. baton gives agents a different primitive: a
*lease* — a signed, expiring, revocable handle to a bundle of credentials that is only
ever resolved on the broker side of the wall.

```
credential ──► context ──► lease ──► run / http
 (encrypted)   (named bundle)  (signed handle)   (auth applied out of band)
```

## Why this exists

Two problems, one mechanism:

1. **Secrets in model context.** Any MCP tool that returns a token has made the agent a
   custodian of it. Injection, transcript leaks, and log scraping all follow. Here, no
   tool returns a value — `baton_run` and `baton_http` *use* the credential and hand
   back only output, scrubbed.
2. **One machine, many auths.** CLI auth is not one env var: it is `~/.aws/credentials`,
   `~/.config/gh/hosts.yml`, `~/.kube/config`, `.npmrc`, `.docker/config.json`. Agents
   sharing a real `$HOME` overwrite each other. baton materializes a context into a
   throwaway sandbox `$HOME`, so `--ctx aws-prod` and `--ctx aws-staging` run side by
   side without touching the host or each other.

## Quickstart

```bash
uv sync

# store a credential (prompts hidden; never pass secrets as argv)
baton cred add gh-work --provider github --field token

# group credentials into a named auth situation
baton ctx add work --cred gh-work

# use it — the child gets an isolated HOME with only this context
baton run work -- gh api /user
baton run work -- sh -c 'echo $GH_TOKEN'   # → «baton:redacted»

# hand auth to another agent without handing over the key
baton lease new work --ttl 600 --uses 20
```

## MCP server

```json
{
  "mcpServers": {
    "baton": {
      "command": "/absolute/path/to/baton/.venv/bin/baton-mcp"
    }
  }
}
```

Tools: `baton_contexts`, `baton_credentials`, `baton_lease`, `baton_run`, `baton_http`,
`baton_leases`, `baton_revoke`, `baton_audit`, `baton_info`.

Built against **MCP Python SDK 2.x**, where `mcp.server.fastmcp.FastMCP` was replaced by
`mcp.server.mcpserver.MCPServer` — most tutorials still target the removed import path.

## Providers

`aws` · `gcp` · `github` · `gitlab` · `npm` · `docker` · `kube` · `ssh` · `generic`

A provider preset fixes the secret fields, the materialization plan (env vars, ini/json/
config files, file modes), and the HTTP auth scheme. `baton info` lists them.

```bash
baton cred add kube-prod --provider kube --field-file kubeconfig=~/.kube/config
baton cred add reg --provider docker --field username --field password --field registry=ghcr.io
```

## Crypto

| Purpose | Primitive | Why |
| --- | --- | --- |
| Record encryption | **AES-256-GCM-SIV** (RFC 8452) | nonce-misuse resistant and *key-committing*, unlike AES-GCM |
| Key commitment | **BLAKE3** keyed tag over header‖AAD‖ct | structural, not emergent — kills partitioning-oracle/multi-key confusion |
| Subkeys | **BLAKE3** `derive_key`, one domain per purpose | no key reuse across storage/lease/audit/commit |
| Lease MACs, audit chain | **BLAKE3** keyed mode | a real PRF, faster than HMAC-SHA256, 128-bit truncated |
| Passphrase mode | **Argon2id** (m=64 MiB, t=3, p=4) | memory-hard, well above the OWASP floor |
| At-rest AAD | `cred:<id>:<name>` | ciphertext cannot be relocated between records |

SigV4 uses SHA-256 because the AWS specification fixes it; everything else is BLAKE3.

Master seed resolution order: `BATON_MASTER_KEY` → `BATON_PASSPHRASE` (Argon2id) → OS
keyring (Keychain / Secret Service / Credential Locker) → `0600` keyfile. The database
alone is never enough to decrypt anything.

## Security properties

- No MCP tool returns a credential value. Enforced by construction, not convention.
- Child processes never inherit the caller's credential-shaped env vars (`*TOKEN*`,
  `*KEY*`, `*SECRET*`, `*PASSWORD*`, …) unless a context explicitly passes them through.
- Sandbox homes are `0700`, unique per run, and deleted on exit, failure, and timeout.
- All output crossing back to an agent is scrubbed: known values first, then provider
  token shapes (`AKIA…`, `ghp_…`, `glpat-…`, `sk-…`, JWTs, private-key headers).
- The audit log is a BLAKE3 hash chain over every column, so rewriting history is
  detectable (`baton audit`).
- Lease tokens are stored only as a BLAKE3 digest; the token itself is never at rest.

## Honest limits

- Local, single-user, single-machine. There is no network sync or multi-host vault yet.
- No OAuth refresh flows: credentials are static secrets with expiry metadata. A token
  that rotates must be re-added (until a refresh provider lands).
- `baton env --reveal` prints values for the human operator on explicit request; the MCP
  surface has no equivalent.
- Redaction is value- and pattern-based. It cannot catch a secret the agent was already
  given by some other tool.

## Layout

```
src/baton/crypto.py       envelope, subkeys, MACs, audit chain
src/baton/vault.py        encrypted store, leases, audit (thread-safe)
src/baton/catalog.py      provider presets
src/baton/materialize.py  context → sandbox HOME (env, files, modes)
src/baton/runner.py       subprocess in isolated HOME + redaction
src/baton/broker.py       HTTP with attached auth (bearer/header/basic/query/sigv4)
src/baton/mcp_server.py   MCP tools
src/baton/cli.py          operator CLI
```

```bash
.venv/bin/python -m pytest tests -q
```
