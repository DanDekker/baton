<div align="center">

<img src="assets/baton-banner.svg" alt="baton — Auth contexts for agents. Pass the baton, never the secret." width="100%">
<p><strong>Local vault · Signed leases · Isolated CLI homes · Brokered HTTP</strong></p>
<p><a href="#quick-start">Quick start</a> · <a href="#mcp-integration">MCP integration</a> · <a href="#security-model">Security model</a> · <a href="#limits">Limits</a></p>

</div>

---

Agents need to use credentials. They do not need to see them. baton keeps secrets in an encrypted local vault and gives agents short-lived, revocable **leases** to named auth contexts. The broker applies credentials to commands and HTTP requests, then redacts known secrets from the output.

```text
encrypted credential → named context → signed lease
                                      ├─ run  → temporary HOME → redacted output
                                      └─ http → attached auth  → redacted response
```

| The problem | The baton approach |
| --- | --- |
| A tool returns an API key, placing it in a transcript or log. | Tools return metadata and lease handles. Credential values stay in the broker. |
| Agents share a machine and overwrite each other's CLI auth files. | Each run gets a temporary `HOME` with only that context's auth material. |
| Long-lived credentials are handed from agent to agent. | Leases expire, can be scoped to services and use counts, and can be revoked. |

## Quick start

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
source .venv/bin/activate

# Prompts for the token without putting its value in shell history.
baton cred add gh-work --provider github --field token

# Bundle credentials into a named auth context.
baton ctx add work --cred gh-work

# Run a CLI with this context's auth in a temporary HOME.
baton run work -- gh api /user

# Or make an HTTP request with auth attached by the broker.
baton http work https://api.github.com/user

# Delegate access with a 10-minute, 20-use lease.
baton lease new work --ttl 600 --uses 20
```

If a command prints the stored token, baton replaces it with `«baton:redacted»` in the returned output. Secret values should be entered through hidden `--field` prompts or `--field-file`, not as command arguments.

## MCP integration

Point your MCP client at the installed server:

```json
{
  "mcpServers": {
    "baton": {
      "command": "/absolute/path/to/baton/.venv/bin/baton-mcp"
    }
  }
}
```

| Workflow | Tools |
| --- | --- |
| Inspect metadata | `baton_info`, `baton_contexts`, `baton_credentials` |
| Delegate and revoke | `baton_lease`, `baton_leases`, `baton_revoke` |
| Use a context | `baton_run`, `baton_http` |
| Maintain and inspect | `baton_refresh`, `baton_audit` |

The MCP surface does not return credential values. `baton_run` and `baton_http` use credentials inside the broker and return redacted results. The server targets MCP Python SDK 2.x.

## Providers and refresh

**Built-in presets:** `aws` · `gcp` · `github` · `gitlab` · `npm` · `docker` · `kube` · `ssh` · `generic`

A preset defines expected fields, how auth is materialized for CLIs, and how it is attached to HTTP requests. Run `baton info` to inspect the available presets.

```bash
baton cred add kube-prod --provider kube --field-file kubeconfig=~/.kube/config
baton cred add registry --provider docker \
  --field username --field password --field registry=ghcr.io
```

Credentials can refresh automatically when they are expired or close to expiry. Built-in options include OAuth 2.0 refresh tokens and external commands; Python integrations can register custom handlers with `register_refresh_provider(name, handler)`. OAuth refresh supports token rotation and `expires_in`.

```bash
# Bare fields prompt for values, including the client secret.
baton cred add api --provider generic \
  --field token --field refresh_token --field client_secret \
  --refresh-provider oauth2 \
  --refresh-token-url https://auth.example.com/token \
  --refresh-client-id my-client-id

baton cred refresh api --force
```

## Security model

| Layer | Control |
| --- | --- |
| Storage | Authenticated encryption with record identity as associated data, plus a BLAKE3 keyed commitment. |
| Delegation | Signed leases with expiry, revocation, optional service scope, and an atomic use budget. Only a token digest is stored. |
| Execution | Context-specific files and environment variables are written into a temporary `0700` home; dangerous inherited injection variables are removed. |
| HTTP | The broker attaches bearer, header, basic, query, or AWS SigV4 auth. It rejects disallowed schemes, metadata endpoints, link-local addresses, and private networks by default. Redirects are returned for separate validation. |
| Output | Known credential values and recognized provider token shapes are redacted before broker results are returned. |
| Audit | Credential use and administrative actions are recorded in a BLAKE3 hash chain. SQLite uses WAL and atomic lease updates. |

The master seed is resolved in this order: `BATON_MASTER_KEY` → `BATON_PASSPHRASE` with Argon2id → OS keyring → a `0600` keyfile. The database alone is not sufficient to decrypt stored credentials. Mutable key buffers are wiped when the vault closes.

<details>
<summary>Cryptographic construction</summary>

| Purpose | Primitive |
| --- | --- |
| Record encryption | AES-256-GCM-SIV (RFC 8452) when available; ChaCha20-Poly1305 fallback |
| Explicit envelope commitment | BLAKE3 keyed tag over header, associated data, and ciphertext |
| Subkeys | BLAKE3 `derive_key`, separated by purpose |
| Lease MACs and audit chain | BLAKE3 keyed mode |
| Passphrase derivation | Argon2id, 64 MiB memory, 3 iterations, parallelism 4 |
| Record identity | Associated data `cred:<id>:<name>` |

AWS SigV4 uses SHA-256 as required by that protocol.

</details>

## Limits

- baton is local to one user and one machine. It does not sync vaults between hosts.
- A temporary `HOME` isolates CLI configuration; it is not an operating-system sandbox. Child processes retain their normal filesystem permissions.
- Redaction covers known values and recognized token shapes. It cannot recover a secret already exposed to an agent elsewhere.
- HTTP hostname checks happen before the connection. For untrusted destinations, pair baton with network-level egress controls.
- `baton env --reveal` prints values only when explicitly requested by the operator. There is no MCP equivalent.

## Development

```bash
uv sync --extra dev
.venv/bin/python -m pytest tests -q
```

<details>
<summary>Project map</summary>

```text
src/baton/crypto.py       envelopes, subkeys, MACs, audit chain
src/baton/vault.py        encrypted store, leases, audit
src/baton/catalog.py      provider presets
src/baton/refresh.py      OAuth, command, and custom refresh handlers
src/baton/materialize.py  context → temporary HOME
src/baton/runner.py       subprocess execution and redaction
src/baton/broker.py       brokered HTTP and auth attachment
src/baton/mcp_server.py   MCP tools
src/baton/cli.py          operator CLI
```

</details>
