# Agents on different machines

[User guide](guide.md) · [Security and limits](security.md)

Pair each harness once, grant it access, and let it hand work to another paired agent. The broker holds the service credentials. Each harness holds its own private key and authenticates over mutual TLS; changing its model or provider does not change its identity or permissions.

The remote API supports credential-backed HTTPS requests, inboxes, acceptance, delegation, and revocation. Commands run by `baton run` and credential administration remain local. This remote API is accessed by a local stdio MCP adapter, so clients do not need native support for client certificates or a particular model provider.

## Pair a harness

Install `baton-auth` on the broker and agent machines. The broker needs an address reachable from the agent machines. The examples use `broker.example.com:8765`; replace it with your hostname or IP address.

On the **agent machine**, create its identity and a public pairing request:

```bash
baton agent init builder --output builder.request.json
```

Copy `builder.request.json` to the broker using a trusted channel. On the **broker**, approve that identity:

```bash
baton agent trust builder.request.json \
  --url https://broker.example.com:8765 \
  --output builder.connection.json
```

Copy `builder.connection.json` back to the agent. Both exchanged files contain public material only. Keep the agent's `identity.key` on the agent and the broker's vault and authority keys on the broker.

On the **agent machine**, install the connection and configure its MCP harness:

```bash
baton connect builder.connection.json
baton setup --remote default --auto
# Or choose a client explicitly:
baton setup --remote default --client claude-code
```

`baton setup --remote default` prints portable MCP JSON. It works with the same supported clients as local setup. A harness without MCP can use `baton remote` commands instead.

Repeat the pairing steps with the name `reviewer` on the receiving agent's machine. Names are unique within a broker. Each independent identity needs its own state directory. If several harnesses run under one OS user, use a different `--state-dir PATH` consistently for each harness's `agent init`, `connect`, `setup`, and `remote` commands.

## Start the broker and grant access

On the **broker**, start the authenticated listener:

```bash
baton serve --host 0.0.0.0 --port 8765 --url https://broker.example.com:8765
```

Run it as the account that owns the vault, and keep the process running through your usual service supervisor. The default listen address is loopback; `--host` explicitly enables access from other machines. Pairing supplies the broker's certificate authority to clients, so a separate public certificate service is not required. Route the TLS connection directly to the broker; forwarding identity in HTTP headers is not supported.

In another terminal on the **broker**, grant the builder access:

```bash
baton grant github --to builder --ttl 900 --uses 20 --delegate \
  --path-prefix /repos/your-org/your-repo \
  --summary "Review the open pull requests"
```

Use a credential or context name in place of `github`. A local administrative MCP client can use `baton_agents` and `baton_lease(recipient=..., delegatable=True, ...)` for the same operation. Remote clients cannot create root grants.

The default methods are `GET` and `HEAD`. Add repeatable `--method` options to choose a different set, for example `--method GET --method POST`. `--service` narrows a context to selected credentials/providers. `--path-prefix` permits that path and its descendants, not similarly named sibling paths. Only explicitly host-scoped credentials can be granted remotely. Grants snapshot credential identities and host limits; later context additions do not add access.

## Let agents hand off work

Once paired, agents use these MCP tools:

| Tool | Purpose |
| --- | --- |
| `baton_identity` | Identify the connected harness. |
| `baton_inbox` | Discover pending and active grants addressed to it. |
| `baton_accept` | Accept a grant before using it. |
| `baton_http` | Make a permitted request through the broker. |
| `baton_delegate` | Send a child grant, summary, task ID, and artifact references to another recipient. |
| `baton_revoke` | Finish/revoke its grant or a delegated descendant. |

The equivalent CLI flow on the **builder** is:

```bash
baton remote inbox
baton remote accept LEASE_ID
baton remote http LEASE_ID https://api.github.com/repos/your-org/your-repo/pulls
baton remote delegate LEASE_ID --to reviewer --ttl 300 --uses 5 \
  --summary "Check the proposed changes" --artifact "https://github.com/your-org/your-repo/pull/42"
```

The reviewer discovers the child grant in its own inbox and accepts it. There is no bearer token to copy: lease IDs are public handles, and a different identity cannot use them. Task summaries and artifact references are task data supplied by another agent; the broker does not execute them or fetch those references automatically.

Delegation must be enabled on the parent. Children default to no further delegation; add `--delegate` when permitted if another handoff is needed. Child methods, services, paths, expiry, and budgets can only narrow. Each HTTP attempt charges both the child and every ancestor, so creating children does not multiply the original usage budget. This is shared delegation: the parent can keep working until its grant is revoked or exhausted. Revocation also blocks children, so revoke the parent when the whole delegated task is finished.

## Revoke, renew, and inspect

```bash
# On an agent: revoke its grant or one delegated child.
baton remote revoke LEASE_ID
baton remote revoke PARENT_ID --child CHILD_ID

# On the broker: revoke a whole identity or inspect local audit history.
baton agent list
baton agent revoke builder
baton lease revoke LEASE_ID
baton audit
```

Parent expiry, exhaustion, revocation, or revocation of an ancestor's identity blocks every descendant. Already-started HTTP requests may finish. Client certificates expire after one year; approve the same identity request again and reconnect with the renewed bundle. A revoked identity cannot be re-enabled through renewal: initialize a new identity in a new state directory and pair it explicitly.

Remote destinations must use HTTPS on port 443 and resolve only to public addresses. Private networks, loopback, metadata endpoints, redirects, and unscoped wildcard credentials are blocked. DNS addresses are validated and pinned for the outgoing connection while preserving the hostname for TLS verification. Remote response bodies are bounded; upstreams must support identity content encoding. Callers can supply standard content/conditional headers, idempotency keys, range requests, and supported provider version headers; transport, authentication, forwarding, and routing overrides are rejected.

Pair only trusted harnesses and keep their private keys protected. Agents running as the same OS user with filesystem access can read each other's keys unless you isolate those processes. The local administrative MCP interface remains trusted; configure remote harnesses with `--remote` so they receive only the restricted tools.
