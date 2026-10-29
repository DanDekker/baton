# Using baton

[Back to overview](../README.md) · [Security and limits](security.md)

baton keeps credentials on your machine and uses them on an agent's behalf. Three terms are enough to get started:

| Term | What it means |
| --- | --- |
| **Credential** | A token, password, key, or config file you store in baton. |
| **Context** | A named group of credentials, such as `work` or `staging`. |
| **Lease** | A temporary pass to use a context. It can expire, run out of uses, or be revoked. |

## Set up a context

Install with Python 3.10+ and [uv](https://docs.astral.sh/uv/), then add a GitHub token. A bare `--field token` prompts without showing the value or putting it in shell history.

```bash
uv tool install git+https://github.com/DanDekker/baton.git

baton cred add gh-work --provider github --field token --context work
baton ctx list
```

Run a command or send an HTTP request with the `work` context:

```bash
baton run work -- gh api /user
baton http work https://api.github.com/user
```

For `baton run`, put baton options before the context name and the child command after `--`. The child gets a temporary `HOME` with this context's CLI configuration. Output is checked for known secrets before it is returned.

## Give an agent temporary access

```bash
baton lease new work --ttl 600 --uses 20
baton lease list
baton lease revoke LEASE_ID
```

The first command prints a lease token. Give that token only to the agent that needs it: anyone holding a live lease can use its allowed context. `--ttl` is in seconds; `--uses` sets a use limit. Add `--service github` to restrict a lease to that service.

## Connect an MCP client

Connect a local agent with one command:

```bash
baton setup --client codex
baton setup --client claude-code
baton setup --client cursor
baton setup --client vscode
```

Codex and Claude Code use their own setup commands. Cursor gets a personal `~/.cursor/mcp.json`; VS Code gets `.vscode/mcp.json` in the current project. For another MCP client, run `baton setup` to print JSON, or `baton setup --output PATH` to merge into its JSON config. Add `--root servers` if that client uses a `servers` key. baton uses its installed Python environment and includes the vault path, so the client opens the same vault. Setup leaves other configured servers alone.

Client formats follow the current [Codex](https://learn.chatgpt.com/docs/extend/mcp), [Claude Code](https://code.claude.com/docs/en/mcp), [Cursor](https://cursor.com/docs/mcp), and [VS Code](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) MCP guides.

If you use `BATON_MASTER_KEY` or `BATON_PASSPHRASE`, supply it to the client through its environment; setup never writes a key into the config. Agents without MCP can call `baton run` or `baton http` through a command tool. A local MCP server must be installed on the machine where the agent runs.

| What an agent needs to do | MCP tools |
| --- | --- |
| See available contexts and metadata | `baton_contexts`, `baton_credentials`, `baton_info` |
| Get or manage a pass | `baton_lease`, `baton_leases`, `baton_revoke` |
| Use a context | `baton_run`, `baton_http` |
| Refresh or inspect history | `baton_refresh`, `baton_audit` |

These tools do not return stored credential values. The server uses MCP Python SDK 2.x.

## Use other services

Run `baton info` to see the fields expected by each preset. Built-in presets are `aws`, `gcp`, `github`, `gitlab`, `npm`, `docker`, `kube`, `ssh`, and `generic`. Any other provider name uses bearer token auth by default.

```bash
baton cred add kube-prod --provider kube --field-file kubeconfig=~/.kube/config
baton cred add registry --provider docker \
  --field username --field password --field registry=ghcr.io
baton cred add my-api --provider my-service --field api_key \
  --auth header:x-api-key --auth-field api_key \
  --env 'MY_SERVICE_KEY={api_key}' --context work
```

Presets decide how baton sets environment variables, writes CLI config files, or attaches HTTP authentication. For a custom provider, `--auth` also accepts `bearer`, `query:NAME`, `basic` (with `username` and `password` fields), and `none` for CLI-only use. Use `--field-file NAME=PATH` for a file or longer value. Avoid `--field NAME=VALUE` for secrets because the value can appear in shell history and process listings.

## Refresh expiring tokens

baton can refresh an expiring credential before use. OAuth 2.0 refresh tokens, external commands, and custom Python handlers are supported. For OAuth, keep the client secret and refresh token in prompted fields:

```bash
baton cred add api --provider generic \
  --field token --field refresh_token --field client_secret \
  --refresh-provider oauth2 \
  --refresh-token-url https://auth.example.com/token \
  --refresh-client-id my-client-id

baton cred refresh api --force
```

OAuth refresh can rotate the refresh token and update the expiry from `expires_in`. Python integrations can register other handlers with `register_refresh_provider(name, handler)`.

## Useful commands

| Command | Purpose |
| --- | --- |
| `baton status` | Show vault status and counts. |
| `baton cred list` / `baton ctx list` | See stored names without revealing values. |
| `baton env work` | See which environment variables a context sets. |
| `baton audit` | Check the audit chain and recent activity. |
| `baton --help` | See all commands and examples. |

Use `--state-dir PATH` to choose another vault directory. `baton env --reveal` prints values for a human operator on explicit request; never use it in an agent transcript.

## Work on the package

The distribution name is `baton-auth` because `baton` is an unrelated PyPI project. The import name is `baton_auth`. This repository installs the `baton`, `baton-auth`, and `baton-mcp` commands. It is installable from GitHub; a PyPI release has not been published yet.

```bash
uv sync --extra dev
.venv/bin/python -m pytest tests -q
uv build
```
