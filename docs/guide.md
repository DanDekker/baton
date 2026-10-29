# Using baton

[Back to overview](../README.md) · [Security and limits](security.md)

baton keeps credentials on your machine and uses them on an agent's behalf. Three terms are enough to get started:

| Term | What it means |
| --- | --- |
| **Credential** | A token, password, key, or config file you store in baton. |
| **Context** | A named group of credentials, such as `work` or `staging`. |
| **Lease** | A temporary pass to use a context. It can expire, run out of uses, or be revoked. |

## Set up a context

Install with Python 3.10+ and [uv](https://docs.astral.sh/uv/), then import your existing logins or add a token. `baton add SERVICE` prompts privately for required fields without putting secrets in shell history.

```bash
uv tool install baton-auth

baton import                # auto-import local logins (gh, aws, npm, kube, ...)
baton add github            # or prompt privately for a single service
baton list
```

Run a command or send an HTTP request using a credential name, a context name, or the default context:

```bash
baton run -- gh api /user
baton run github -- gh api /user
baton http https://api.github.com/user -H "Accept: application/vnd.github+json"
```

When a context has multiple credentials, `baton http` automatically selects the credential whose allowed host matches the request URL. For `baton run`, put baton options before `--` and the child command after `--`. The child runs in your current working directory (or `--cwd PATH`) with a temporary `HOME` containing only the permitted CLI configuration. Output is checked for known secrets (including URL- and base64-encoded forms) before it is returned.

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
baton setup --client claude-desktop
baton setup --client windsurf
baton setup --client zed
baton setup --client muse-code
baton setup --client hermes-agent
baton setup --client agents-md
```

Codex and Claude Code use their own setup commands. Cursor gets a personal `~/.cursor/mcp.json`; VS Code gets `.vscode/mcp.json` in the current project. For another MCP client, run `baton setup` to print JSON, or `baton setup --output PATH` to merge into its JSON config. Add `--root servers` if that client uses a `servers` key. baton uses its installed Python environment and includes the vault path, so the client opens the same vault. Setup leaves other configured servers alone.

Muse Code gets `~/.config/muse/settings.json` (or `$XDG_CONFIG_HOME/muse/settings.json`); Hermes Agent gets `~/.hermes/config.yaml` (or `$HERMES_HOME/config.yaml`). Both keep their existing settings and other MCP servers. Use `--output PATH` to target another config file.

Client formats follow the current [Codex](https://learn.chatgpt.com/docs/extend/mcp), [Claude Code](https://code.claude.com/docs/en/mcp), [Cursor](https://cursor.com/docs/mcp), [VS Code](https://code.visualstudio.com/docs/agents/reference/mcp-configuration), [Muse Code](https://meta-models.github.io/muse-code-sdk/next/guides/extend/mcp-servers/), and [Hermes Agent](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/reference/mcp-config-reference.md) MCP guides.

If you use `BATON_MASTER_KEY` or `BATON_PASSPHRASE`, supply it to the client through its environment; setup never writes a key into the config. Agents without MCP can call `baton run` or `baton http` through a command tool. A local MCP server must be installed on the machine where the agent runs.

| What an agent needs to do | MCP tools |
| --- | --- |
| See available contexts and metadata | `baton_contexts`, `baton_credentials`, `baton_info` |
| Get or manage a pass | `baton_lease`, `baton_leases`, `baton_revoke` |
| Use a context | `baton_run`, `baton_http` |
| Refresh or inspect history | `baton_refresh`, `baton_audit` |

These tools do not return stored credential values. The server uses MCP Python SDK 2.x.

## Use other services

Run `baton info` to see the fields expected by each preset. Built-in presets are `aws`, `gcp`, `github`, `gitlab`, `npm`, `docker`, `kube`, `ssh`, `openai`, `anthropic`, `huggingface`, `pypi`, `cloudflare`, `stripe`, `slack`, and `generic`. Any other provider name uses bearer token auth by default.

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

The [PyPI package](https://pypi.org/project/baton-auth/) is named `baton-auth` because `baton` is an unrelated project. The import name is `baton_auth`. It installs the `baton`, `baton-auth`, and `baton-mcp` commands. Version tags build and publish the package through GitHub Actions.

```bash
uv sync --extra dev
.venv/bin/python -m pytest tests -q
uv build
```
