<div align="center">

<img src="https://raw.githubusercontent.com/DanDekker/baton/main/assets/baton-banner.svg" alt="baton — Pass the baton, never the secret." width="100%">

<p><a href="#try-it">Try it</a> · <a href="https://github.com/DanDekker/baton/blob/main/docs/guide.md">User guide</a> · <a href="https://github.com/DanDekker/baton/blob/main/docs/security.md">Security</a></p>

<p><a href="https://github.com/DanDekker/baton/actions/workflows/package.yml"><img src="https://github.com/DanDekker/baton/actions/workflows/package.yml/badge.svg?branch=main" alt="Package CI"></a></p>

</div>

---

**baton is a local authentication broker for AI agents and MCP tools.** It lets an agent use your GitHub, cloud, or API credentials without putting the secret value into its chat or tool output.

Save a credential once, group it into a **context** such as `work`, then give an agent a **lease**: a temporary pass that can expire or be revoked. baton uses the credential for a command or HTTP request and hides known secrets in the result.

## Try it

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/). Install [baton-auth from PyPI](https://pypi.org/project/baton-auth/):

```bash
uv tool install baton-auth

baton cred add gh-work --provider github --field token --context work
# or import an existing local login:
baton cred import github --context work

baton run work -- gh api /user
baton http work https://api.github.com/user
baton lease new work --ttl 600 --uses 20
baton setup  # prints MCP config for an agent client
```

The bare `--field token` prompts privately (or reads from piped stdin). Commands run in your working directory with a temporary `HOME` containing only that context's CLI settings.

`baton setup --client CLIENT` connects Codex, Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Zed, Muse Code, Hermes Agent, or writes `AGENTS.md` instructions. `baton setup` prints portable MCP config for other clients. Agents with command access can use `baton run` or `baton http`.

## Cryptography at a glance

| Name | How baton uses it |
| --- | --- |
| AES-256-GCM-SIV; ChaCha20-Poly1305 fallback | Encrypts credentials in the local vault. |
| BLAKE3 | Derives separate keys, authenticates leases and vault records, and links audit entries. |
| Argon2id | Turns a passphrase into the vault key when passphrase mode is used. |
| HMAC-SHA-256 | Signs AWS requests using Signature Version 4. |

## Learn more

- [User guide](https://github.com/DanDekker/baton/blob/main/docs/guide.md) — contexts, leases, providers, refresh, and MCP tools.
- [Security and limits](https://github.com/DanDekker/baton/blob/main/docs/security.md) — what baton protects, how it stores secrets, and where its boundary ends.

The distribution is named `baton-auth` and also provides the `baton-auth` command. The Python import is `baton_auth`.

baton runs locally for one user on one machine. A temporary `HOME` keeps CLI configuration separate; it is not a full operating-system sandbox.
