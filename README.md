<div align="center">

<img src="https://raw.githubusercontent.com/DanDekker/baton/master/assets/baton-banner.svg" alt="baton — Pass the baton, never the secret." width="100%">

<p><a href="#try-it">Try it</a> · <a href="https://github.com/DanDekker/baton/blob/master/docs/guide.md">User guide</a> · <a href="https://github.com/DanDekker/baton/blob/master/docs/security.md">Security</a></p>

</div>

---

**baton is a local authentication broker for AI agents and MCP tools.** It lets an agent use your GitHub, cloud, or API credentials without putting the secret value into its chat or tool output.

Save a credential once, group it into a **context** such as `work`, then give an agent a **lease**: a temporary pass that can expire or be revoked. baton uses the credential for a command or HTTP request and hides known secrets in the result.

## Try it

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
source .venv/bin/activate

baton cred add gh-work --provider github --field token  # prompts privately
baton ctx add work --cred gh-work

baton run work -- gh api /user
baton http work https://api.github.com/user
baton lease new work --ttl 600 --uses 20
```

Commands run with a temporary `HOME` containing that context's CLI settings. For agents, the MCP server offers the same `run` and `http` actions through tools that return metadata and redacted results.

```json
{
  "mcpServers": {
    "baton": {
      "command": "/absolute/path/to/baton/.venv/bin/baton-mcp"
    }
  }
}
```

## Learn more

- [User guide](https://github.com/DanDekker/baton/blob/master/docs/guide.md) — contexts, leases, providers, refresh, and MCP tools.
- [Security and limits](https://github.com/DanDekker/baton/blob/master/docs/security.md) — what baton protects, how it stores secrets, and where its boundary ends.

baton runs locally for one user on one machine. A temporary `HOME` keeps CLI configuration separate; it is not a full operating-system sandbox.
