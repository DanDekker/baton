"""Provider presets: how a secret becomes a working CLI auth.

A preset is the whole domain knowledge of this tool. For each provider it fixes
(a) the secret fields, (b) the materialization steps that make a CLI accept
those fields in an isolated HOME, and (c) how the brokered HTTP layer attaches
the credential.

Templating: `{field}` is substituted from the secret payload, `{HOME}` from the
sandbox home. Anything else left unresolved is a hard error at plan time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import BatonError, Credential


class PresetError(BatonError):
    """Invalid provider or missing required fields."""


@dataclass(frozen=True, slots=True)
class Preset:
    provider: str
    fields: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    materialize: tuple[dict[str, Any], ...] = ()
    auth: dict[str, Any] = field(default_factory=dict)
    hosts: tuple[str, ...] = ()
    hint: str = ""

    @property
    def all_fields(self) -> tuple[str, ...]:
        return self.fields + self.optional


_GH_HOSTS = "github.com:\n    oauth_token: {token}\n    git_protocol: https\n"
_GH_HOSTS_USER = "    user: {user}\n"

PRESETS: dict[str, Preset] = {
    "aws": Preset(
        provider="aws",
        fields=("access_key_id", "secret_access_key"),
        optional=("session_token", "region"),
        materialize=(
            {
                "kind": "env",
                "map": {
                    "AWS_ACCESS_KEY_ID": "{access_key_id}",
                    "AWS_SECRET_ACCESS_KEY": "{secret_access_key}",
                    "AWS_SESSION_TOKEN": "{session_token}",
                    "AWS_REGION": "{region}",
                    "AWS_DEFAULT_REGION": "{region}",
                },
            },
            {
                "kind": "ini",
                "path": ".aws/credentials",
                "section": "default",
                "map": {
                    "aws_access_key_id": "{access_key_id}",
                    "aws_secret_access_key": "{secret_access_key}",
                    "aws_session_token": "{session_token}",
                },
            },
        ),
        auth={"scheme": "sigv4", "service": "execute-api"},
        hint="AWS access key (or STS session credentials)",
    ),
    "gcp": Preset(
        provider="gcp",
        fields=("service_account_json",),
        materialize=(
            {
                "kind": "file",
                "path": ".config/gcloud/baton-sa.json",
                "mode": "0600",
                "template": "{service_account_json}",
            },
            {
                "kind": "env",
                "map": {
                    "GOOGLE_APPLICATION_CREDENTIALS": "{HOME}/.config/gcloud/baton-sa.json",
                    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": "{HOME}/.config/gcloud/baton-sa.json",
                },
            },
        ),
        auth={"scheme": "bearer", "field": "access_token"},
        hint="GCP service-account JSON blob",
    ),
    "github": Preset(
        provider="github",
        fields=("token",),
        optional=("user",),
        materialize=(
            {
                "kind": "env",
                "map": {"GH_TOKEN": "{token}", "GITHUB_TOKEN": "{token}"},
            },
            {"kind": "file", "path": ".config/gh/hosts.yml", "template": _GH_HOSTS},
            {
                "kind": "file",
                "path": ".config/gh/hosts.yml",
                "optional": True,
                "template": _GH_HOSTS_USER,
            },
        ),
        auth={"scheme": "bearer", "field": "token"},
        hosts=("api.github.com", "*.github.com", "*.githubusercontent.com"),
        hint="GitHub PAT (ghp_/github_pat_) or fine-grained token",
    ),
    "gitlab": Preset(
        provider="gitlab",
        fields=("token",),
        materialize=(
            {"kind": "env", "map": {"GITLAB_TOKEN": "{token}", "GLAB_TOKEN": "{token}"}},
        ),
        auth={"scheme": "header", "header": "PRIVATE-TOKEN", "field": "token"},
        hosts=("gitlab.com", "*.gitlab.com"),
        hint="GitLab PAT (glpat-)",
    ),
    "npm": Preset(
        provider="npm",
        fields=("token",),
        materialize=(
            {"kind": "env", "map": {"NPM_TOKEN": "{token}"}},
            {
                "kind": "file",
                "path": ".npmrc",
                "template": "//registry.npmjs.org/:_authToken={token}\n",
            },
        ),
        auth={"scheme": "bearer", "field": "token"},
        hosts=("registry.npmjs.org", "*.npmjs.org", "*.npmjs.com"),
        hint="npm registry token",
    ),
    "docker": Preset(
        provider="docker",
        fields=("username", "password"),
        optional=("registry",),
        materialize=(
            {
                "kind": "docker_auth",
                "path": ".docker/config.json",
                "registry": "{registry}",
                "username": "{username}",
                "password": "{password}",
            },
        ),
        auth={"scheme": "basic", "user": "username", "password": "password"},
        hint="Container registry credentials",
    ),
    "kube": Preset(
        provider="kube",
        fields=("kubeconfig",),
        materialize=(
            {
                "kind": "file",
                "path": ".kube/config",
                "mode": "0600",
                "template": "{kubeconfig}",
            },
            {"kind": "env", "map": {"KUBECONFIG": "{HOME}/.kube/config"}},
        ),
        auth={"scheme": "bearer", "field": "token"},
        hint="Full kubeconfig YAML",
    ),
    "ssh": Preset(
        provider="ssh",
        fields=("private_key",),
        optional=("public_key", "known_hosts", "key_name"),
        materialize=(
            {
                "kind": "file",
                "path": ".ssh/{key_name}",
                "mode": "0600",
                "template": "{private_key}\n",
            },
            {
                "kind": "file",
                "path": ".ssh/{key_name}.pub",
                "mode": "0644",
                "optional": True,
                "template": "{public_key}\n",
            },
            {
                "kind": "file",
                "path": ".ssh/known_hosts",
                "mode": "0644",
                "optional": True,
                "template": "{known_hosts}",
            },
        ),
        hint="SSH private key material",
    ),
    "openai": Preset(
        provider="openai",
        fields=("token",),
        optional=("org_id", "project_id"),
        materialize=(
            {
                "kind": "env",
                "map": {
                    "OPENAI_API_KEY": "{token}",
                    "OPENAI_ORG_ID": "{org_id}",
                    "OPENAI_PROJECT_ID": "{project_id}",
                },
            },
        ),
        auth={"scheme": "bearer", "field": "token"},
        hosts=("api.openai.com", "*.openai.com"),
        hint="OpenAI API key (sk-proj-/sk-)",
    ),
    "anthropic": Preset(
        provider="anthropic",
        fields=("token",),
        materialize=(
            {"kind": "env", "map": {"ANTHROPIC_API_KEY": "{token}"}},
        ),
        auth={"scheme": "header", "header": "x-api-key", "field": "token"},
        hosts=("api.anthropic.com", "*.anthropic.com"),
        hint="Anthropic API key (sk-ant-)",
    ),
    "huggingface": Preset(
        provider="huggingface",
        fields=("token",),
        materialize=(
            {
                "kind": "env",
                "map": {
                    "HF_TOKEN": "{token}",
                    "HUGGING_FACE_HUB_TOKEN": "{token}",
                },
            },
            {
                "kind": "file",
                "path": ".cache/huggingface/token",
                "mode": "0600",
                "template": "{token}",
            },
        ),
        auth={"scheme": "bearer", "field": "token"},
        hosts=("huggingface.co", "*.huggingface.co", "*.hf.co"),
        hint="Hugging Face user access token (hf_)",
    ),
    "pypi": Preset(
        provider="pypi",
        fields=("token",),
        materialize=(
            {
                "kind": "env",
                "map": {
                    "UV_PUBLISH_TOKEN": "{token}",
                    "TWINE_USERNAME": "__token__",
                    "TWINE_PASSWORD": "{token}",
                    "POETRY_PYPI_TOKEN_PYPI": "{token}",
                },
            },
            {
                "kind": "file",
                "path": ".pypirc",
                "mode": "0600",
                "template": "[pypi]\nusername = __token__\npassword = {token}\n",
            },
        ),
        auth={"scheme": "bearer", "field": "token"},
        hosts=("upload.pypi.org", "test.pypi.org", "pypi.org", "*.pypi.org"),
        hint="PyPI API token (pypi-)",
    ),
    "cloudflare": Preset(
        provider="cloudflare",
        fields=("token",),
        optional=("account_id",),
        materialize=(
            {
                "kind": "env",
                "map": {
                    "CLOUDFLARE_API_TOKEN": "{token}",
                    "CF_API_TOKEN": "{token}",
                    "CLOUDFLARE_ACCOUNT_ID": "{account_id}",
                },
            },
        ),
        auth={"scheme": "bearer", "field": "token"},
        hosts=("api.cloudflare.com", "*.cloudflare.com"),
        hint="Cloudflare API token",
    ),
    "stripe": Preset(
        provider="stripe",
        fields=("token",),
        materialize=(
            {
                "kind": "env",
                "map": {
                    "STRIPE_API_KEY": "{token}",
                    "STRIPE_SECRET_KEY": "{token}",
                },
            },
        ),
        auth={"scheme": "bearer", "field": "token"},
        hosts=("api.stripe.com", "*.stripe.com"),
        hint="Stripe secret or restricted key (sk_/rk_)",
    ),
    "slack": Preset(
        provider="slack",
        fields=("token",),
        materialize=(
            {
                "kind": "env",
                "map": {
                    "SLACK_BOT_TOKEN": "{token}",
                    "SLACK_TOKEN": "{token}",
                },
            },
        ),
        auth={"scheme": "bearer", "field": "token"},
        hosts=("slack.com", "*.slack.com"),
        hint="Slack bot or user token (xoxb-/xoxp-)",
    ),
    "generic": Preset(
        provider="generic",
        fields=("token",),
        materialize=(),
        auth={"scheme": "bearer", "field": "token"},
        hint="Bare token; add env mapping with --env NAME={token}",
    ),
}


def preset(provider: str) -> Preset:
    if not provider.strip():
        raise PresetError("provider name cannot be empty")
    return PRESETS.get(provider) or Preset(
        provider=provider,
        auth={"scheme": "bearer", "field": "token"},
        hint="Custom provider; bearer token by default",
    )


def build_credential(
    name: str,
    provider: str,
    values: dict[str, str],
    *,
    expires_at: float | None = None,
    notes: str = "",
    env_map: dict[str, str] | None = None,
    refresh: dict[str, Any] | None = None,
    auth: dict[str, Any] | None = None,
    allowed_hosts: list[str] | None = None,
) -> Credential:
    """Validate field coverage and assemble a Credential from a preset."""
    p = preset(provider)
    if provider == "ssh" and "key_name" not in values:
        values = {**values, "key_name": "id_baton"}
    auth_spec = dict(auth) if auth is not None else dict(p.auth)
    if provider in PRESETS and provider != "generic":
        required = list(p.fields)
    elif auth_spec.get("scheme") == "basic":
        required = ["username", "password"]
    elif auth_spec.get("scheme") == "none":
        required = []
    else:
        required = [str(auth_spec.get("field", "token"))]
    if auth is not None:
        if auth_spec.get("scheme") == "basic":
            required.extend(("username", "password"))
        elif auth_spec.get("scheme") in {"bearer", "header", "query"}:
            required.append(str(auth_spec.get("field", "token")))
    missing = [f for f in dict.fromkeys(required) if not values.get(f)]
    if missing:
        raise PresetError(f"{provider}: missing required field(s): {', '.join(missing)}")
    if not any(values.values()):
        raise PresetError(f"{provider}: provide at least one secret field")
    allowed = set(p.all_fields) | {"refresh_token", "client_id", "client_secret"}
    unknown = [k for k in values if k not in allowed]
    if unknown and provider in PRESETS and provider != "generic":
        raise PresetError(f"{provider}: unknown field(s): {', '.join(unknown)}")

    steps: list[dict[str, Any]] = [dict(s) for s in p.materialize]
    if env_map:
        steps.append({"kind": "env", "map": dict(env_map)})

    if allowed_hosts is not None:
        hosts = [h.strip().lower() for h in allowed_hosts if h.strip()]
    else:
        hosts = list(p.hosts)

    # Incomplete optional steps are dropped at plan time; prune empty templates here.
    return Credential(
        name=name,
        provider=provider,
        secret={k: v for k, v in values.items() if v},
        materialize=steps,
        auth=auth_spec,
        refresh=dict(refresh or {}),
        allowed_hosts=hosts,
        expires_at=expires_at,
        notes=notes,
        meta={"preset": provider},
    )
