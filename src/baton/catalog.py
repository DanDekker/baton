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
    """Unknown provider or missing required fields."""


@dataclass(frozen=True, slots=True)
class Preset:
    provider: str
    fields: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    materialize: tuple[dict[str, Any], ...] = ()
    auth: dict[str, Any] = field(default_factory=dict)
    hint: str = ""

    @property
    def all_fields(self) -> tuple[str, ...]:
        return self.fields + self.optional


_GH_HOSTS = """github.com:\n    oauth_token: {token}\n    user: {user}\n    git_protocol: https\n"""

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
        ),
        auth={"scheme": "bearer", "field": "token"},
        hint="GitHub PAT (ghp_/github_pat_) or fine-grained token",
    ),
    "gitlab": Preset(
        provider="gitlab",
        fields=("token",),
        materialize=(
            {"kind": "env", "map": {"GITLAB_TOKEN": "{token}", "GLAB_TOKEN": "{token}"}},
        ),
        auth={"scheme": "header", "header": "PRIVATE-TOKEN", "field": "token"},
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
    "generic": Preset(
        provider="generic",
        fields=("token",),
        materialize=(),
        auth={"scheme": "bearer", "field": "token"},
        hint="Bare token; add env mapping with --env NAME={token}",
    ),
}


def preset(provider: str) -> Preset:
    try:
        return PRESETS[provider]
    except KeyError:
        raise PresetError(
            f"unknown provider {provider!r} (have: {', '.join(sorted(PRESETS))})"
        ) from None


def build_credential(
    name: str,
    provider: str,
    values: dict[str, str],
    *,
    expires_at: float | None = None,
    notes: str = "",
    env_map: dict[str, str] | None = None,
) -> Credential:
    """Validate field coverage and assemble a Credential from a preset."""
    p = preset(provider)
    if provider == "ssh" and "key_name" not in values:
        values = {**values, "key_name": "id_baton"}
    missing = [f for f in p.fields if not values.get(f)]
    if missing:
        raise PresetError(f"{provider}: missing required field(s): {', '.join(missing)}")
    unknown = [k for k in values if k not in p.all_fields]
    if unknown and provider != "generic":
        raise PresetError(f"{provider}: unknown field(s): {', '.join(unknown)}")

    steps: list[dict[str, Any]] = [dict(s) for s in p.materialize]
    if env_map:
        steps.append({"kind": "env", "map": dict(env_map)})

    # Incomplete optional steps are dropped at plan time; prune empty templates here.
    return Credential(
        name=name,
        provider=provider,
        secret={k: v for k, v in values.items() if v},
        materialize=steps,
        auth=dict(p.auth),
        expires_at=expires_at,
        notes=notes,
        meta={"preset": provider},
    )
