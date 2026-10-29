"""Turn a context into a concrete, isolated CLI environment.

This is the piece that makes baton more than a password manager: a context is
materialized into a *sandbox home*, so two agents can hold different AWS/GH/kube
auths at the same time without touching each other's global CLI state, and
nothing they run can read a credential belonging to another context.

Planning is pure (no disk writes) so it can be inspected and tested; applying is
a separate step the runner performs inside a temp dir it owns.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import BatonError, Context
from .vault import Vault


class MaterializeError(BatonError):
    """A context could not be turned into an environment."""


# Anything matching this never leaks in from the caller's environment.
_SENSITIVE = re.compile(
    r"(?i)(token|secret|passw|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|credential|auth|cookie|session|bearer|_pat$|^glpat)"
)

# Minimal environment every child process needs regardless of context.
_BASE_ENV = ("PATH", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "USER", "SHELL")

_PLACEHOLDER = re.compile(r"\{([a-zA-Z0-9_]+)\}")


@dataclass(slots=True)
class FileSpec:
    path: str
    content: str
    mode: int = 0o600


@dataclass(slots=True)
class Plan:
    context: Context
    env: dict[str, str] = field(default_factory=dict)
    files: list[FileSpec] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)  # env name / path -> credential


def _render(template: str, fields: dict[str, str], home: str, where: str) -> str:
    def sub(m: re.Match[str]) -> str:
        name = m.group(1)
        if name == "HOME":
            return home
        if name not in fields:
            raise MaterializeError(f"{where}: unresolved placeholder {{{name}}}")
        return fields[name]

    return _PLACEHOLDER.sub(sub, template)


def _refs(template: str) -> set[str]:
    """Placeholders a template depends on, excluding {HOME}."""
    return set(_PLACEHOLDER.findall(template)) - {"HOME"}


def plan(vault: Vault, context_name: str) -> Plan:
    ctx = vault.get_context(context_name)
    p = Plan(context=ctx)

    base: dict[str, str] = {k: os.environ[k] for k in _BASE_ENV if k in os.environ}
    base.update(ctx.env)
    for name in ctx.passthrough:
        if name in os.environ:
            base[name] = os.environ[name]
    p.env = base

    for cred_name in ctx.credentials:
        cred = vault.get_credential(cred_name)
        fields = {k: v for k, v in cred.secret.items() if v}
        p.secrets.extend(v for v in fields.values() if len(v) >= 8)
        where = f"credential {cred.name}"
        for step in cred.materialize:
            kind = step.get("kind")
            if kind == "env":
                # Per-entry skip: an absent *optional* field must not drop the
                # whole env block (that silently unsets required variables).
                for env_name, tmpl in step["map"].items():
                    if _refs(tmpl) - fields.keys():
                        continue
                    if "{HOME}" in tmpl:
                        rel = _render(tmpl, fields, "", where).lstrip("/")
                        p.env[env_name] = f"HOME_REL:{rel}"
                    else:
                        value = _render(tmpl, fields, "", where)
                        if value:
                            p.env[env_name] = value
                    p.sources[env_name] = cred.name
            elif kind == "file":
                refs = _refs(step["template"]) | _refs(step["path"])
                if refs - fields.keys():
                    if step.get("optional"):
                        continue
                    raise MaterializeError(
                        f"{where}: missing field(s) {sorted(refs - fields.keys())} "
                        f"for {step['path']}"
                    )
                path = _render(step["path"], fields, "", where).lstrip("/")
                content = _render(step["template"], fields, "", where)
                p.files.append(
                    FileSpec(path=path, content=content, mode=int(str(step.get("mode", "0600")), 8))
                )
                p.sources[path] = cred.name
            elif kind == "ini":
                path = _render(step["path"], fields, "", where).lstrip("/")
                lines = [f"[{step.get('section', 'default')}]"]
                for key, tmpl in step["map"].items():
                    if _refs(tmpl) - fields.keys():
                        continue
                    value = _render(tmpl, fields, "", where)
                    if value:
                        lines.append(f"{key} = {value}")
                if len(lines) > 1:
                    p.files.append(FileSpec(path=path, content="\n".join(lines) + "\n"))
                    p.sources[path] = cred.name
            elif kind == "docker_auth":
                registry = step.get("registry") or "https://index.docker.io/v1/"
                if _refs(registry) - fields.keys():
                    registry = "https://index.docker.io/v1/"
                registry = _render(registry, fields, "", where)
                user = _render(step["username"], fields, "", where)
                password = _render(step["password"], fields, "", where)
                token = base64.b64encode(f"{user}:{password}".encode()).decode()
                payload = {"auths": {registry: {"auth": token}}}
                p.files.append(
                    FileSpec(path=step["path"].lstrip("/"), content=json.dumps(payload, indent=2))
                )
                p.sources[step["path"]] = cred.name
            else:
                raise MaterializeError(f"{where}: unknown materialize kind {kind!r}")
    return p


def apply(plan_obj: Plan, home: Path) -> dict[str, str]:
    """Write the plan into `home` and return the final environment."""
    home = home.resolve()
    home.mkdir(parents=True, exist_ok=True)
    os_home = str(home)

    for spec in plan_obj.files:
        target = home / spec.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(spec.content)
        target.chmod(spec.mode)

    env = dict(plan_obj.env)
    for name, value in list(env.items()):
        if value.startswith("HOME_REL:"):
            env[name] = f"{os_home}/{value[len('HOME_REL:'):]}"
    env.update(
        {
            "HOME": os_home,
            "XDG_CONFIG_HOME": f"{os_home}/.config",
            "XDG_CACHE_HOME": f"{os_home}/.cache",
            "XDG_DATA_HOME": f"{os_home}/.local/share",
            "XDG_STATE_HOME": f"{os_home}/.local/state",
            "BATON_CONTEXT": plan_obj.context.name,
        }
    )
    for d in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
        Path(env[d]).mkdir(parents=True, exist_ok=True)

    # opt-in inheritance of non-secret dotfiles (gitconfig, ssh/known_hosts, ...)
    real_home = Path.home()
    for rel in plan_obj.context.inherit_paths:
        src = real_home / rel
        dst = home / rel
        if not src.exists():
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists():
            continue
        dst.write_text(src.read_text(errors="replace"))
    return env


def scrub(env: dict[str, str]) -> dict[str, str]:
    """Drop caller env vars that look like credentials (defence in depth)."""
    return {k: v for k, v in env.items() if not _SENSITIVE.search(k)}
