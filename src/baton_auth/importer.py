"""Import existing local CLI logins and environment tokens into the vault."""

from __future__ import annotations

import base64
import configparser
import json
import os
import re
import subprocess
from pathlib import Path

from . import catalog
from .models import BatonError, Credential


class ImportError_(BatonError):
    """Could not import a credential from local state."""


_DEFAULT_ENV_VARS: dict[str, tuple[str, ...]] = {
    "github": ("GH_TOKEN", "GITHUB_TOKEN"),
    "gitlab": ("GITLAB_TOKEN", "GLAB_TOKEN"),
    "openai": ("OPENAI_API_KEY",),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "huggingface": ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN"),
    "pypi": ("UV_PUBLISH_TOKEN", "TWINE_PASSWORD", "POETRY_PYPI_TOKEN_PYPI"),
    "cloudflare": ("CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"),
    "stripe": ("STRIPE_API_KEY", "STRIPE_SECRET_KEY"),
    "slack": ("SLACK_BOT_TOKEN", "SLACK_TOKEN"),
    "npm": ("NPM_TOKEN",),
}


def import_credential(
    provider: str,
    *,
    name: str | None = None,
    profile: str = "default",
    from_path: str | Path | None = None,
    from_env: str | None = None,
) -> Credential:
    """Detect and import an existing local credential for `provider`."""
    provider = provider.strip().lower()
    cred_name = name or provider
    path = Path(from_path).expanduser() if from_path else None

    if from_env:
        val = os.environ.get(from_env, "").strip()
        if not val:
            raise ImportError_(f"environment variable {from_env!r} is not set or empty")
        return catalog.build_credential(cred_name, provider, {"token": val})

    if provider == "github":
        values = _import_github(path)
    elif provider == "aws":
        values = _import_aws(path, profile)
    elif provider == "npm":
        values = _import_npm(path)
    elif provider == "kube":
        values = _import_kube(path)
    elif provider == "gcp":
        values = _import_gcp(path)
    elif provider == "docker":
        values = _import_docker(path, None if profile == "default" else profile)
    elif provider == "ssh":
        values = _import_ssh(path)
    elif provider == "huggingface":
        values = _import_huggingface(path)
    elif provider == "pypi":
        values = _import_pypi(path)
    else:
        values = _import_from_env_or_file(provider, path)

    return catalog.build_credential(cred_name, provider, values)


_AUTO_IMPORT_ORDER: tuple[str, ...] = (
    "github",
    "aws",
    "anthropic",
    "openai",
    "huggingface",
    "npm",
    "pypi",
    "kube",
    "gcp",
    "docker",
    "gitlab",
    "cloudflare",
    "stripe",
    "slack",
)


def import_all() -> list[Credential]:
    """Scan local CLI configs and environment variables and import all found credentials."""
    found: list[Credential] = []
    for provider in _AUTO_IMPORT_ORDER:
        try:
            found.append(import_credential(provider))
        except BatonError:
            continue
    return found


def _import_github(path: Path | None) -> dict[str, str]:
    if path is None:
        try:
            proc = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return {"token": proc.stdout.strip()}
        except FileNotFoundError:
            pass
        cfg_dir = os.environ.get("GH_CONFIG_DIR")
        path = (Path(cfg_dir) if cfg_dir else Path.home() / ".config" / "gh") / "hosts.yml"

    if path.exists():
        text = path.read_text()
        m_tok = re.search(r"oauth_token:\s*(\S+)", text)
        if m_tok:
            out = {"token": m_tok.group(1).strip("\"'")}
            m_user = re.search(r"user:\s*(\S+)", text)
            if m_user:
                out["user"] = m_user.group(1).strip("\"'")
            return out

    return _import_from_env_or_file("github", None)


def _import_aws(path: Path | None, profile: str) -> dict[str, str]:
    creds_path = path or (Path.home() / ".aws" / "credentials")
    if creds_path.exists():
        cp = configparser.RawConfigParser()
        cp.read(creds_path)
        if cp.has_section(profile):
            sec = cp[profile]
            akid = sec.get("aws_access_key_id", "").strip()
            secret = sec.get("aws_secret_access_key", "").strip()
            if akid and secret:
                out = {"access_key_id": akid, "secret_access_key": secret}
                if sec.get("aws_session_token"):
                    out["session_token"] = sec["aws_session_token"].strip()
                region = sec.get("region", "").strip()
                if not region:
                    cfg_path = creds_path.parent / "config"
                    if cfg_path.exists():
                        cfg = configparser.RawConfigParser()
                        cfg.read(cfg_path)
                        cfg_sec = "default" if profile == "default" else f"profile {profile}"
                        if cfg.has_section(cfg_sec) and cfg[cfg_sec].get("region"):
                            region = cfg[cfg_sec]["region"].strip()
                if region:
                    out["region"] = region
                return out
    akid = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if akid and secret:
        out = {"access_key_id": akid, "secret_access_key": secret}
        if os.environ.get("AWS_SESSION_TOKEN"):
            out["session_token"] = os.environ["AWS_SESSION_TOKEN"].strip()
        if os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"):
            out["region"] = (
                os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or ""
            ).strip()
        return out
    raise ImportError_(f"no AWS credentials found for profile {profile!r} in {creds_path}")


def _import_npm(path: Path | None) -> dict[str, str]:
    npmrc = path or (Path.home() / ".npmrc")
    if npmrc.exists():
        for line in npmrc.read_text().splitlines():
            m = re.search(r"_authToken\s*=\s*(\S+)", line)
            if m:
                return {"token": m.group(1).strip("\"'")}
    return _import_from_env_or_file("npm", None)


def _import_kube(path: Path | None) -> dict[str, str]:
    kc = path or Path(os.environ.get("KUBECONFIG", "").split(":")[0] or (Path.home() / ".kube" / "config"))
    if not kc.exists():
        raise ImportError_(f"kubeconfig not found at {kc}")
    return {"kubeconfig": kc.read_text()}


def _import_gcp(path: Path | None) -> dict[str, str]:
    adc = path or Path(
        os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        or (Path.home() / ".config" / "gcloud" / "application_default_credentials.json")
    )
    if not adc.exists():
        raise ImportError_(f"GCP credentials file not found at {adc}")
    return {"service_account_json": adc.read_text()}


def _import_docker(path: Path | None, registry: str | None) -> dict[str, str]:
    cfg_path = path or (Path.home() / ".docker" / "config.json")
    if not cfg_path.exists():
        raise ImportError_(f"Docker config not found at {cfg_path}")
    data = json.loads(cfg_path.read_text())
    auths = data.get("auths") or {}
    targets = [registry] if registry else list(auths.keys())
    for reg in targets:
        entry = auths.get(reg) or {}
        raw_auth = entry.get("auth")
        if raw_auth:
            decoded = base64.b64decode(raw_auth).decode(errors="replace")
            if ":" in decoded:
                user, password = decoded.split(":", 1)
                return {"username": user, "password": password, "registry": reg}
    raise ImportError_(f"no decoded auth entry found in {cfg_path}")


def _import_ssh(path: Path | None) -> dict[str, str]:
    ssh_dir = Path.home() / ".ssh"
    candidates = [path] if path else [ssh_dir / "id_ed25519", ssh_dir / "id_rsa"]
    for cand in candidates:
        if cand and cand.exists():
            out = {"private_key": cand.read_text().rstrip("\n"), "key_name": cand.name}
            pub = cand.with_suffix(cand.suffix + ".pub")
            if pub.exists():
                out["public_key"] = pub.read_text().rstrip("\n")
            kh = cand.parent / "known_hosts"
            if kh.exists():
                out["known_hosts"] = kh.read_text()
            return out
    raise ImportError_("no SSH private key found in ~/.ssh")


def _import_huggingface(path: Path | None) -> dict[str, str]:
    hf_home = Path(os.environ.get("HF_HOME") or (Path.home() / ".cache" / "huggingface"))
    token_path = path or (hf_home / "token")
    if token_path.exists():
        tok = token_path.read_text().strip()
        if tok:
            return {"token": tok}
    return _import_from_env_or_file("huggingface", None)


def _import_pypi(path: Path | None) -> dict[str, str]:
    pypirc = path or (Path.home() / ".pypirc")
    if pypirc.exists():
        cp = configparser.RawConfigParser()
        cp.read(pypirc)
        if cp.has_section("pypi") and cp["pypi"].get("password"):
            return {"token": cp["pypi"]["password"].strip()}
    return _import_from_env_or_file("pypi", None)


def _import_from_env_or_file(provider: str, path: Path | None) -> dict[str, str]:
    if path is not None:
        if not path.exists():
            raise ImportError_(f"file not found: {path}")
        val = path.read_text().strip()
        if not val:
            raise ImportError_(f"file is empty: {path}")
        return {"token": val}
    for env_var in _DEFAULT_ENV_VARS.get(provider, ()):
        val = os.environ.get(env_var, "").strip()
        if val:
            return {"token": val}
    raise ImportError_(
        f"could not auto-detect {provider} credentials; pass --from-env VAR or --from-path PATH"
    )
