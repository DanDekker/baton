"""Execute a command inside a context's sandbox home.

The credential is never handed to the caller and never lands in the agent's
context: the child process gets a throwaway HOME containing only this context's
material, its output is scrubbed on the way back, and the home is destroyed
whether the command succeeded, failed, or timed out.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .materialize import apply, plan
from .models import BatonError, LeaseError
from .redact import Redactor
from .vault import Vault


class RunError(BatonError):
    """The command could not be started."""


@dataclass(slots=True)
class RunResult:
    argv: list[str]
    context: str
    lease_id: str | None
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    redactions: int = 0
    timed_out: bool = False
    extra: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "argv": self.argv,
            "context": self.context,
            "lease_id": self.lease_id,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "redactions": self.redactions,
            "timed_out": self.timed_out,
        }


def _resolve(vault: Vault, target: str, service: str | None) -> tuple[str, str | None]:
    """Accept either a context name or a lease token."""
    if target.startswith("btn_"):
        lease = vault.resolve_lease(target)  # raises LeaseError
        if not lease.allows(service):
            raise LeaseError(f"lease does not grant {service!r}")
        return lease.context, lease.id
    return target, None


def run(
    vault: Vault,
    target: str,
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: float | None = None,
    env_extra: dict[str, str] | None = None,
    stdin: str | None = None,
    service: str | None = None,
) -> RunResult:
    if not argv:
        raise RunError("empty command")
    context_name, lease_id = _resolve(vault, target, service)
    p = plan(vault, context_name)

    sandbox = vault.state_dir / "run" / f"{context_name}-{uuid.uuid4().hex[:12]}"
    started = time.monotonic()
    timed_out = False
    try:
        env = apply(p, sandbox)
        if lease_id:
            env["BATON_LEASE"] = lease_id
        if env_extra:
            env.update(env_extra)
        argv_list = list(argv)
        try:
            proc = subprocess.run(
                argv_list,
                cwd=cwd or str(sandbox),
                env=env,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            out, err, code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            out = _decode(exc.stdout)
            err = _decode(exc.stderr)
            code = -signal.SIGKILL
        except FileNotFoundError as exc:
            raise RunError(f"command not found: {argv_list[0]}") from exc
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    # Only credential-derived values are redacted. Feeding every env value in
    # here would scrub HOME/PATH out of the child's own output.
    redactor = Redactor([*p.secrets, *(env[k] for k in p.sources if k in env)])
    clean_out, n1 = redactor.redact_counted(out)
    clean_err, n2 = redactor.redact_counted(err)
    duration = int((time.monotonic() - started) * 1000)

    vault.audit(
        lease_id,
        None,
        "run",
        argv_list[0],
        code == 0,
        {
            "context": context_name,
            "exit_code": code,
            "redactions": n1 + n2,
            "argv_len": len(argv_list),
        },
    )
    return RunResult(
        argv=argv_list,
        context=context_name,
        lease_id=lease_id,
        exit_code=code,
        stdout=clean_out,
        stderr=clean_err,
        duration_ms=duration,
        redactions=n1 + n2,
        timed_out=timed_out,
    )


def _decode(data: object) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode(errors="replace")
    return str(data)


def cleanup_stale_runs(vault: Vault) -> int:
    """Remove sandbox homes left behind by a killed daemon."""
    runs = vault.state_dir / "run"
    if not runs.exists():
        return 0
    removed = 0
    for child in runs.iterdir():
        if child.is_dir() and (time.time() - child.stat().st_mtime) > 3600:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
    return removed
