"""Execute a command inside a context's sandbox home.

The credential is never handed to the caller and never lands in the agent's
context: the child process gets a throwaway HOME containing only this context's
material, its output is scrubbed on the way back, and the home is destroyed
whether the command succeeded, failed, or timed out.
"""

from __future__ import annotations

import shutil
import time
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .materialize import apply, plan
from .models import BatonError, LeaseError
from .redact import Redactor
from .process import CaptureError, capture
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


def _resolve(
    vault: Vault, target: str | None, service: str | None
) -> tuple[str | None, str | None, list[str] | None]:
    """Accept a context name, a credential name, a lease token, or None for default."""
    if target and target.startswith("btn_"):
        lease = vault.resolve_lease(target)  # raises LeaseError
        if service is not None and not lease.allows(service):
            raise LeaseError(f"lease does not grant {service!r}")
        if service is not None:
            allowed = [service]
        elif lease.services and "*" not in lease.services:
            allowed = list(lease.services)
        else:
            allowed = None
        return lease.context, lease.id, allowed
    return target, None, [service] if service else None


def run(
    vault: Vault,
    target: str | None,
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
    target_name, lease_id, allowed_services = _resolve(vault, target, service)
    p = plan(vault, target_name, allowed_services=allowed_services)
    context_name = p.context.name

    run_root = vault.state_dir / "run"
    if run_root.is_symlink():
        raise RunError("command directory must not be a symlink")
    run_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    label = re.sub(r"[^A-Za-z0-9_.-]", "_", context_name)[:48]
    sandbox = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=run_root))
    started = time.monotonic()
    timed_out = False
    redactor = Redactor(p.secrets)
    try:
        env = apply(p, sandbox)
        if lease_id:
            env["BATON_LEASE"] = lease_id
        if env_extra:
            env.update(env_extra)

        # Scrub dangerous code-injection environment variables unless explicitly allowed
        dangerous_vars = (
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "PYTHONPATH",
            "NODE_OPTIONS",
            "BASH_ENV",
            "ENV",
        )
        for var in dangerous_vars:
            if var in env and var not in p.context.passthrough:
                del env[var]

        redactor = Redactor([*p.secrets, *(env[k] for k in p.sources if k in env)])
        argv_list = list(argv)
        run_cwd: str | None = None
        if cwd is not None:
            resolved_cwd = Path(cwd).expanduser()
            if not resolved_cwd.is_dir():
                raise RunError(redactor(f"working directory not found: {cwd}"))
            run_cwd = str(resolved_cwd)
        try:
            result = capture(
                argv_list, cwd=run_cwd, env=env, timeout=timeout,
                input_data=stdin.encode() if stdin is not None else None,
                inherit_stdin=True,
            )
            out = result.stdout.decode("utf-8", errors="replace")
            err = result.stderr.decode("utf-8", errors="replace")
            timed_out, code = result.timed_out, result.returncode
        except CaptureError as exc:
            raise RunError(str(exc)) from None
        except (TypeError, ValueError):
            raise RunError("invalid command arguments or environment") from None
        except FileNotFoundError:
            raise RunError(redactor(f"command not found: {argv_list[0]}")) from None
        except OSError as exc:
            raise RunError(redactor(f"cannot run command: {exc}")) from None
    except BatonError as exc:
        raise RunError(redactor(str(exc))) from None
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    partial_out = partial_err = 0
    if timed_out:
        out, partial_out = redactor.redact_partial_tail(out)
        err, partial_err = redactor.redact_partial_tail(err)
    clean_out, n1 = redactor.redact_counted(out)
    clean_err, n2 = redactor.redact_counted(err)
    redacted_args = [redactor.redact_counted(arg) for arg in argv_list]
    clean_argv = [arg for arg, _ in redacted_args]
    redactions = n1 + n2 + partial_out + partial_err + sum(count for _, count in redacted_args)
    duration = int((time.monotonic() - started) * 1000)

    vault.audit(
        lease_id,
        None,
        "run",
        clean_argv[0],
        code == 0,
        {
            "context": context_name,
            "exit_code": code,
            "redactions": redactions,
            "argv_len": len(argv_list),
        },
    )
    return RunResult(
        argv=clean_argv,
        context=context_name,
        lease_id=lease_id,
        exit_code=code,
        stdout=clean_out,
        stderr=clean_err,
        duration_ms=duration,
        redactions=redactions,
        timed_out=timed_out,
    )
