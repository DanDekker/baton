import json
import sys
from pathlib import Path

import pytest

from baton_auth import runner
from baton_auth.catalog import build_credential
from baton_auth.models import BatonError, Context
from baton_auth.vault import Vault


@pytest.fixture
def vault(tmp_path):
    with Vault(state_dir=tmp_path / "state", master_key=b"k" * 32) as vault:
        vault.put_credential(
            build_credential("api", "generic", {"token": "test-secret-value"})
        )
        yield vault


@pytest.mark.parametrize("pipe", ["stdout", "stderr"])
def test_run_output_limit_stops_process_and_cleans_home(vault, pipe):
    script = f"import sys; sys.{pipe}.write('x' * (2 * 1024 * 1024)); sys.{pipe}.flush(); import time; time.sleep(60)"
    with pytest.raises(runner.RunError, match="exceeds 1 MiB"):
        runner.run(vault, "api", [sys.executable, "-c", script], timeout=3)
    assert not list((vault.state_dir / "run").iterdir())


@pytest.mark.parametrize(
    "name", ["../../escape", "/absolute/path", ".", "name/with/slashes"]
)
def test_context_name_cannot_control_temporary_directory(vault, name):
    vault.put_context(Context(name, credentials=["api"]))
    result = runner.run(
        vault, name, [sys.executable, "-c", "import os; print(os.environ['HOME'])"]
    )
    path = Path(result.stdout.strip())
    assert path.parent == (vault.state_dir / "run").resolve()
    assert not path.exists()


def test_run_refuses_symlinked_work_directory(vault, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (vault.state_dir / "run").symlink_to(outside, target_is_directory=True)
    with pytest.raises(runner.RunError, match="symlink"):
        runner.run(vault, "api", [sys.executable, "-c", "pass"])
    assert not list(outside.iterdir())


def test_stdin_and_large_output_do_not_deadlock(vault):
    script = "import sys; sys.stdout.write('x'*100000); sys.stdout.flush(); data=sys.stdin.read(); print(len(data))"
    result = runner.run(
        vault, "api", [sys.executable, "-c", script], stdin="y" * 100000, timeout=3
    )
    assert result.exit_code == 0 and not result.timed_out
    assert result.stdout.endswith("100000\n")


def test_home_relative_auth_path_cannot_escape_or_leak(vault):
    cred = vault.get_credential("api")
    cred.materialize = [{"kind": "env", "map": {"CONFIG": "{HOME}/../../{token}"}}]
    vault.put_credential(cred)
    with pytest.raises(runner.RunError, match="unsafe path") as err:
        runner.run(vault, "api", [sys.executable, "-c", "pass"])
    assert cred.secret["token"] not in str(err.value)
    assert cred.secret["token"] not in json.dumps(vault.audit_tail(5))
    assert not list((vault.state_dir / "run").iterdir())


@pytest.mark.parametrize("name", ["", "\x00", "name\nforged-log", "\x1b[31m"])
def test_record_names_reject_control_characters(vault, name):
    with pytest.raises(BatonError, match="record name"):
        vault.put_context(Context(name, credentials=["api"]))
    cred = vault.get_credential("api")
    cred.name = name
    with pytest.raises(BatonError, match="record name"):
        vault.put_credential(cred)


@pytest.mark.parametrize(
    "secret", ["test-secret-value", "first-secret-line\nsecond-secret-line"]
)
def test_timeout_redacts_incomplete_secret_output(vault, secret):
    cred = vault.get_credential("api")
    cred.secret["token"] = secret
    vault.put_credential(cred)
    partial = secret[: len(secret) // 2]
    script = f"import sys,time; sys.stdout.write({partial!r}); sys.stdout.flush(); time.sleep(5)"
    result = runner.run(vault, "api", [sys.executable, "-c", script], timeout=0.2)
    assert result.timed_out and result.stdout == "«baton:redacted»"
    assert partial not in result.stdout
