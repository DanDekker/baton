import base64
import os

import pytest

from baton.cli import build_parser, main


def _key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BATON_MASTER_KEY", _key())
    monkeypatch.delenv("BATON_STATE_DIR", raising=False)
    return tmp_path / "state"


def test_parser_has_no_conflicting_options():
    # regression: `--json` was declared by both the shared parent and `http`
    parser = build_parser()
    for argv in (
        ["status"],
        ["cred", "list"],
        ["ctx", "list"],
        ["lease", "list"],
        ["http", "ctx", "https://example.com", "--body", "{}"],
    ):
        assert parser.parse_args(argv) is not None


def test_status_and_lists(env, capsys):
    assert main(["status", "--state-dir", str(env)]) == 0
    assert main(["cred", "list", "--state-dir", str(env)]) == 0
    assert main(["ctx", "list", "--state-dir", str(env)]) == 0
    out = capsys.readouterr().out
    assert "blake3" in out


def test_cred_add_ctx_and_run(env, capsys):
    token = "ghp_" + "Q" * 36
    assert (
        main(
            [
                "cred",
                "add",
                "gh",
                "--provider",
                "github",
                "--field",
                f"token={token}",
                "--state-dir",
                str(env),
            ]
        )
        == 0
    )
    assert main(["ctx", "add", "work", "--cred", "gh", "--state-dir", str(env)]) == 0

    code = main(
        ["run", "--state-dir", str(env), "work", "--", "sh", "-c", "echo $GH_TOKEN"]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert token not in out
    assert "«baton:redacted»" in out


def test_lease_new_roundtrip(env, capsys):
    main(
        [
            "cred", "add", "gh", "--provider", "github", "--field", "token=ghp_" + "w" * 36,
            "--state-dir", str(env),
        ]
    )
    main(["ctx", "add", "work", "--cred", "gh", "--state-dir", str(env)])
    capsys.readouterr()
    assert main(["lease", "new", "work", "--ttl", "60", "--state-dir", str(env)]) == 0
    token = capsys.readouterr().out.strip()
    assert token.startswith("btn_")


def test_audit_reports_intact_chain(env, capsys):
    main(["status", "--state-dir", str(env)])
    assert main(["audit", "--state-dir", str(env)]) == 0
    assert "intact" in capsys.readouterr().out
