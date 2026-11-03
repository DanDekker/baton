"""Adversarial refresh inputs, storage upgrades, and caller-visible failures."""

import asyncio
import base64
import json
import os
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from baton_auth import broker, refresh
from baton_auth.catalog import build_credential
from baton_auth.cli import main
from baton_auth.mcp_server import build
from baton_auth.models import RefreshError
from baton_auth.vault import Vault

KEY = b"k" * 32
SECRET = "fake-refresh-secret-123456"


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.setenv("BATON_MASTER_KEY", base64.urlsafe_b64encode(KEY).decode())
    with Vault(state_dir=tmp_path / "state", master_key=KEY) as vault:
        yield vault


def _credential(config):
    return build_credential(
        "api",
        "generic",
        {"token": "working-token", "refresh_token": SECRET},
        expires_at=time.time() - 1,
        refresh=config,
    )


def _oauth_response(monkeypatch, body, *, status=200, headers=None, stream=None):
    original = httpx.Client

    def handler(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(
            status,
            headers=headers,
            stream=stream or httpx.ByteStream(json.dumps(body).encode()),
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kw: original(transport=httpx.MockTransport(handler), **kw),
    )


def _oauth_config(**extra):
    return {"provider": "oauth2", "token_url": "http://127.0.0.1/token", **extra}


def _exec_config(script, **extra):
    return {"provider": "exec", "argv": [sys.executable, "-c", script], **extra}


def _unchanged_after_failure(vault):
    before = dict(vault.get_credential_row("api"))
    with pytest.raises(RefreshError) as err:
        vault.refresh_credential("api", force=True)
    assert dict(vault.get_credential_row("api")) == before
    assert not any(
        row["action"] == "credential.refresh" for row in vault.audit_tail(10)
    )
    return err


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "token",
        {},
        {"access_token": {}},
        {"access_token": ["token"]},
        {"access_token": True},
        {"access_token": 42},
        {"access_token": " "},
        {"access_token": "token\r\nInjected: value"},
        {"access_token": "new-token", "refresh_token": None},
        {"access_token": "new-token", "refresh_token": []},
        *(
            {"access_token": "new-token", "expires_in": x}
            for x in ("NaN", "Infinity", -1, True, {}, "bad")
        ),
        {"access_token": "new-token", "token_type": {"secret": SECRET}},
    ],
)
def test_bad_oauth_responses_preserve_credentials(vault, monkeypatch, body):
    _oauth_response(monkeypatch, body)
    vault.put_credential(_credential(_oauth_config()))
    err = _unchanged_after_failure(vault)
    assert SECRET not in str(err.value)


@pytest.mark.parametrize(
    "output",
    [
        "",
        " ",
        "null",
        "[]",
        '{"token":null}',
        '{"token":{}}',
        '{"token":42}',
        '{"token":"new","expires_in":"NaN"}',
    ],
)
def test_bad_exec_responses_preserve_credentials(vault, output):
    config = _exec_config(f"print({output!r})", format="json")
    vault.put_credential(_credential(config))
    _unchanged_after_failure(vault)


@pytest.mark.parametrize(
    "timeout", [0, -1, True, "NaN", "Infinity", "bad", 1e300, 10**1000]
)
def test_invalid_timeout_never_runs_command(vault, tmp_path, timeout):
    marker = tmp_path / "should-not-exist"
    config = _exec_config(
        f"from pathlib import Path; Path({str(marker)!r}).touch()", timeout=timeout
    )
    vault.put_credential(_credential(config))
    _unchanged_after_failure(vault)
    assert not marker.exists()


def test_oauth_error_body_does_not_reach_cli_or_mcp(vault, monkeypatch, capsys):
    echoed = "newly-minted-secret-not-yet-in-vault"
    _oauth_response(monkeypatch, {"error_description": SECRET + echoed}, status=400)
    vault.put_credential(_credential(_oauth_config()))
    assert (
        main(["cred", "refresh", "api", "--force", "--state-dir", str(vault.state_dir)])
        == 1
    )
    out = capsys.readouterr()
    text = out.out + out.err
    assert "HTTP 400" in text
    assert SECRET not in text and echoed not in text
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError) as err:
        asyncio.run(
            build(vault).call_tool(
                "baton_refresh", {"credential": "api", "force": True}
            )
        )
    rendered = "".join(traceback.format_exception(err.value))
    assert "HTTP 400" in rendered
    assert SECRET not in rendered and echoed not in rendered


def test_command_errors_do_not_echo_stderr_or_argv(vault):
    config = _exec_config(
        f"import sys; print({SECRET!r}, file=sys.stderr); print('unknown-new-secret', file=sys.stderr); sys.exit(7)"
    )
    vault.put_credential(_credential(config))
    err = _unchanged_after_failure(vault)
    rendered = "".join(traceback.format_exception(err.value))
    assert "exit code 7" in rendered
    assert SECRET not in rendered and "unknown-new-secret" not in rendered


@pytest.mark.parametrize("pipe", ["stdout", "stderr"])
def test_command_output_is_bounded(vault, pipe):
    vault.put_credential(
        _credential(
            _exec_config(f"import sys; sys.{pipe}.write('x' * (2 * 1024 * 1024))")
        )
    )
    assert "exceeds 1 MiB" in str(_unchanged_after_failure(vault).value)


@pytest.mark.skipif(
    os.name != "posix", reason="process group cleanup is POSIX-specific"
)
def test_timeout_kills_descendant_even_after_parent_exits(vault, tmp_path):
    marker = tmp_path / "descendant-survived"
    child = f"import time; from pathlib import Path; time.sleep(1); Path({str(marker)!r}).touch()"
    parent = f"import subprocess, sys; subprocess.Popen([sys.executable, '-c', {child!r}]); print('token')"
    vault.put_credential(_credential(_exec_config(parent, timeout=0.25)))
    started = time.monotonic()
    assert "timed out" in str(_unchanged_after_failure(vault).value)
    assert time.monotonic() - started < 2
    time.sleep(1.1)
    assert not marker.exists()


def test_oauth_response_size_limit_stops_reading(vault, monkeypatch):
    class Endless(httpx.SyncByteStream):
        chunks = 0
        closed = False

        def __iter__(self):
            for _ in range(1000):
                self.chunks += 1
                yield b"x" * 65536

        def close(self):
            self.closed = True

    stream = Endless()
    _oauth_response(monkeypatch, None, stream=stream)
    vault.put_credential(_credential(_oauth_config()))
    assert "exceeds 1 MiB" in str(_unchanged_after_failure(vault).value)
    assert stream.chunks == 17 and stream.closed


def test_compressed_oauth_response_is_rejected(vault, monkeypatch):
    _oauth_response(monkeypatch, None, headers={"Content-Encoding": "gzip"})
    vault.put_credential(_credential(_oauth_config()))
    assert "identity encoding" in str(_unchanged_after_failure(vault).value)


@pytest.mark.parametrize(
    "result",
    [
        None,
        refresh.RefreshResult({}),
        refresh.RefreshResult({"token": None}),
        refresh.RefreshResult({"token": "new"}, expires_at=float("nan")),
    ],
)
def test_invalid_custom_provider_result_preserves_credential(
    vault, monkeypatch, result
):
    monkeypatch.setitem(refresh._REGISTRY, "broken", lambda *_: result)
    vault.put_credential(_credential({"provider": "broken"}))
    _unchanged_after_failure(vault)


def test_unexpected_provider_exception_is_safe(vault, monkeypatch):
    def broken(*_):
        raise ValueError(SECRET + "new-unrecognized-secret")

    monkeypatch.setitem(refresh._REGISTRY, "broken", broken)
    vault.put_credential(_credential({"provider": "broken"}))
    rendered = "".join(
        traceback.format_exception(_unchanged_after_failure(vault).value)
    )
    assert SECRET not in rendered and "new-unrecognized-secret" not in rendered


@pytest.mark.parametrize(
    "url", ["http://8.8.8.8/token", "http://auth.example.com/token"]
)
def test_public_token_endpoint_requires_https_before_sending(vault, monkeypatch, url):
    monkeypatch.setattr(broker, "validate_target_url", lambda *a, **k: ["8.8.8.8"])
    requests = []
    monkeypatch.setattr(httpx, "Client", lambda **kw: requests.append(kw))
    vault.put_credential(_credential(_oauth_config(token_url=url)))
    assert "HTTPS" in str(_unchanged_after_failure(vault).value)
    assert not requests


def test_oauth_transport_does_not_trust_proxy_environment(vault, monkeypatch):
    original = httpx.Client
    options = []

    def client(**kwargs):
        options.append(kwargs)
        return original(
            transport=httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    stream=httpx.ByteStream(b'{"access_token":"replacement"}'),
                )
            ),
            **kwargs,
        )

    monkeypatch.setattr(httpx, "Client", client)
    vault.put_credential(_credential(_oauth_config()))
    cred, changed = vault.refresh_credential("api")
    assert changed and cred.expires_at is None
    assert vault.refresh_credential("api")[1] is False
    assert len(options) == 1 and options[0]["trust_env"] is False


def test_redirect_does_not_forward_refresh_token(vault, monkeypatch):
    _oauth_response(
        monkeypatch,
        {},
        status=307,
        headers={"Location": "https://elsewhere.example/token"},
    )
    vault.put_credential(_credential(_oauth_config()))
    assert "HTTP 307" in str(_unchanged_after_failure(vault).value)


def test_broken_http_stream_preserves_credentials(vault, monkeypatch):
    class Broken(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            yield b'{"access_token":"partial'
            raise httpx.RemoteProtocolError(SECRET)

        def close(self):
            self.closed = True

    stream = Broken()
    _oauth_response(monkeypatch, None, stream=stream)
    vault.put_credential(_credential(_oauth_config()))
    err = _unchanged_after_failure(vault)
    assert "request failed" in str(err.value)
    assert SECRET not in "".join(traceback.format_exception(err.value))
    assert stream.closed


def test_stalled_http_server_times_out(vault):
    release = threading.Event()

    class Stall(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            release.wait(5)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Stall)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        config = _oauth_config(
            token_url=f"http://127.0.0.1:{server.server_port}/token", timeout=0.1
        )
        vault.put_credential(_credential(config))
        started = time.monotonic()
        assert "request failed" in str(_unchanged_after_failure(vault).value)
        assert time.monotonic() - started < 2
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join()


def test_invalid_command_encoding_keeps_existing_token(vault):
    vault.put_credential(
        _credential(_exec_config("import sys; sys.stdout.buffer.write(b'\\xff')"))
    )
    assert "UTF-8" in str(_unchanged_after_failure(vault).value)


def test_empty_text_output_keeps_existing_token(vault):
    vault.put_credential(_credential(_exec_config("print('  ')")))
    assert "nonempty" in str(_unchanged_after_failure(vault).value)
