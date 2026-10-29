from urllib.parse import quote

import httpx
import pytest

from baton import broker, cli
from baton.catalog import build_credential
from baton.models import Context
from baton.vault import Vault

KEY = b"k" * 32


@pytest.fixture()
def vault(tmp_path):
    v = Vault(master_key=KEY, state_dir=tmp_path / "state")
    cred = build_credential("test-api", "generic", {"token": "secret_val_12345"})
    v.put_credential(cred)
    v.put_context(Context(name="default", credentials=["test-api"]))
    yield v
    v.close()


def test_ssrf_rejects_non_http_schemes():
    for bad in ("file:///etc/passwd", "ftp://example.com/file", "gopher://example.com"):
        with pytest.raises(broker.BrokerError, match="unsupported URL scheme"):
            broker.validate_target_url(bad)


def test_ssrf_blocks_cloud_metadata():
    for meta in (
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.local/meta",
        "http://[fd00:ec2::254]/latest/meta-data/",
    ):
        with pytest.raises(broker.BrokerError, match="SSRF protection.*metadata"):
            broker.validate_target_url(meta)


def test_ssrf_blocks_private_subnets_by_default():
    private_targets = (
        "http://10.0.0.1:8080/admin",
        "http://172.16.1.5:9000/internal",
        "http://192.168.1.100/",
    )
    for target in private_targets:
        with pytest.raises(broker.BrokerError, match="SSRF protection.*private network"):
            broker.validate_target_url(target, allow_private=False)

    # Allowed when explicitly enabled
    for target in private_targets:
        broker.validate_target_url(target, allow_private=True)


def test_ssrf_loopback_handling():
    # Loopback allowed by default
    broker.validate_target_url("http://127.0.0.1:8000/api", allow_loopback=True)
    broker.validate_target_url("http://localhost:8000/api", allow_loopback=True)

    # Blocked when disallowed
    with pytest.raises(broker.BrokerError, match="SSRF protection.*loopback"):
        broker.validate_target_url("http://127.0.0.1:8000/api", allow_loopback=False)

    with pytest.raises(broker.BrokerError, match="SSRF protection.*loopback"):
        broker.validate_target_url("http://localhost:8000/api", allow_loopback=False)


def test_broker_request_blocks_ssrf(vault):
    with pytest.raises(broker.BrokerError, match="SSRF protection"):
        broker.request(vault, "default", "GET", "http://169.254.169.254/latest/meta-data/")

    with pytest.raises(broker.BrokerError, match="SSRF protection"):
        broker.request(
            vault,
            "default",
            "GET",
            "http://127.0.0.1:8080/status",
            allow_loopback=False,
        )


def test_cli_http_parser_flags():
    parser = cli.build_parser()
    args = parser.parse_args(["http", "default", "http://10.0.0.1/api", "--allow-private"])
    assert args.allow_private is True
    assert args.disallow_loopback is False

    args2 = parser.parse_args(
        ["http", "default", "http://localhost/api", "--disallow-loopback"]
    )
    assert args2.allow_private is False
    assert args2.disallow_loopback is True


def _stub_client(monkeypatch, response):
    calls = []

    class Client:
        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def request(self, method, url, **kwargs):
            calls.append(("request", method, url, kwargs))
            return response

    monkeypatch.setattr(broker.httpx, "Client", Client)
    return calls


def test_broker_only_loads_selected_credential(vault, monkeypatch):
    vault.put_credential(build_credential("other", "generic", {"token": "other_secret_12345"}))
    vault.put_context(Context(name="both", credentials=["test-api", "other"]))
    calls = _stub_client(monkeypatch, httpx.Response(200, text="ok"))
    loaded = []
    original = vault.get_credential

    def get_credential(name, **kwargs):
        loaded.append((name, kwargs))
        return original(name, **kwargs)

    monkeypatch.setattr(vault, "get_credential", get_credential)
    response = broker.request(vault, "both", "GET", "http://127.0.0.1/test", service="other")
    assert response.status == 200
    assert [name for name, _ in loaded] == ["other", "other"]
    assert loaded[0][1] == {"auto_refresh": True}
    assert len([call for call in calls if call[0] == "request"]) == 1


def test_broker_returns_redirect_without_following_it(vault, monkeypatch):
    calls = _stub_client(
        monkeypatch,
        httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"}),
    )
    response = broker.request(vault, "default", "GET", "http://127.0.0.1/redirect")
    assert response.status == 302
    assert response.headers["location"] == "http://169.254.169.254/latest/meta-data/"
    assert calls[0] == ("init", {"timeout": 30.0, "follow_redirects": False})
    assert len([call for call in calls if call[0] == "request"]) == 1


def test_broker_redacts_query_auth_from_returned_url(vault, monkeypatch):
    cred = vault.get_credential("test-api")
    cred.secret["token"] = "secret+/value=12345"
    cred.auth = {"scheme": "query", "field": "token", "param": "key"}
    vault.put_credential(cred)
    encoded = quote(cred.secret["token"], safe="")
    calls = _stub_client(
        monkeypatch,
        httpx.Response(302, headers={"location": f"http://127.0.0.1/next?key={encoded}"}),
    )

    response = broker.request(vault, "default", "GET", "http://127.0.0.1/probe")
    assert encoded in calls[1][2]
    assert response.url == "http://127.0.0.1/probe"
    assert encoded not in response.headers["location"]
    assert "«baton:redacted»" in response.headers["location"]
    assert response.redactions >= 1
