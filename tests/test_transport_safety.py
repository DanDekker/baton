import json
from urllib.parse import quote_plus

import httpx
import pytest

from baton_auth import broker
from baton_auth.catalog import build_credential
from baton_auth.models import BatonError
from baton_auth.remote import RemoteClient
from baton_auth.vault import Vault

SECRET = "secret with spaces+/12345"


@pytest.fixture
def vault(tmp_path):
    with Vault(state_dir=tmp_path / "state", master_key=b"k" * 32) as vault:
        vault.put_credential(build_credential("api", "generic", {"token": SECRET}))
        yield vault


def _client(monkeypatch, handler):
    original = httpx.Client
    options = []

    def factory(**kwargs):
        options.append(kwargs)
        return original(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    return options


def test_local_http_pins_dns_and_cannot_override_origin(vault, monkeypatch):
    dns_calls = []
    requests = []

    def dns(*_, **__):
        dns_calls.append(1)
        return ["93.184.216.34"] if len(dns_calls) == 1 else ["169.254.169.254"]

    def handle(request):
        requests.append(request)
        assert request.url.host == "93.184.216.34"
        assert request.headers["Host"] == "example.com"
        assert request.extensions["sni_hostname"] == "example.com"
        assert request.headers.get_list("Authorization") == [f"Bearer {SECRET}"]
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    monkeypatch.setattr(broker, "validate_target_url", dns)
    options = _client(monkeypatch, handle)
    result = broker.request(
        vault,
        "api",
        "GET",
        "https://example.com/",
        headers={
            "HOST": "evil.example",
            "authorization": "override",
            "AUTHORIZATION": "second override",
        },
    )
    assert result.body == "ok" and len(requests) == len(dns_calls) == 1
    assert options[0]["trust_env"] is False


def test_unreachable_first_address_falls_back_without_resolving_again(
    vault, monkeypatch
):
    monkeypatch.setattr(
        broker,
        "validate_target_url",
        lambda *a, **kw: ["2001:4860:4860::8888", "93.184.216.34"],
    )
    calls = []

    def handle(request):
        calls.append(request.url.host)
        if len(calls) == 1:
            raise httpx.ConnectError("unreachable")
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    _client(monkeypatch, handle)
    assert (
        broker.request(
            vault, "api", "POST", "https://example.com/", body=b"request"
        ).body
        == "ok"
    )
    assert calls == ["2001:4860:4860::8888", "93.184.216.34"]


def test_read_failure_does_not_retry_a_post(vault, monkeypatch):
    monkeypatch.setattr(
        broker,
        "validate_target_url",
        lambda *a, **kw: ["93.184.216.34", "93.184.216.35"],
    )
    calls = []

    def handle(request):
        calls.append(request)
        raise httpx.ReadTimeout(SECRET)

    _client(monkeypatch, handle)
    with pytest.raises(broker.BrokerError, match="upstream request failed") as err:
        broker.request(vault, "api", "POST", "https://example.com/")
    assert len(calls) == 1 and SECRET not in str(err.value)


def test_streaming_limit_closes_response_without_leaking_partial_secret(
    vault, monkeypatch
):
    class Endless(httpx.SyncByteStream):
        chunks = 0
        closed = False

        def __iter__(self):
            yield b"a" * (broker.MAX_BODY - 5) + SECRET.encode()
            while True:
                self.chunks += 1
                yield b"x" * 65536

        def close(self):
            self.closed = True

    stream = Endless()
    _client(monkeypatch, lambda _: httpx.Response(200, stream=stream))
    result = broker.request(vault, "api", "GET", "http://127.0.0.1/")
    assert result.truncated and stream.closed and stream.chunks == 0
    assert "secre" not in result.body and len(result.body) < broker.MAX_BODY


def test_query_auth_overrides_existing_value_and_redacts_form_encoding(
    vault, monkeypatch
):
    cred = vault.get_credential("api")
    cred.auth = {"scheme": "query", "param": "key&other", "field": "token"}
    vault.put_credential(cred)

    def handle(request):
        assert request.url.params.get_list("key&other") == [SECRET]
        return httpx.Response(200, stream=httpx.ByteStream(str(request.url).encode()))

    _client(monkeypatch, handle)
    result = broker.request(
        vault, "api", "GET", "http://127.0.0.1/?key%26other=old#fragment"
    )
    assert SECRET not in result.body and quote_plus(SECRET, safe="") not in result.body
    assert "«baton:redacted»" in result.body


def test_http_audit_redacts_secrets_in_path(vault, monkeypatch):
    _client(monkeypatch, lambda _: httpx.Response(200, stream=httpx.ByteStream(b"ok")))
    broker.request(
        vault, "api", "GET", "http://127.0.0.1/" + quote_plus(SECRET, safe="")
    )
    assert SECRET not in json.dumps(vault.audit_tail(5))
    assert quote_plus(SECRET, safe="") not in json.dumps(vault.audit_tail(5))


@pytest.mark.parametrize(
    "scheme,header",
    [("bearer", "Authorization"), ("basic", "Authorization"), ("header", "X-Api-Key")],
)
def test_auth_headers_replace_conflicting_case_variants(vault, scheme, header):
    cred = vault.get_credential("api")
    cred.auth = {"scheme": scheme, "header": header}
    cred.secret.update(username="user", password=SECRET)
    headers, _ = broker.attach_auth(
        cred,
        "GET",
        "http://127.0.0.1/",
        {header.lower(): "wrong", header.upper(): "wrong"},
        b"",
    )
    assert len([key for key in headers if key.lower() == header.lower()]) == 1
    assert "wrong" not in headers.values()


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf"), 10**1000])
def test_bad_http_timeout_fails_before_network(vault, monkeypatch, timeout):
    monkeypatch.setattr(
        broker, "validate_target_url", lambda *a, **k: pytest.fail("network reached")
    )
    with pytest.raises(broker.BrokerError, match="timeout"):
        broker.request(vault, "api", "GET", "http://127.0.0.1/", timeout=timeout)


def test_userinfo_cannot_override_configured_auth():
    with pytest.raises(broker.BrokerError, match="userinfo"):
        broker.validate_target_url("https://attacker:password@example.com/")


@pytest.mark.parametrize(
    "payload,status",
    [(None, 200), ([], 500), ({"result": []}, 200), ({"error": {}}, 400)],
)
def test_malformed_remote_response_is_a_controlled_error(payload, status):
    client = RemoteClient.__new__(RemoteClient)
    client.config = {"endpoint": "https://broker.example"}
    client._client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                status,
                stream=httpx.ByteStream(json.dumps(payload).encode()),
            )
        )
    )
    with client, pytest.raises(BatonError, match="invalid response"):
        client.call("identity")


def test_remote_response_rejects_compression_before_reading():
    class Bomb(httpx.SyncByteStream):
        def __iter__(self):
            pytest.fail("compressed response must not be read")
            yield b""

    client = RemoteClient.__new__(RemoteClient)
    client.config = {"endpoint": "https://broker.example"}
    client._client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                headers={"Content-Encoding": "gzip"},
                stream=Bomb(),
            )
        )
    )
    with client, pytest.raises(BatonError, match="identity content encoding"):
        client.call("identity")
