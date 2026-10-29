import asyncio
import json
from pathlib import Path
import ssl
import threading

import httpx
import pytest

from baton_auth import broker, cli, delegation, identity, integration, remote_mcp
from baton_auth.catalog import build_credential
from baton_auth.models import BatonError, Context
from baton_auth.remote import RemoteClient, RemoteServer
from baton_auth.vault import Vault

SECRET = "ghp_" + "Z" * 36


@pytest.fixture
def network(tmp_path):
    with Vault(tmp_path / "broker", master_key=b"k" * 32) as vault:
        vault.put_credential(build_credential("gh", "github", {"token": SECRET}))
        vault.put_context(Context("work", credentials=["gh"]))
        server = RemoteServer(("127.0.0.1", 0), vault, identity.server_context(vault, "https://127.0.0.1"))
        endpoint = f"https://127.0.0.1:{server.server_port}"
        clients, states, bundles = {}, {}, {}
        for name in ("alice", "bob"):
            states[name] = tmp_path / name
            request = identity.init_agent(name, states[name])
            bundles[name] = identity.trust_agent(vault, request, endpoint)
            identity.connect(bundles[name], states[name])
            clients[name] = RemoteClient(states[name])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield vault, clients, states, bundles, endpoint
        finally:
            for client in clients.values():
                client.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def grant(network, **kwargs):
    vault = network[0]
    return vault.issue_lease("work", recipient="alice", delegatable=True, max_uses=5, **kwargs)


def test_real_tls_pairing_and_recipient_bound_handoff(network):
    vault, clients, states, bundles, _ = network
    root = grant(network)
    alice, bob = clients["alice"], clients["bob"]
    assert alice.call("identity")["id"] == bundles["alice"]["id"]
    assert bob.call("inbox") == {"leases": []}
    assert alice.call("inbox")["leases"][0]["id"] == root.id
    with pytest.raises(BatonError, match="not bound"):
        bob.call("accept", lease=root.id)
    with pytest.raises(BatonError, match="accepted"):
        alice.call("delegate", lease=root.id, recipient="bob")
    alice.call("accept", lease=root.id)
    child = alice.call("delegate", lease=root.id, recipient="bob", ttl=30, max_uses=2,
                       task={"summary": "Review PR 42", "artifacts": ["https://example.org/pr/42"]})
    assert child["recipient"] == bundles["bob"]["id"]
    assert "token" not in child
    assert bob.call("inbox")["leases"][0]["task"]["summary"] == "Review PR 42"
    bob.call("accept", lease=child["id"])
    with pytest.raises(BatonError, match="not bound"):
        alice.call("accept", lease=child["id"])
    alice.call("revoke", lease=root.id, child_id=child["id"])
    assert bob.call("inbox") == {"leases": []}
    assert vault.verify_audit()[0]
    assert not (states["alice"] / "baton.db").exists()
    assert not (states["bob"] / "baton.db").exists()
    assert "PRIVATE KEY" not in json.dumps(bundles)
    assert (states["alice"] / "identity.key").stat().st_mode & 0o777 == 0o600


def test_missing_client_cert_and_wrong_broker_ca_are_rejected(network, tmp_path):
    _, _, states, _, endpoint = network
    trusted = ssl.create_default_context(cafile=str(states["alice"] / "connections/default/ca.pem"))
    with httpx.Client(verify=trusted, trust_env=False) as unauthenticated:
        with pytest.raises(httpx.HTTPError):
            unauthenticated.post(endpoint + "/v1", json={"operation": "inbox", "arguments": {}})
    with Vault(tmp_path / "other-broker", master_key=b"o" * 32) as other:
        wrong_request = identity.init_agent("outsider", tmp_path / "outsider")
        wrong_bundle = identity.trust_agent(other, wrong_request, endpoint)
        identity.connect(wrong_bundle, tmp_path / "outsider")
    with RemoteClient(tmp_path / "outsider") as outsider:
        with pytest.raises(BatonError, match="cannot connect"):
            outsider.call("identity")


def test_pairing_bundle_cannot_replace_another_identity(network):
    _, _, states, bundles, _ = network
    before = (states["bob"] / "identity.key").read_bytes()
    with pytest.raises(BatonError, match="different local identity"):
        identity.connect(bundles["alice"], states["bob"])
    assert (states["bob"] / "identity.key").read_bytes() == before


def test_revoking_paired_identity_blocks_existing_connection_and_descendants(network):
    vault, clients, _, _, _ = network
    root = grant(network)
    clients["alice"].call("accept", lease=root.id)
    child = clients["alice"].call("delegate", lease=root.id, recipient="bob")
    clients["bob"].call("accept", lease=child["id"])
    identity.revoke_agent(vault, "alice")
    with pytest.raises(BatonError, match="revoked"):
        clients["alice"].call("identity")
    assert clients["bob"].call("inbox") == {"leases": []}
    with pytest.raises(BatonError, match="revoked"):
        clients["bob"].call("accept", lease=child["id"])


def test_remote_api_has_no_admin_shell_or_context_bypass(network):
    vault, clients, _, _, _ = network
    client = clients["alice"]
    for op in ("run", "grant", "credentials", "contexts", "setup"):
        with pytest.raises(BatonError, match="unsupported"):
            client.call(op)
    with pytest.raises(BatonError, match="unavailable"):
        client.call("accept", lease="work")
    local = vault.issue_lease("work")
    with pytest.raises(BatonError, match="not bound"):
        client.call("accept", lease=local.token)
    with pytest.raises(BatonError, match="unsupported"):
        client.call("inbox", recipient="bob")


def test_remote_http_pins_dns_preserves_tls_origin_and_redacts(network, monkeypatch):
    vault, clients, _, bundles, _ = network
    root = grant(network)
    client = clients["alice"]
    client.call("accept", lease=root.id)
    real_client = httpx.Client
    calls = []
    def upstream(request):
        calls.append(request)
        assert request.url.host == "93.184.216.34"
        assert request.headers["Host"] == "api.github.com"
        assert request.extensions["sni_hostname"] == "api.github.com"
        assert request.headers["Authorization"] == f"Bearer {SECRET}"
        return httpx.Response(200, stream=httpx.ByteStream(f"authorized {SECRET}".encode()))
    def factory(**kwargs):
        assert kwargs["trust_env"] is False
        assert kwargs["follow_redirects"] is False
        return real_client(transport=httpx.MockTransport(upstream), **kwargs)
    def dns(url, **kwargs):
        assert kwargs == {"allow_private": False, "allow_loopback": False}
        return ["93.184.216.34"]
    monkeypatch.setattr(broker, "validate_target_url", dns)
    monkeypatch.setattr(broker.httpx, "Client", factory)
    response = client.call("http", lease=root.id, url="https://api.github.com/user", service="github")
    assert response["status"] == 200
    assert SECRET not in json.dumps(response)
    assert "redacted" in response["body"]
    assert len(calls) == 1
    assert delegation.resolve(vault, root.id, bundles["alice"]["id"], consume=False).uses == 1


def test_remote_http_permissions_and_private_networks_fail_before_use(network):
    vault, clients, _, _, _ = network
    root = grant(network, path_prefixes=["/repos/acme"])
    client = clients["alice"]
    client.call("accept", lease=root.id)
    for extra in ({"method": "DELETE"}, {"url": "https://evil.example/repos/acme"},
                  {"url": "http://api.github.com/repos/acme"}, {"url": "https://api.github.com/user"}):
        options = {"lease": root.id, "url": "https://api.github.com/repos/acme", **extra}
        with pytest.raises(BatonError):
            client.call("http", **options)
    local = build_credential("local", "generic", {"token": "local_secret_value"}, allowed_hosts=["127.0.0.1"])
    vault.put_credential(local)
    scoped = vault.issue_lease("local", recipient="alice")
    client.call("accept", lease=scoped.id)
    with pytest.raises(BatonError, match="loopback"):
        client.call("http", lease=scoped.id, url="https://127.0.0.1/")
    assert vault._conn.execute("SELECT uses FROM leases WHERE id=?", (root.id,)).fetchone()[0] == 0


def test_frozen_credentials_cannot_expand_with_context_edits(network, monkeypatch):
    vault, clients, _, _, _ = network
    root = grant(network)
    client = clients["alice"]
    client.call("accept", lease=root.id)
    vault.put_credential(build_credential("extra", "openai", {"token": "sk-" + "X" * 40}))
    vault.put_context(Context("work", credentials=["gh", "extra"]))
    with pytest.raises(BatonError):
        client.call("http", lease=root.id, url="https://api.openai.com/v1/models", service="extra")
    vault.delete_credential("gh")
    vault.put_credential(build_credential("gh", "github", {"token": "ghp_" + "Q" * 36}))
    with pytest.raises(BatonError, match="removed or replaced"):
        client.call("http", lease=root.id, url="https://api.github.com/user")


def test_remote_mcp_is_restricted_and_setup_keeps_identity_local(network, tmp_path, capsys):
    _, clients, states, _, _ = network
    server = remote_mcp.build(clients["alice"])
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert names == {"baton_identity", "baton_inbox", "baton_accept", "baton_http", "baton_delegate", "baton_revoke"}
    output = tmp_path / "mcp.json"
    assert cli.main(["setup", "--remote", "default", "--state-dir", str(states["alice"]), "--output", str(output)]) == 0
    entry = json.loads(output.read_text())["mcpServers"]["baton"]
    assert entry["args"] == ["-m", "baton_auth.remote_mcp", "--connection", "default"]
    assert "PRIVATE KEY" not in output.read_text()
    assert "BATON_MASTER_KEY" not in entry["env"]
    for name in ("codex", "claude-code"):
        assert "baton_auth.remote_mcp" in integration.client_command(name, str(states["alice"]), "default")


def test_remote_response_limits_and_header_overrides(network, monkeypatch):
    _, clients, _, _, _ = network
    root = grant(network)
    client = clients["alice"]
    client.call("accept", lease=root.id)
    monkeypatch.setattr(broker, "validate_target_url", lambda *_a, **_kw: ["93.184.216.34"])
    for header in ("Host", "Authorization", "X-Original-URL", "X-Forwarded-Host", "Connection"):
        with pytest.raises(BatonError, match="header is not permitted"):
            client.call("http", lease=root.id, url="https://api.github.com/user", headers={header: "override"})
    real_client = httpx.Client
    def upstream(request):
        # The known secret straddles the body limit. No partial tail may escape.
        payload = b"a" * (broker.MAX_BODY - 10) + SECRET.encode() + b"b" * 100000
        return httpx.Response(200, stream=httpx.ByteStream(payload))
    monkeypatch.setattr(broker.httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(upstream), **kwargs,
    ))
    result = client.call("http", lease=root.id, url="https://api.github.com/user")
    assert result["truncated"]
    assert len(result["body"]) <= broker.MAX_BODY
    assert "ghp_" not in result["body"]


def test_cli_pairing_does_not_create_a_client_vault(tmp_path, monkeypatch, capsys):
    import base64
    monkeypatch.setenv("BATON_MASTER_KEY", base64.urlsafe_b64encode(b"k" * 32).decode())
    agent_dir, broker_dir = tmp_path / "client", tmp_path / "server"
    request, bundle = tmp_path / "request.json", tmp_path / "connection.json"
    assert cli.main(["agent", "init", "cli-agent", "--state-dir", str(agent_dir), "--output", str(request)]) == 0
    assert cli.main(["agent", "trust", str(request), "--state-dir", str(broker_dir),
                     "--url", "https://broker.example:8765", "--output", str(bundle)]) == 0
    assert cli.main(["connect", str(bundle), "--state-dir", str(agent_dir)]) == 0
    assert not (agent_dir / "baton.db").exists()
    assert "PRIVATE KEY" not in request.read_text() + bundle.read_text()
    assert cli.main(["agent", "init", "different-agent", "--state-dir", str(agent_dir)]) == 1
