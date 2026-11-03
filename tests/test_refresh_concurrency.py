"""Refresh rotation and expiry under concurrent callers."""

import base64
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from baton_auth import refresh
from baton_auth.catalog import build_credential
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


def test_concurrent_auto_refresh_rotates_once(vault, monkeypatch):
    calls = []

    def provider(cred, config):
        calls.append(cred.secret["refresh_token"])
        time.sleep(0.05)
        return refresh.RefreshResult(
            {"token": "rotated-token", "refresh_token": "rotated-refresh"},
            expires_at=time.time() + 600,
        )

    monkeypatch.setitem(refresh._REGISTRY, "concurrent", provider)
    vault.put_credential(_credential({"provider": "concurrent"}))
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: vault.refresh_credential("api"), range(48)))
    assert calls == [SECRET]
    assert sum(changed for _, changed in results) == 1
    assert all(cred.secret["token"] == "rotated-token" for cred, _ in results)


def test_refresh_is_serialized_across_independent_connections(vault, monkeypatch):
    calls = []

    def provider(cred, config):
        calls.append(cred.secret["refresh_token"])
        time.sleep(0.1)
        return refresh.RefreshResult(
            {"token": "new-token", "refresh_token": "new-refresh"},
            expires_at=time.time() + 600,
        )

    monkeypatch.setitem(refresh._REGISTRY, "rotation", provider)
    vault.put_credential(_credential({"provider": "rotation"}))
    connections = [Vault(state_dir=vault.state_dir, master_key=KEY) for _ in range(8)]
    ready = threading.Barrier(8)

    def rotate(connection):
        ready.wait(timeout=3)
        return connection.refresh_credential("api")

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(rotate, connections))
    finally:
        for connection in connections:
            connection.close()
    assert calls == [SECRET]
    assert sum(changed for _, changed in results) == 1
    assert all(cred.secret["refresh_token"] == "new-refresh" for cred, _ in results)


def test_refresh_without_lifetime_clears_stale_expiry(vault, monkeypatch):
    calls = []

    def provider(*_):
        calls.append(1)
        return refresh.RefreshResult({"token": "replacement-token"})

    monkeypatch.setitem(refresh._REGISTRY, "no-expiry", provider)
    vault.put_credential(_credential({"provider": "no-expiry"}))
    credential, changed = vault.refresh_credential("api")
    assert changed and credential.expires_at is None
    assert vault.refresh_credential("api")[1] is False
    assert calls == [1]
