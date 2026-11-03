import time
from concurrent.futures import ThreadPoolExecutor

import keyring
import pytest

from baton_auth.catalog import build_credential
from baton_auth.models import VaultLocked
from baton_auth.vault import Vault, _hardened_write


@pytest.mark.parametrize("backend", ["keyring", "keyfile", "passphrase"])
def test_concurrent_first_start_uses_one_master_key(tmp_path, monkeypatch, backend):
    monkeypatch.delenv("BATON_MASTER_KEY", raising=False)
    monkeypatch.delenv("BATON_PASSPHRASE", raising=False)
    stored = {}

    def get(service, account):
        time.sleep(0.01)
        if backend == "keyfile":
            raise RuntimeError("no test keyring")
        return stored.get((service, account))

    monkeypatch.setattr(keyring, "get_password", get)
    monkeypatch.setattr(
        keyring,
        "set_password",
        lambda service, account, value: stored.__setitem__((service, account), value),
    )
    options = {"passphrase": "test-only-passphrase"} if backend == "passphrase" else {}
    path = tmp_path / "new-vault"

    def create(index):
        with Vault(state_dir=path, **options) as vault:
            vault.put_credential(
                build_credential(
                    f"api-{index}", "generic", {"token": f"fake-token-{index}"}
                )
            )
            return vault._get_meta("key_check")

    with ThreadPoolExecutor(max_workers=8) as pool:
        checks = list(pool.map(create, range(16)))
    assert len(set(checks)) == 1
    with Vault(state_dir=path, **options) as vault:
        for index in range(16):
            assert (
                vault.get_credential(f"api-{index}").secret["token"]
                == f"fake-token-{index}"
            )
        assert vault.verify_audit()[0]


def test_keyring_recovery_does_not_replace_existing_keyfile(tmp_path, monkeypatch):
    monkeypatch.delenv("BATON_MASTER_KEY", raising=False)
    monkeypatch.delenv("BATON_PASSPHRASE", raising=False)

    def unavailable(*_):
        raise RuntimeError("no test keyring")

    monkeypatch.setattr(keyring, "get_password", unavailable)
    monkeypatch.setattr(
        keyring, "set_password", lambda *_: pytest.fail("must keep existing key")
    )
    with Vault(state_dir=tmp_path / "state") as vault:
        vault.put_credential(
            build_credential("api", "generic", {"token": "preserved-token"})
        )
    monkeypatch.setattr(keyring, "get_password", lambda *_: None)
    with Vault(state_dir=tmp_path / "state") as vault:
        assert vault.mode == "keyfile"
        assert vault.get_credential("api").secret["token"] == "preserved-token"


def test_wrong_key_cannot_open_or_overwrite_existing_vault(tmp_path):
    path = tmp_path / "state"
    with Vault(state_dir=path, master_key=b"k" * 32) as vault:
        vault.put_credential(
            build_credential("api", "generic", {"token": "preserved-token"})
        )
    with pytest.raises(VaultLocked, match="does not match"):
        Vault(state_dir=path, master_key=b"x" * 32)
    with Vault(state_dir=path, master_key=b"k" * 32) as vault:
        assert vault.get_credential("api").secret["token"] == "preserved-token"


def test_atomic_key_write_does_not_follow_predictable_temp_symlink(tmp_path):
    victim = tmp_path / "unrelated"
    victim.write_text("keep me")
    keyfile = tmp_path / "master.key"
    keyfile.with_suffix(".key.tmp").symlink_to(victim)
    _hardened_write(keyfile, b"test-key")
    assert victim.read_text() == "keep me"
    assert keyfile.read_bytes() == b"test-key"
    assert keyfile.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("unavailable", [False, True])
def test_missing_keyring_entry_does_not_create_a_replacement_key(
    tmp_path, monkeypatch, unavailable
):
    monkeypatch.delenv("BATON_MASTER_KEY", raising=False)
    monkeypatch.delenv("BATON_PASSPHRASE", raising=False)
    stored = {}
    monkeypatch.setattr(keyring, "get_password", lambda *_: stored.get("key"))
    monkeypatch.setattr(
        keyring, "set_password", lambda *args: stored.update(key=args[-1])
    )
    path = tmp_path / "state"
    with Vault(state_dir=path) as vault:
        vault.put_credential(
            build_credential("api", "generic", {"token": "preserved-token"})
        )
    original = stored.pop("key")

    def get(*_):
        if unavailable:
            raise RuntimeError("keyring locked")
        return None

    monkeypatch.setattr(keyring, "get_password", get)
    monkeypatch.setattr(
        keyring, "set_password", lambda *_: pytest.fail("must not mint a replacement")
    )
    with pytest.raises(VaultLocked, match="key is unavailable"):
        Vault(state_dir=path)
    assert not (path / "master.key").exists()
    monkeypatch.setattr(keyring, "get_password", lambda *_: original)
    with Vault(state_dir=path) as vault:
        assert vault.get_credential("api").secret["token"] == "preserved-token"


def test_corrupt_database_returns_a_controlled_error(tmp_path):
    path = tmp_path / "baton.db"
    original = b"not a SQLite database" * 50
    path.write_bytes(original)
    with pytest.raises(VaultLocked, match="cannot open vault database"):
        Vault(state_dir=tmp_path, master_key=b"k" * 32)
    assert path.read_bytes() == original
