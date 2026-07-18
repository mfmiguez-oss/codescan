"""Vault secret loader — fake hvac client, no real Vault."""

from __future__ import annotations

import os

import pytest

from codescan.config import Config, VaultConfig
from codescan.vault import _authenticate, load_secrets_into_env


@pytest.fixture(autouse=True)
def _env_guard():
    # Isolate os.environ mutations (the loader writes env directly).
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


class FakeVault:
    """Minimal stand-in for an authenticated hvac.Client."""

    def __init__(self, secrets: dict[str, dict], version: int = 2):
        self._secrets = secrets
        self.token = None

        outer = self

        class _V2:
            def read_secret_version(self, path, mount_point):
                return {"data": {"data": outer._secrets[path]}}

        class _V1:
            def read_secret(self, path, mount_point):
                return {"data": outer._secrets[path]}

        self.secrets = type("KV", (), {"kv": type("_", (), {"v2": _V2(), "v1": _V1()})()})()


def test_injects_kv_v2_secrets_into_env():
    client = FakeVault({"codescan": {"SNYK_TOKEN": "s3cr3t", "FOUNDRY_API_KEY": "sk-x"}})
    cfg = VaultConfig(enabled=True, paths=["codescan"])
    n = load_secrets_into_env(cfg, client=client)
    assert n == 2
    assert os.environ["SNYK_TOKEN"] == "s3cr3t"
    assert os.environ["FOUNDRY_API_KEY"] == "sk-x"


def test_existing_env_wins_unless_override():
    os.environ["SNYK_TOKEN"] = "preset"
    client = FakeVault({"p": {"SNYK_TOKEN": "from-vault", "XRAY_TOKEN": "x"}})

    load_secrets_into_env(VaultConfig(enabled=True, paths=["p"]), client=client)
    assert os.environ["SNYK_TOKEN"] == "preset"       # not overridden
    assert os.environ["XRAY_TOKEN"] == "x"            # new key set

    load_secrets_into_env(VaultConfig(enabled=True, paths=["p"], override_env=True), client=client)
    assert os.environ["SNYK_TOKEN"] == "from-vault"   # now overridden


def test_kv_v1_path():
    client = FakeVault({"p": {"GITHUB_TOKEN": "ghp"}})
    load_secrets_into_env(VaultConfig(enabled=True, paths=["p"], kv_version=1), client=client)
    assert os.environ["GITHUB_TOKEN"] == "ghp"


def test_no_paths_is_noop():
    assert load_secrets_into_env(VaultConfig(enabled=True, paths=[]), client=FakeVault({})) == 0


def test_approle_requires_role_and_secret():
    with pytest.raises(RuntimeError, match="approle"):
        _authenticate(FakeVault({}), VaultConfig(auth="approle"))


def test_unknown_auth_method():
    with pytest.raises(RuntimeError, match="unknown vault.auth"):
        _authenticate(FakeVault({}), VaultConfig(auth="ldap"))


def test_config_load_pulls_vault_before_interpolation(tmp_path, monkeypatch):
    # Vault fills SNYK_TOKEN, which the config then interpolates.
    import codescan.vault as vault

    def fake_load(cfg, **kw):
        assert cfg.enabled and cfg.paths == ["codescan"]
        os.environ["SNYK_TOKEN"] = "injected-by-vault"
        return 1

    monkeypatch.setattr(vault, "load_secrets_into_env", fake_load)

    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text(
        "vault:\n  enabled: true\n  paths: [codescan]\n"
        "snyk:\n  token: ${SNYK_TOKEN}\n",
        encoding="utf-8",
    )
    cfg = Config.load(cfg_path)
    assert cfg.snyk.token == "injected-by-vault"


def test_config_load_skips_vault_when_disabled(tmp_path, monkeypatch):
    import codescan.vault as vault
    monkeypatch.setattr(vault, "load_secrets_into_env",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not run")))
    cfg_path = tmp_path / "c.yaml"
    cfg_path.write_text("vault:\n  enabled: false\n", encoding="utf-8")
    Config.load(cfg_path)   # must not call the loader
