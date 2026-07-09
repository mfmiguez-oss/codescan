"""Optional HashiCorp Vault secret source.

codescan resolves every secret through the environment (`${ENV}` interpolation in
`config.py`, and the AI SDKs read their keys from env). This module keeps that
single seam: when `vault.enabled` is set, it fetches KV secrets from Vault and
**injects them into `os.environ` before config interpolation runs**, so the rest
of the config (`snyk.token: ${SNYK_TOKEN}`, `servicenow.password:
${SERVICENOW_PASSWORD}`, `ANTHROPIC_API_KEY`, …) resolves from Vault with no other
change. Each secret's keys become environment variable names.

By default an already-set environment variable wins (so an operator can still
override a single value out-of-band); set `override_env` to let Vault win.

`hvac` is an optional dependency (`pip install 'codescan[vault]'`), imported
lazily so importing this module never requires it.
"""

from __future__ import annotations

import os

from .config import VaultConfig


def load_secrets_into_env(cfg: VaultConfig, *, client: object | None = None) -> int:
    """Fetch `cfg.paths` from Vault and set them as env vars. Returns the count set.

    `client` is injectable for testing; when omitted, an authenticated `hvac`
    client is built from `cfg`. Raises `RuntimeError` on missing dependency, auth
    failure, or an unreadable path — a misconfigured secret source should fail
    loudly rather than silently leave credentials unset.
    """
    if not cfg.paths:
        return 0
    vault = client if client is not None else _build_client(cfg)

    loaded = 0
    for path in cfg.paths:
        data = _read_kv(vault, cfg, path)
        if not isinstance(data, dict):
            raise RuntimeError(f"Vault path '{path}' did not return a key/value map")
        for key, value in data.items():
            if value is None:
                continue
            if not cfg.override_env and key in os.environ:
                continue
            os.environ[str(key)] = str(value)
            loaded += 1
    return loaded


def _build_client(cfg: VaultConfig):
    try:
        import hvac
    except ImportError as exc:  # pragma: no cover - exercised via message in tests
        raise RuntimeError(
            "vault.enabled is set but the 'hvac' package isn't installed. "
            "Install it with: pip install 'codescan[vault]'."
        ) from exc

    client = hvac.Client(
        url=cfg.address or None,          # None -> hvac uses VAULT_ADDR
        namespace=cfg.namespace or None,  # Vault Enterprise namespace
        verify=cfg.verify_tls,
    )
    _authenticate(client, cfg)
    if not client.is_authenticated():
        raise RuntimeError(
            f"Vault authentication failed (auth={cfg.auth}, address={cfg.address or 'VAULT_ADDR'})"
        )
    return client


def _authenticate(client, cfg: VaultConfig) -> None:
    auth = (cfg.auth or "token").lower()
    if auth == "token":
        if cfg.token:                     # else hvac falls back to VAULT_TOKEN
            client.token = cfg.token
    elif auth == "approle":
        if not (cfg.role_id and cfg.secret_id):
            raise RuntimeError("vault.auth is 'approle' but role_id/secret_id are not set")
        client.auth.approle.login(role_id=cfg.role_id, secret_id=cfg.secret_id)
    else:
        raise RuntimeError(f"unknown vault.auth '{cfg.auth}'. Known: token, approle")


def _read_kv(client, cfg: VaultConfig, path: str) -> dict:
    if cfg.kv_version == 1:
        resp = client.secrets.kv.v1.read_secret(path=path, mount_point=cfg.kv_mount)
        return resp["data"]
    resp = client.secrets.kv.v2.read_secret_version(path=path, mount_point=cfg.kv_mount)
    return resp["data"]["data"]
