"""HttpClient error handling — client errors fail fast with the real reason."""

from __future__ import annotations

import pytest

from codescan.connectors.base import HttpClient


class _Resp:
    def __init__(self, status_code, reason, text="", headers=None):
        self.status_code = status_code
        self.reason = reason
        self.text = text
        self.headers = headers or {}


def test_4xx_fails_fast_with_reason():
    client = HttpClient("https://api.github.com", "bad-token")
    calls = {"n": 0}

    def fake_request(method, url, **kwargs):
        calls["n"] += 1
        return _Resp(401, "Unauthorized", text='{"message": "Bad credentials"}')

    client.session.request = fake_request

    with pytest.raises(RuntimeError) as exc:
        client.get("/user/repos")

    msg = str(exc.value)
    assert "401 Unauthorized" in msg
    assert "Bad credentials" in msg          # surfaces the real reason
    assert calls["n"] == 1                    # not retried on a 4xx


def test_missing_base_url_fails_clearly():
    client = HttpClient("", "tok")           # empty base URL (unset env var)
    with pytest.raises(RuntimeError) as exc:
        client.get("/repos/owner/name")
    assert "no base URL configured" in str(exc.value)


def test_success_returns_response():
    client = HttpClient("https://api.github.com", "tok")
    client.session.request = lambda method, url, **kw: _Resp(200, "OK", text="[]")
    assert client.get("/user/repos").status_code == 200
