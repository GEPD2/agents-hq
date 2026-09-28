"""Test fixtures. Runs the app in-process via TestClient with a throwaway auth
file and a Host the TrustedHost allowlist accepts. No network, no real DB."""

import os

# Must be set before importing the app: TrustedHost reads it at import time.
os.environ.setdefault("ALLOWED_HOSTS", "testserver,127.0.0.1,localhost")

import pytest
from fastapi.testclient import TestClient

import services.auth_store as auth_store
import main as main_module


@pytest.fixture(autouse=True)
def _reset_singletons():
    # The app and these limiter/guard singletons are imported once for the whole
    # session, so their state must be cleared between tests.
    import services.security as security
    security.rate_limiter._hits.clear()
    security.login_guard._fails.clear()
    security.login_guard._locked_until.clear()
    yield


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    # auth_store reads AUTH_FILE on every call, so a per-test path needs no reload.
    monkeypatch.setenv("AUTH_FILE", str(tmp_path / "auth.json"))
    auth_store.seed_default()
    return TestClient(main_module.app), auth_store, main_module


@pytest.fixture()
def anon_client(app_client):
    tc, _, _ = app_client
    return tc


@pytest.fixture()
def client(app_client):
    """Authenticated client with a fully configured account. Logs in with the
    seeded default, then completes the forced first-login password change so the
    session can reach the rest of the app (the default account is must_change)."""
    tc, store, _ = app_client
    r = tc.post(
        "/login",
        data={"username": store.DEFAULT_USERNAME, "password": store.DEFAULT_PASSWORD},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    r = tc.post(
        "/account/setup",
        data={"new_username": "", "new_password": "changed-pass-1", "confirm_password": "changed-pass-1"},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
    return tc
