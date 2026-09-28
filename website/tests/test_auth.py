def test_unauth_page_redirects(anon_client):
    r = anon_client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login"


def test_unauth_api_401(anon_client):
    r = anon_client.get("/api/status")
    assert r.status_code == 401


def test_login_with_default_then_access(client):
    r = client.get("/api/status")
    assert r.status_code == 200


def test_wrong_password_rejected(app_client):
    tc, auth_store, _ = app_client
    r = tc.post("/login", data={"username": auth_store.DEFAULT_USERNAME, "password": "wrong"},
                follow_redirects=False)
    assert r.status_code == 401


def test_verify_and_change_credentials(app_client):
    tc, auth_store, _ = app_client
    assert auth_store.verify_login(auth_store.DEFAULT_USERNAME, auth_store.DEFAULT_PASSWORD)
    auth_store.change_credentials(auth_store.DEFAULT_PASSWORD, "newadmin", "s3cretpass!")
    assert not auth_store.verify_login(auth_store.DEFAULT_USERNAME, auth_store.DEFAULT_PASSWORD)
    assert auth_store.verify_login("newadmin", "s3cretpass!")


def test_change_requires_correct_current(app_client):
    tc, auth_store, _ = app_client
    import pytest
    with pytest.raises(ValueError):
        auth_store.change_credentials("badcurrent", "x", "anotherpass1")


def test_session_cookie_is_persistent_and_lax(app_client):
    tc, auth_store, _ = app_client
    r = tc.post(
        "/login",
        data={"username": auth_store.DEFAULT_USERNAME, "password": auth_store.DEFAULT_PASSWORD},
        follow_redirects=False,
    )
    setc = r.headers.get("set-cookie", "")
    assert "ahq_session=" in setc
    assert "Max-Age=" in setc          # persists across browser restart
    assert "HttpOnly" in setc
    assert "samesite=lax" in setc.lower()


def _login_default(tc, auth_store):
    r = tc.post(
        "/login",
        data={"username": auth_store.DEFAULT_USERNAME, "password": auth_store.DEFAULT_PASSWORD},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)


def test_default_account_is_must_change(app_client):
    tc, auth_store, _ = app_client
    assert auth_store.must_change() is True


def test_must_change_confines_to_setup(app_client):
    tc, auth_store, _ = app_client
    _login_default(tc, auth_store)
    # A page is bounced to the setup screen; the API is blocked with 403.
    r = tc.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/account/setup"
    assert tc.get("/api/status").status_code == 403


def test_setup_rejects_shipped_default_password(app_client):
    tc, auth_store, _ = app_client
    _login_default(tc, auth_store)
    r = tc.post(
        "/account/setup",
        data={"new_username": "", "new_password": auth_store.DEFAULT_PASSWORD,
              "confirm_password": auth_store.DEFAULT_PASSWORD},
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert auth_store.must_change() is True


def test_setup_rejects_mismatched_confirm(app_client):
    tc, auth_store, _ = app_client
    _login_default(tc, auth_store)
    r = tc.post(
        "/account/setup",
        data={"new_username": "", "new_password": "goodpass123", "confirm_password": "different123"},
        follow_redirects=False,
    )
    assert r.status_code == 400
    assert auth_store.must_change() is True


def test_setup_sets_password_and_clears_gate(app_client):
    tc, auth_store, _ = app_client
    _login_default(tc, auth_store)
    r = tc.post(
        "/account/setup",
        data={"new_username": "", "new_password": "goodpass123", "confirm_password": "goodpass123"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    assert auth_store.must_change() is False
    # The gate is now open and the new password works.
    assert tc.get("/api/status").status_code == 200
    assert auth_store.verify_login(auth_store.DEFAULT_USERNAME, "goodpass123")


def test_set_credentials_rejects_default_password(app_client):
    tc, auth_store, _ = app_client
    import pytest
    with pytest.raises(ValueError):
        auth_store.set_credentials("", auth_store.DEFAULT_PASSWORD)


def test_login_lockout_after_failures(app_client):
    tc, auth_store, main_module = app_client
    import services.security as security
    for _ in range(security.login_guard.max_fails):
        r = tc.post("/login", data={"username": "GEPD2", "password": "wrong"}, follow_redirects=False)
        assert r.status_code == 401
    # Next attempt is locked, even with the correct password.
    r = tc.post(
        "/login",
        data={"username": auth_store.DEFAULT_USERNAME, "password": auth_store.DEFAULT_PASSWORD},
        follow_redirects=False,
    )
    assert r.status_code == 429
    # Reset clears the lock.
    security.login_guard.reset("testclient")
    r = tc.post(
        "/login",
        data={"username": auth_store.DEFAULT_USERNAME, "password": auth_store.DEFAULT_PASSWORD},
        follow_redirects=False,
    )
    assert r.status_code in (302, 303)
