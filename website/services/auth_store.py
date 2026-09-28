"""Account store for the control panel login.

A single local admin account, hashed with pbkdf2 (stdlib), kept in a JSON file
outside the repo. Seeded on first run with the documented default credentials,
which the operator changes from Settings > Account. No database dependency, so
login works even if MySQL is down.
"""

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from fastapi import Request

COOKIE_NAME = "ahq_session"

# Documented default. Change immediately from Settings > Account after first login.
DEFAULT_USERNAME = "GEPD2"
DEFAULT_PASSWORD = "tbHTP5eVmXRDHyQv"

_ITERATIONS = 200_000
_AGENTS_BASE_DIR = os.environ.get("AGENTS_BASE_DIR", "/agents-hq")

# Session cookie lifetime in seconds (default 7 days) so the login survives a
# browser restart. Override with SESSION_TTL.
SESSION_TTL = int(os.environ.get("SESSION_TTL", 604800))


def _auth_file() -> Path:
    return Path(os.environ.get("AUTH_FILE", str(Path(_AGENTS_BASE_DIR) / "runtime" / "auth.json")))


def _hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS).hex()


def _make_record(username: str, password: str, must_change: bool = False) -> dict:
    salt = secrets.token_hex(16)
    return {
        "username": username,
        "salt": salt,
        "hash": _hash(password, salt),
        "iterations": _ITERATIONS,
        "session_secret": secrets.token_hex(32),
        "must_change": must_change,
    }


def _load() -> dict | None:
    path = _auth_file()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def _save(data: dict) -> None:
    path = _auth_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def seed_default() -> None:
    """Create the default account on first run if none exists. It is flagged
    must_change so the panel forces a password rotation before anything else."""
    if _load() is None:
        _save(_make_record(DEFAULT_USERNAME, DEFAULT_PASSWORD, must_change=True))


def current_username() -> str:
    data = _load()
    return data["username"] if data else DEFAULT_USERNAME


def must_change() -> bool:
    """Whether the account still holds shipped defaults and must be rotated.
    Absent flag means an already-configured install, so it is never forced."""
    data = _load()
    return bool(data.get("must_change")) if data else False


def verify_login(username: str, password: str) -> bool:
    data = _load()
    if not data:
        return False
    if not hmac.compare_digest(username or "", data["username"]):
        return False
    candidate = _hash(password or "", data["salt"])
    return hmac.compare_digest(candidate, data["hash"])


def session_value() -> str:
    data = _load()
    if not data:
        return ""
    return hmac.new(
        bytes.fromhex(data["session_secret"]), b"auth:" + data["username"].encode(), hashlib.sha256
    ).hexdigest()


def is_authed(request: Request) -> bool:
    got = request.cookies.get(COOKIE_NAME, "")
    expected = session_value()
    return bool(expected) and hmac.compare_digest(got, expected)


def issue_session_cookie(resp, request: Request) -> None:
    """Set the login session cookie with the standard attributes. One definition
    used by /login and the account-change endpoint so they never drift.
    SameSite=Lax keeps the cookie on normal navigations while withholding it on
    cross-site POSTs; Secure is set only over HTTPS so plain-http loopback works."""
    resp.set_cookie(
        COOKIE_NAME,
        session_value(),
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL,
        secure=(request.url.scheme == "https"),
    )


def set_credentials(new_username: str, new_password: str) -> None:
    """Write a new account record (clearing must_change) after validating the
    password. Username defaults to the current one when left blank. Rotates the
    session secret so any other open session is invalidated. Shared by the forced
    first-login setup and by Settings > Account."""
    data = _load()
    current = data["username"] if data else DEFAULT_USERNAME
    username = (new_username or "").strip() or current
    if not new_password:
        raise ValueError("new password is required")
    if len(new_password) < 8:
        raise ValueError("new password must be at least 8 characters")
    if new_password == DEFAULT_PASSWORD:
        raise ValueError("choose a password other than the shipped default")
    _save(_make_record(username, new_password, must_change=False))


def change_credentials(current_password: str, new_username: str, new_password: str) -> None:
    """Verify the current password, then rewrite the account (Settings > Account)."""
    data = _load()
    if not data:
        raise ValueError("no account configured")
    if not hmac.compare_digest(_hash(current_password or "", data["salt"]), data["hash"]):
        raise ValueError("current password is incorrect")
    set_credentials(new_username, new_password)
