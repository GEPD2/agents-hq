"""Security layer for the control panel.

Security headers + CSP, the auth gate (delegating to auth_store), and an
in-memory rate limiter. Stdlib only. Login is always required; credentials and
sessions live in services/auth_store.py.
"""

import os
import time

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from services import auth_store

# Paths reachable without a session so the login page can render and submit.
_EXEMPT_PREFIXES = ("/static/", "/login", "/logout")

# While the account still holds shipped defaults (must_change), an authenticated
# user is confined to these paths until they set a new password.
_SETUP_PATHS = ("/account/setup", "/api/account/setup")

# All libraries are vendored under /static/vendor, fonts are self-hosted, and the
# map is offline, so the panel loads zero external hosts. 'unsafe-inline' remains
# only for the inline scripts/styles in the templates.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)

_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


def _is_exempt(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in _EXEMPT_PREFIXES)


async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    for k, v in _SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    return response


async def auth_gate_middleware(request: Request, call_next):
    # Login is always required; the account store owns credentials and sessions.
    path = request.url.path
    if _is_exempt(path):
        return await call_next(request)
    if not auth_store.is_authed(request):
        if path.startswith("/api/"):
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        return RedirectResponse(url="/login", status_code=303)
    # Authenticated but still on shipped defaults: confine to the setup screen
    # until a new password is set.
    if auth_store.must_change() and path not in _SETUP_PATHS:
        if path.startswith("/api/"):
            return JSONResponse({"detail": "Set a new password first"}, status_code=403)
        return RedirectResponse(url="/account/setup", status_code=303)
    return await call_next(request)


class RateLimiter:
    """Fixed-window in-memory limiter. Single-process, single-user panel, so a
    plain dict of hit timestamps per key is enough; no external store needed."""

    def __init__(self):
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.time()
        bucket = [t for t in self._hits.get(key, []) if now - t < window]
        if len(bucket) >= limit:
            self._hits[key] = bucket
            return False
        bucket.append(now)
        self._hits[key] = bucket
        return True


rate_limiter = RateLimiter()


class LoginGuard:
    """Per-IP failed-login lockout. After LOGIN_MAX_FAILS failures within
    LOGIN_WINDOW, that IP is locked for LOGIN_LOCKOUT seconds. A successful login
    resets it. In-memory, single-process; no external store."""

    def __init__(self):
        self.max_fails = int(os.environ.get("LOGIN_MAX_FAILS", 5))
        self.window = float(os.environ.get("LOGIN_WINDOW", 900))
        self.lockout = float(os.environ.get("LOGIN_LOCKOUT", 900))
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def locked_for(self, ip: str) -> int:
        until = self._locked_until.get(ip, 0)
        remaining = until - time.time()
        return int(remaining) if remaining > 0 else 0

    def register_failure(self, ip: str) -> None:
        now = time.time()
        bucket = [t for t in self._fails.get(ip, []) if now - t < self.window]
        bucket.append(now)
        self._fails[ip] = bucket
        if len(bucket) >= self.max_fails:
            self._locked_until[ip] = now + self.lockout
            self._fails[ip] = []

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)
        self._locked_until.pop(ip, None)


login_guard = LoginGuard()
