import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import HTTPException as FastAPIHTTPException
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from routers import agents, reports, kb, settings as settings_router, iocs as iocs_router, batch as batch_router, market as market_router, cases as cases_router, map_router, graph_router, metrics as metrics_router, activity as activity_router
from services import security, auth_store, migrations

BASE_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth_store.seed_default()
    migrations.run()
    yield


app = FastAPI(
    title="AGENTS-HQ Control Panel",
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware runs outermost-last: register the auth gate, then security headers,
# then the Host allowlist so it is the outermost layer and rejects a bad Host
# (DNS-rebinding defense) before anything else runs.
app.middleware("http")(security.auth_gate_middleware)
app.middleware("http")(security.security_headers_middleware)

_ALLOWED_HOSTS = [
    h.strip() for h in os.environ.get(
        "ALLOWED_HOSTS", "127.0.0.1,localhost,127.0.0.1:8080,localhost:8080,127.0.0.1:8443,localhost:8443"
    ).split(",") if h.strip()
]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_ALLOWED_HOSTS)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def _wants_json(request: Request) -> bool:
    return request.url.path.startswith("/api/") or "application/json" in request.headers.get("accept", "")


_ERROR_MESSAGES = {
    400: "Bad request.",
    401: "Authentication required.",
    403: "You do not have access to that.",
    404: "That page or resource was not found.",
    429: "Too many requests. Slow down and try again shortly.",
    500: "Something went wrong on the server.",
}


async def _render_error(request: Request, status_code: int, detail: str | None = None):
    if _wants_json(request):
        return JSONResponse({"detail": detail or _ERROR_MESSAGES.get(status_code, "Error")}, status_code=status_code)
    ctx = {
        "request": request,
        "code": status_code,
        "message": detail or _ERROR_MESSAGES.get(status_code, "Error"),
        "show_login": status_code == 401,
    }
    return templates.TemplateResponse("error.html", ctx, status_code=status_code)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return await _render_error(request, exc.status_code, exc.detail if isinstance(exc.detail, str) else None)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return await _render_error(request, 500)


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/login")
async def login_submit(request: Request, username: str = Form(""), password: str = Form("")):
    ip = request.client.host if request.client else "unknown"
    locked = security.login_guard.locked_for(ip)
    if locked > 0:
        mins = max(1, locked // 60)
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": f"Too many attempts. Try again in {mins} min."},
            status_code=429,
        )
    if not auth_store.verify_login(username, password):
        security.login_guard.register_failure(ip)
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password."}, status_code=401
        )
    security.login_guard.reset(ip)
    resp = RedirectResponse(url="/", status_code=303)
    auth_store.issue_session_cookie(resp, request)
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie(auth_store.COOKIE_NAME)
    return resp


@app.get("/account/setup", response_class=HTMLResponse)
async def account_setup_page(request: Request, error: str = ""):
    # Only meaningful while the account still holds shipped defaults.
    if not auth_store.must_change():
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        "account_setup.html",
        {"request": request, "error": error, "username": auth_store.current_username()},
    )


@app.post("/account/setup")
async def account_setup_submit(
    request: Request,
    new_username: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
):
    def fail(msg: str):
        return templates.TemplateResponse(
            "account_setup.html",
            {"request": request, "error": msg, "username": auth_store.current_username()},
            status_code=400,
        )

    if new_password != confirm_password:
        return fail("Passwords do not match.")
    try:
        auth_store.set_credentials(new_username, new_password)
    except ValueError as e:
        return fail(str(e))
    resp = RedirectResponse(url="/", status_code=303)
    auth_store.issue_session_cookie(resp, request)
    return resp

app.include_router(agents.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(kb.router, prefix="/api")
app.include_router(settings_router.router, prefix="/api")
app.include_router(iocs_router.router, prefix="/api")
app.include_router(batch_router.router, prefix="/api")
app.include_router(market_router.router, prefix="/api")
app.include_router(cases_router.router, prefix="/api")
app.include_router(map_router.router, prefix="/api")
app.include_router(graph_router.router, prefix="/api")
app.include_router(metrics_router.router, prefix="/api")
app.include_router(activity_router.router, prefix="/api")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    return templates.TemplateResponse("agents.html", {"request": request})


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})


@app.get("/reports/{filename:path}", response_class=HTMLResponse)
async def report_view(request: Request, filename: str):
    return templates.TemplateResponse("report_view.html", {"request": request, "filename": filename})


@app.get("/kb", response_class=HTMLResponse)
async def kb_page(request: Request):
    return templates.TemplateResponse("kb.html", {"request": request})


@app.get("/threat-actors", response_class=HTMLResponse)
async def threat_actors_page(request: Request):
    return templates.TemplateResponse("threat_actors.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/timeline", response_class=HTMLResponse)
async def timeline_page(request: Request):
    return templates.TemplateResponse("timeline.html", {"request": request})


@app.get("/iocs", response_class=HTMLResponse)
async def iocs_page(request: Request):
    return templates.TemplateResponse("iocs.html", {"request": request})


@app.get("/batch", response_class=HTMLResponse)
async def batch_page(request: Request):
    return templates.TemplateResponse("batch.html", {"request": request})


@app.get("/market-intel", response_class=HTMLResponse)
async def market_intel_page(request: Request):
    return templates.TemplateResponse("market_intel.html", {"request": request})


@app.get("/graph", response_class=HTMLResponse)
async def graph_page(request: Request):
    return templates.TemplateResponse("graph.html", {"request": request})


@app.get("/map", response_class=HTMLResponse)
async def map_page(request: Request):
    return templates.TemplateResponse("map_view.html", {"request": request})


@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request):
    return templates.TemplateResponse("cases.html", {"request": request})


@app.get("/cases/{case_id}", response_class=HTMLResponse)
async def case_detail_page(request: Request, case_id: str):
    return templates.TemplateResponse("case_detail.html", {"request": request, "case_id": case_id})


@app.get("/pivot/{ioc_type}/{value:path}", response_class=HTMLResponse)
async def pivot_page(request: Request, ioc_type: str, value: str):
    return templates.TemplateResponse("pivot.html", {"request": request, "ioc_type": ioc_type, "value": value})


@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request):
    return templates.TemplateResponse("privacy.html", {"request": request})


if __name__ == "__main__":
    import uvicorn
    # proxy_headers lets the app trust X-Forwarded-Proto from the local nginx TLS
    # proxy, so request.url.scheme is https behind it (drives the Secure cookie).
    uvicorn.run(
        "main:app", host="127.0.0.1", port=8080, reload=True,
        proxy_headers=True, forwarded_allow_ips="127.0.0.1",
    )
