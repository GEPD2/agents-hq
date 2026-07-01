import os
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from routers import agents, reports, kb, settings as settings_router, iocs as iocs_router, batch as batch_router, market as market_router, cases as cases_router, map_router, graph_router

BASE_DIR = Path(__file__).parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="AGENTS-HQ Control Panel",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
