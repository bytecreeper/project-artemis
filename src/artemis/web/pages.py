"""Template-rendered pages -- the dashboard UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["pages"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _ctx(request: Request, **kwargs) -> dict:
    """Build template context with view_mode detection."""
    path = request.url.path
    # Simple view: /, /alerts, /network, /settings (when accessed from simple nav)
    # Ops view: /ops, /guardian, /hunt, /events, /generate
    ops_paths = ("/ops", "/guardian", "/hunt", "/events", "/generate")
    view_mode = "ops" if any(path.startswith(p) for p in ops_paths) else "simple"
    return {"request": request, "view_mode": view_mode, **kwargs}


# -- Simple View --

@router.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("home.html", _ctx(request, active="home"))


# -- Ops View --

@router.get("/ops", response_class=HTMLResponse)
async def ops_dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("dashboard.html", _ctx(request, active="dashboard"))


@router.get("/guardian", response_class=HTMLResponse)
async def guardian(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("guardian.html", _ctx(request, active="guardian"))


@router.get("/hunt", response_class=HTMLResponse)
async def hunt(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("hunt.html", _ctx(request, active="hunt"))


# -- Shared --

@router.get("/alerts", response_class=HTMLResponse)
async def alerts(request: Request) -> HTMLResponse:
    # Detect referrer to choose view mode
    ref = request.headers.get("referer", "")
    view_mode = "ops" if "/ops" in ref or "/guardian" in ref or "/hunt" in ref or "/events" in ref else "simple"
    return templates.TemplateResponse("alerts.html", {"request": request, "view_mode": view_mode, "active": "alerts"})


@router.get("/network", response_class=HTMLResponse)
async def network(request: Request) -> HTMLResponse:
    ref = request.headers.get("referer", "")
    view_mode = "ops" if "/ops" in ref or "/guardian" in ref or "/hunt" in ref or "/events" in ref else "simple"
    return templates.TemplateResponse("network.html", {"request": request, "view_mode": view_mode, "active": "network"})


@router.get("/events", response_class=HTMLResponse)
async def events(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("events.html", _ctx(request, active="events"))


@router.get("/generate", response_class=HTMLResponse)
async def generate(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("generate.html", _ctx(request, active="generate"))


@router.get("/settings", response_class=HTMLResponse)
async def settings(request: Request) -> HTMLResponse:
    ref = request.headers.get("referer", "")
    view_mode = "ops" if "/ops" in ref or "/guardian" in ref or "/hunt" in ref or "/events" in ref else "simple"
    return templates.TemplateResponse("settings.html", {"request": request, "view_mode": view_mode, "active": "settings"})


# Reports
@router.get("/reports", response_class=HTMLResponse)
async def reports(request: Request) -> HTMLResponse:
    ref = request.headers.get("referer", "")
    view_mode = "ops" if "/ops" in ref or "/guardian" in ref or "/hunt" in ref or "/events" in ref else "simple"
    return templates.TemplateResponse("reports.html", {"request": request, "view_mode": view_mode, "active": "reports"})


# Chat — Natural Language Interface
@router.get("/chat", response_class=HTMLResponse)
async def chat(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("chat.html", _ctx(request, active="chat"))


# Keep /dashboard as alias for /ops
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_redirect(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("dashboard.html", _ctx(request, active="dashboard"))
