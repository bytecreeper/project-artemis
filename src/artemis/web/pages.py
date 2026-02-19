"""Template-rendered pages -- the dashboard UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["pages"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _ctx(request: Request, **kwargs) -> dict:
    """Build template context with view_mode detection.
    
    Priority: ?mode= param > path-based detection > simple default.
    """
    # Explicit mode param wins
    mode_param = request.query_params.get("mode")
    if mode_param in ("ops", "simple"):
        return {"request": request, "view_mode": mode_param, **kwargs}

    # Path-based: only exclusively-ops pages force Archer
    path = request.url.path
    ops_only = ("/ops", "/dashboard", "/guardian", "/hunt", "/events", "/generate", "/simulate")
    view_mode = "ops" if any(path.startswith(p) for p in ops_only) else "simple"
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
    return templates.TemplateResponse("alerts.html", _ctx(request, active="alerts"))


@router.get("/network", response_class=HTMLResponse)
async def network(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("network.html", _ctx(request, active="network"))


@router.get("/events", response_class=HTMLResponse)
async def events(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("events.html", _ctx(request, active="events"))


@router.get("/generate", response_class=HTMLResponse)
async def generate(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("generate.html", _ctx(request, active="generate"))


@router.get("/settings", response_class=HTMLResponse)
async def settings(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("settings.html", _ctx(request, active="settings"))


# Adversary Simulation
@router.get("/simulate", response_class=HTMLResponse)
async def simulate(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("simulate.html", _ctx(request, active="simulate"))


# Vulnerability Scanner
@router.get("/scan", response_class=HTMLResponse)
async def scan(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("scan.html", _ctx(request, active="scan"))


# Reports
@router.get("/reports", response_class=HTMLResponse)
async def reports(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("reports.html", _ctx(request, active="reports"))


# Chat — Natural Language Interface
@router.get("/chat", response_class=HTMLResponse)
async def chat(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("chat.html", _ctx(request, active="chat"))


# Keep /dashboard as alias for /ops
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_redirect(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("dashboard.html", _ctx(request, active="dashboard"))


# Login
@router.get("/login", response_class=HTMLResponse)
async def login(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("login.html", {"request": request})


# Logout
@router.get("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    from fastapi.responses import RedirectResponse
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("artemis_token")
    return response
