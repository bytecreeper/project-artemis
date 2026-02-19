"""Authentication — bearer token auth for all API endpoints.

On first run, generates a random token and writes it to config/local.toml.
All API requests must include: Authorization: Bearer <token>
Static files and the health endpoint are exempt.
"""

from __future__ import annotations

import logging
import secrets
from pathlib import Path

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("artemis.auth")

# Paths that don't require auth
PUBLIC_PATHS = frozenset({
    "/api/health",
    "/docs",
    "/openapi.json",
    "/favicon.ico",
    "/login",
    "/logout",
})

PUBLIC_PREFIXES = (
    "/static/",
)


def generate_token() -> str:
    """Generate a cryptographically secure API token."""
    return secrets.token_urlsafe(32)


def ensure_token(config_dir: Path | None = None) -> str:
    """Ensure an API token exists. Generate one on first run.

    Writes the token to config/local.toml if it doesn't exist.
    Returns the active token.
    """
    if config_dir is None:
        config_dir = Path(__file__).parent.parent.parent.parent / "config"

    local_path = config_dir / "local.toml"
    config_dir.mkdir(parents=True, exist_ok=True)

    # Check if local.toml already has a token
    existing_token = _read_token_from_file(local_path)
    if existing_token:
        return existing_token

    # Generate new token
    token = generate_token()

    # Write or append to local.toml
    if local_path.exists():
        content = local_path.read_text()
        if "[web]" in content:
            # Add api_key under existing [web] section
            content = content.replace("[web]", f'[web]\napi_key = "{token}"', 1)
        else:
            content += f'\n[web]\napi_key = "{token}"\n'
        local_path.write_text(content)
    else:
        local_path.write_text(f'[web]\napi_key = "{token}"\n')

    logger.info("=" * 60)
    logger.info("FIRST RUN — API token generated")
    logger.info("Token: %s", token)
    logger.info("Saved to: %s", local_path)
    logger.info("Include in requests: Authorization: Bearer %s", token)
    logger.info("=" * 60)

    return token


def _read_token_from_file(path: Path) -> str | None:
    """Read api_key from a TOML file."""
    if not path.exists():
        return None
    try:
        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]
        with open(path, "rb") as f:
            data = tomllib.load(f)
        token = data.get("web", {}).get("api_key", "")
        return token if token else None
    except Exception:
        return None


class AuthMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that enforces bearer token auth."""

    def __init__(self, app, token: str, enabled: bool = True):
        super().__init__(app)
        self.token = token
        self.enabled = enabled

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        path = request.url.path

        # Skip auth for public paths
        if path in PUBLIC_PATHS:
            return await call_next(request)
        for prefix in PUBLIC_PREFIXES:
            if path.startswith(prefix):
                return await call_next(request)

        # Page routes (HTML) — check cookie or query param
        if not path.startswith("/api/"):
            # Allow page access if token is in cookie or query
            token = request.cookies.get("artemis_token") or request.query_params.get("token")
            if token == self.token:
                return await call_next(request)
            # If no token, redirect to login
            if path != "/login":
                from fastapi.responses import RedirectResponse
                return RedirectResponse(url="/login", status_code=302)
            return await call_next(request)

        # API routes — check Authorization header
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            provided = auth[7:].strip()
            if secrets.compare_digest(provided, self.token):
                return await call_next(request)

        # Also accept token as query param for SSE/browser convenience
        if request.query_params.get("token") == self.token:
            return await call_next(request)

        # Also accept cookie
        if request.cookies.get("artemis_token") == self.token:
            return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing API token"},
        )
