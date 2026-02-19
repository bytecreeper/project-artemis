"""Main FastAPI application — assembles all components."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from artemis.core.config import Config
from artemis.core.events import bus
from artemis.core.database import Database
from artemis.core.persistence import EventPersistence
from artemis.ai.provider import create_provider
from artemis.correlation.engine import CorrelationEngine
from artemis.edr.plugin_base import load_plugins
from artemis.network.scanner import NetworkScanner
from artemis.web.sse import sse_manager
from artemis.core.threat_classifier import classifier
from artemis.ai.alert_narrator import AlertNarrator
import asyncio as _asyncio
from artemis.core.auth import ensure_token, AuthMiddleware

logger = logging.getLogger("artemis.web")

WEB_DIR = Path(__file__).parent
STATIC_DIR = WEB_DIR / "static"


class ArtemisApp:
    """Central application state — holds all initialized components."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.db = Database(config.database.path)
        self.ai = create_provider(config.ai)
        self.persistence = EventPersistence(self.db)
        self.correlation = CorrelationEngine(
            window_seconds=config.correlation.window_seconds,
            min_chain_score=config.correlation.min_chain_score,
        )
        self.network = NetworkScanner(
            scan_range=config.network.scan_range,
            interval=config.network.scan_interval_seconds,
        )
        self.narrator = AlertNarrator(ai_provider=self.ai, db=self.db)
        self.edr_plugins: list = []
        self.start_time = time.time()


# Global app state — populated at startup
state: ArtemisApp | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown lifecycle."""
    global state

    config = Config.load()

    # Ensure auth token exists (generates on first run)
    if config.web.auth_enabled:
        token = ensure_token()
        if not config.web.api_key:
            config.web.api_key = token

    state = ArtemisApp(config)

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Connect database
    state.db.connect()
    logger.info("Database connected")

    # Start event bus
    await bus.start()
    logger.info("Event bus started")

    # Start event persistence (bus → DuckDB)
    await state.persistence.start(bus)

    # Start correlation engine
    if config.correlation.enabled:
        await state.correlation.start(bus)

    # Load and start EDR plugins
    if config.edr.enabled:
        plugin_classes = load_plugins(config.edr.plugins)
        for cls in plugin_classes:
            plugin = cls()
            # Pass plugin-specific config
            if plugin.name == "file_integrity":
                plugin.configure({
                    "watch_paths": config.edr.file_integrity.watch_paths,
                    "poll_interval_seconds": config.edr.file_integrity.poll_interval_seconds,
                })
            await plugin.start(bus)
            state.edr_plugins.append(plugin)
        logger.info("EDR: %d plugins active", len(state.edr_plugins))

    # Start network scanner
    if config.network.enabled:
        await state.network.start(bus)

    # Start threat classifier (with DB persistence)
    classifier.set_db(state.db)
    await classifier.start(bus)

    # Start plain-language alert narrator (with DB persistence)
    state.narrator.load_from_db()
    await state.narrator.start(bus)

    # Start SSE manager (real-time event push)
    await sse_manager.start(bus)

    # Start periodic score recording (every 15 min)
    async def _record_score_loop():
        while True:
            try:
                await _asyncio.sleep(900)  # 15 min
                score = classifier.security_score
                label = classifier.score_label
                findings = len(classifier.active_findings)
                events = state.db.count_events_since(24)
                state.db.record_score(score, label, findings, events)
                logger.debug("Recorded score: %d (%s)", score, label)
            except _asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Score recording error")

    score_task = _asyncio.create_task(_record_score_loop(), name="score-recorder")

    # Record initial score
    try:
        state.db.record_score(
            classifier.security_score, classifier.score_label,
            len(classifier.active_findings), state.db.count_events_since(24),
        )
    except Exception:
        pass

    logger.info("Artemis v3.0.0 ready — all systems online")

    yield

    score_task.cancel()

    # Shutdown
    logger.info("Shutting down...")
    if config.network.enabled:
        await state.network.stop()
    for plugin in state.edr_plugins:
        await plugin.stop()
    if config.correlation.enabled:
        await state.correlation.stop()
    await state.narrator.stop()
    await bus.stop()
    state.db.close()
    logger.info("Shutdown complete")


def create_app() -> FastAPI:
    """Factory function — creates and configures the FastAPI app."""
    app = FastAPI(
        title="Project Artemis",
        version="3.0.0",
        description="AI-powered security operations platform",
        lifespan=lifespan,
    )

    # Auth middleware — loads token from config
    config = Config.load()
    if config.web.auth_enabled:
        token = config.web.api_key or ensure_token()
        app.add_middleware(AuthMiddleware, token=token, enabled=True)

    # Static files
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # API routes
    from artemis.web.api.routes import router as api_router
    app.include_router(api_router, prefix="/api")

    # Template-based pages
    from artemis.web.pages import router as pages_router
    app.include_router(pages_router)

    return app


# The app instance — used by uvicorn
app = create_app()
