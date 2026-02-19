"""File Integrity Monitoring plugin — watches for unauthorized file changes."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from pathlib import Path
from typing import Any

from artemis.core.events import Event, EventBus, EventType
from artemis.edr.plugin_base import EDRPlugin

logger = logging.getLogger("artemis.edr.fim")


class FileIntegrityPlugin(EDRPlugin):
    name = "file_integrity"
    description = "Monitor critical files for unauthorized modifications"
    produces = [EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DELETED]
    consumes = []

    def __init__(self) -> None:
        self._bus: EventBus | None = None
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._watch_paths: list[str] = []
        self._baselines: dict[str, str] = {}  # path → sha256
        self._alerts_fired = 0
        self._poll_interval = 30

    def configure(self, config: dict) -> None:
        self._watch_paths = config.get("watch_paths", [])
        self._poll_interval = config.get("poll_interval_seconds", 30)

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._running = True
        # Build baselines in background (don't block server startup)
        self._task = asyncio.create_task(self._init_and_monitor(), name="fim")
        logger.info("FIM starting — baseline scan in background")

    async def _init_and_monitor(self) -> None:
        """Build baselines then enter monitor loop."""
        await asyncio.to_thread(self._build_baselines)
        logger.info("FIM baseline complete — tracking %d files", len(self._baselines))
        await self._monitor_loop()

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def status(self) -> dict:
        return {
            "running": self._running,
            "tracked_files": len(self._baselines),
            "alerts_fired": self._alerts_fired,
        }

    def _build_baselines(self) -> None:
        for watch_path in self._watch_paths:
            p = Path(watch_path)
            if p.is_file():
                h = self._hash_file(p)
                if h:
                    self._baselines[str(p)] = h
            elif p.is_dir():
                # Only watch direct children for now (configurable depth later)
                for f in p.iterdir():
                    if f.is_file():
                        h = self._hash_file(f)
                        if h:
                            self._baselines[str(f)] = h

    async def _monitor_loop(self) -> None:
        while self._running:
            try:
                changes = await asyncio.to_thread(self._check_changes)
                for change in changes:
                    if self._bus:
                        await self._bus.publish(change)
                        self._alerts_fired += 1
            except Exception:
                logger.exception("FIM check error")
            await asyncio.sleep(self._poll_interval)

    def _check_changes(self) -> list[Event]:
        events = []
        current_files: dict[str, str] = {}

        for path_str, old_hash in self._baselines.items():
            p = Path(path_str)
            if not p.exists():
                events.append(Event(
                    type=EventType.FILE_DELETED,
                    data={"path": path_str, "old_hash": old_hash},
                    source="file_integrity",
                    severity=3,
                ))
                continue

            new_hash = self._hash_file(p)
            if new_hash and new_hash != old_hash:
                events.append(Event(
                    type=EventType.FILE_MODIFIED,
                    data={"path": path_str, "old_hash": old_hash, "new_hash": new_hash},
                    source="file_integrity",
                    severity=2,
                ))
                current_files[path_str] = new_hash
            else:
                current_files[path_str] = old_hash

        # Update baselines with current state
        self._baselines = current_files
        return events

    @staticmethod
    def _hash_file(path: Path) -> str | None:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, PermissionError):
            return None
