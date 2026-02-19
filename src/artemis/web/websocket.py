"""WebSocket manager — pushes real-time events to connected dashboard clients."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from artemis.core.events import Event, EventBus, EventType

logger = logging.getLogger("artemis.ws")


class ConnectionManager:
    """Manages WebSocket connections and broadcasts events."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)
        self._task: asyncio.Task[None] | None = None

    @property
    def active_count(self) -> int:
        return len(self._connections)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.info("WebSocket client connected (%d total)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)
        logger.info("WebSocket client disconnected (%d remaining)", len(self._connections))

    async def start(self, bus: EventBus) -> None:
        """Subscribe to all events and start the broadcast loop."""
        bus.subscribe_all(self._on_event)
        self._task = asyncio.create_task(self._broadcast_loop(), name="ws-broadcast")
        logger.info("WebSocket manager started")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # Close all connections
        for ws in list(self._connections):
            try:
                await ws.close()
            except Exception:
                pass
        self._connections.clear()

    async def _on_event(self, event: Event) -> None:
        """Queue event for broadcast to WebSocket clients."""
        if not self._connections:
            return
        msg = {
            "type": "event",
            "data": {
                "id": event.id,
                "event_type": event.type.value,
                "source": event.source,
                "severity": event.severity,
                "timestamp": event.timestamp,
                "data": event.data,
            },
        }
        try:
            self._queue.put_nowait(msg)
        except asyncio.QueueFull:
            # Drop oldest if full
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            self._queue.put_nowait(msg)

    async def _broadcast_loop(self) -> None:
        """Batch and broadcast events to all connected clients."""
        while True:
            try:
                # Collect events for up to 250ms or 20 events
                batch: list[dict[str, Any]] = []
                try:
                    msg = await asyncio.wait_for(self._queue.get(), timeout=0.25)
                    batch.append(msg)
                except asyncio.TimeoutError:
                    continue

                # Drain any additional queued events
                while len(batch) < 20:
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                if not batch or not self._connections:
                    continue

                payload = json.dumps({"batch": batch})
                dead: list[WebSocket] = []

                for ws in list(self._connections):
                    try:
                        if ws.client_state == WebSocketState.CONNECTED:
                            await ws.send_text(payload)
                        else:
                            dead.append(ws)
                    except Exception:
                        dead.append(ws)

                for ws in dead:
                    self.disconnect(ws)

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Broadcast error")
                await asyncio.sleep(1)


# Singleton
ws_manager = ConnectionManager()
