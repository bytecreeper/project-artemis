"""Server-Sent Events — push real-time events to the browser.

SSE is simpler than WebSocket, works over regular HTTP, and is perfect
for one-way server→client push (which is what Guardian needs).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncGenerator

from starlette.requests import Request
from starlette.responses import StreamingResponse

from artemis.core.events import Event, EventBus

logger = logging.getLogger("artemis.sse")


class SSEManager:
    """Manages SSE connections and broadcasts events to all clients."""

    def __init__(self) -> None:
        self._queues: list[asyncio.Queue[dict[str, Any]]] = []

    @property
    def active_count(self) -> int:
        return len(self._queues)

    async def start(self, bus: EventBus) -> None:
        bus.subscribe_all(self._on_event)
        logger.info("SSE manager started")

    async def _on_event(self, event: Event) -> None:
        if not self._queues:
            return
        msg = {
            "id": event.id,
            "event_type": event.type.value,
            "source": event.source,
            "severity": event.severity,
            "timestamp": event.timestamp,
            "data": event.data,
        }
        dead: list[asyncio.Queue] = []
        for q in self._queues:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                # Drop oldest
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(msg)
                except asyncio.QueueFull:
                    dead.append(q)
        for q in dead:
            if q in self._queues:
                self._queues.remove(q)

    async def subscribe(self) -> AsyncGenerator[str, None]:
        """Yields SSE-formatted strings for a single client."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        self._queues.append(queue)
        logger.info("SSE client connected (%d total)", len(self._queues))
        try:
            # Send initial keepalive
            yield ": connected\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    data = json.dumps(msg)
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive comment to prevent timeout
                    yield ": keepalive\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            if queue in self._queues:
                self._queues.remove(queue)
            logger.info("SSE client disconnected (%d remaining)", len(self._queues))


# Singleton
sse_manager = SSEManager()


def create_sse_response(request: Request) -> StreamingResponse:
    """Create an SSE StreamingResponse for a client."""
    return StreamingResponse(
        sse_manager.subscribe(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
