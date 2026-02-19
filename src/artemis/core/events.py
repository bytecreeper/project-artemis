"""Event bus — the nervous system of Artemis.

All components communicate through events. In single-process mode, events are
dispatched in-process via asyncio. When NATS is enabled, events are published
to NATS subjects for multi-process deployment.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

logger = logging.getLogger("artemis.events")

# Type alias for event handlers
Handler = Callable[["Event"], Awaitable[None]]


class EventType(str, enum.Enum):
    """All event types in the system."""

    # EDR
    PROCESS_START = "edr.process.start"
    PROCESS_STOP = "edr.process.stop"
    PROCESS_SUSPICIOUS = "edr.process.suspicious"
    FILE_CREATED = "edr.file.created"
    FILE_MODIFIED = "edr.file.modified"
    FILE_DELETED = "edr.file.deleted"
    SYSMON_EVENT = "edr.sysmon.event"
    REGISTRY_CHANGE = "edr.registry.change"

    # Network
    HOST_DISCOVERED = "net.host.discovered"
    HOST_LOST = "net.host.lost"
    PORT_OPEN = "net.port.open"
    TRAFFIC_ANOMALY = "net.traffic.anomaly"
    CONNECTION_SUSPICIOUS = "net.connection.suspicious"

    # Threat Intel
    IOC_MATCH = "intel.ioc.match"

    # Correlation
    ALERT = "correlation.alert"
    CHAIN_DETECTED = "correlation.chain"

    # System
    HEALTH_CHECK = "system.health"


@dataclass(frozen=True)
class Event:
    """Immutable event passed through the bus."""

    type: EventType
    data: dict[str, Any]
    source: str  # which component emitted it
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    severity: int = 0  # 0=info, 1=low, 2=medium, 3=high, 4=critical


class EventBus:
    """Async in-process event bus with optional NATS bridge."""

    def __init__(self) -> None:
        self._handlers: dict[EventType, list[Handler]] = {}
        self._wildcard_handlers: list[Handler] = []
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._running = False
        self._task: asyncio.Task[None] | None = None

    def subscribe(self, event_type: EventType, handler: Handler) -> None:
        """Subscribe to a specific event type."""
        self._handlers.setdefault(event_type, []).append(handler)
        logger.debug("Subscribed %s to %s", handler.__qualname__, event_type.value)

    def subscribe_all(self, handler: Handler) -> None:
        """Subscribe to all events (for logging, correlation, etc.)."""
        self._wildcard_handlers.append(handler)

    async def publish(self, event: Event) -> None:
        """Publish an event to the bus."""
        await self._queue.put(event)

    def publish_sync(self, event: Event) -> None:
        """Non-async publish for use in sync contexts (threads, callbacks)."""
        self._queue.put_nowait(event)

    async def start(self) -> None:
        """Start the event dispatch loop."""
        self._running = True
        self._task = asyncio.create_task(self._dispatch_loop(), name="event-bus")
        logger.info("Event bus started")

    async def stop(self) -> None:
        """Stop the dispatch loop, drain remaining events."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # Drain
        while not self._queue.empty():
            event = self._queue.get_nowait()
            await self._dispatch(event)
        logger.info("Event bus stopped")

    async def _dispatch_loop(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch(event)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def _dispatch(self, event: Event) -> None:
        handlers = self._handlers.get(event.type, []) + self._wildcard_handlers
        for handler in handlers:
            try:
                await handler(event)
            except Exception:
                logger.exception("Handler %s failed for event %s", handler.__qualname__, event.type.value)


# Singleton — import and use directly
bus = EventBus()
