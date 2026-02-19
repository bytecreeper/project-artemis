"""Event persistence — bridges the event bus to DuckDB storage.

Subscribes to ALL events and writes them to the database.
Also handles alert persistence from the correlation engine.
"""

from __future__ import annotations

import json
import logging

from artemis.core.database import Database
from artemis.core.events import Event, EventBus, EventType

logger = logging.getLogger("artemis.persistence")


class EventPersistence:
    """Subscribes to all bus events and persists them to DuckDB."""

    def __init__(self, db: Database) -> None:
        self._db = db
        self._events_stored = 0
        self._alerts_stored = 0

    async def start(self, bus: EventBus) -> None:
        bus.subscribe_all(self._on_event)
        bus.subscribe(EventType.CHAIN_DETECTED, self._on_chain_detected)
        bus.subscribe(EventType.HOST_DISCOVERED, self._on_host_discovered)
        logger.info("Event persistence started")

    async def _on_event(self, event: Event) -> None:
        """Persist every event to the events table."""
        try:
            self._db.insert_event(
                event_id=event.id,
                event_type=event.type.value,
                source=event.source,
                severity=event.severity,
                data=json.dumps(event.data),
                timestamp=event.timestamp,
            )
            self._events_stored += 1
        except Exception:
            logger.exception("Failed to persist event %s", event.id)

    async def _on_chain_detected(self, event: Event) -> None:
        """Persist correlated alert chains to the alerts table."""
        try:
            data = event.data
            self._db.conn.execute(
                """INSERT INTO alerts (id, title, description, severity, event_ids, status, mitre_tactics, mitre_techniques)
                   VALUES (?, ?, ?, ?, ?, 'open', ?, ?)""",
                [
                    event.id,
                    data.get("rule", "Unknown"),
                    data.get("description", ""),
                    event.severity,
                    json.dumps(data.get("event_ids", [])),
                    json.dumps(data.get("mitre_tactics", [])),
                    json.dumps(data.get("mitre_techniques", [])),
                ],
            )
            self._alerts_stored += 1
            logger.warning("Alert persisted: %s (severity=%d)", data.get("rule"), event.severity)
        except Exception:
            logger.exception("Failed to persist alert %s", event.id)

    async def _on_host_discovered(self, event: Event) -> None:
        """Persist/update discovered hosts."""
        try:
            data = event.data
            self._db.conn.execute(
                """INSERT OR REPLACE INTO hosts (ip, mac, hostname, os_guess, last_seen, open_ports)
                   VALUES (?, ?, ?, ?, now(), ?)""",
                [
                    data.get("ip", ""),
                    data.get("mac", ""),
                    data.get("hostname", ""),
                    data.get("os_guess", ""),
                    json.dumps(data.get("open_ports", [])),
                ],
            )
        except Exception:
            logger.exception("Failed to persist host %s", event.data.get("ip"))
