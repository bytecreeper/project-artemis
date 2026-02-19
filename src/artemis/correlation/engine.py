"""Correlation engine — detects attack chains from individual events.

Subscribes to ALL events on the bus. Maintains a sliding time window and
looks for patterns that indicate coordinated attacks (e.g., process spawn +
network connection + file write = potential C2 implant).
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from artemis.core.events import Event, EventBus, EventType

logger = logging.getLogger("artemis.correlation")


@dataclass
class EventWindow:
    """Sliding window of recent events, grouped by key (IP, PID, user, etc.)."""

    events: list[Event] = field(default_factory=list)
    score: float = 0.0


@dataclass
class CorrelationRule:
    """A rule that matches a chain of events."""

    name: str
    description: str
    required_types: list[EventType]
    min_score: float = 5.0
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    def matches(self, events: list[Event]) -> bool:
        """Check if a set of events satisfies this rule."""
        seen_types = {e.type for e in events}
        return all(t in seen_types for t in self.required_types)


# Built-in correlation rules
BUILTIN_RULES: list[CorrelationRule] = [
    CorrelationRule(
        name="Suspicious Process + C2 Connection",
        description="A suspicious process was spawned and made a network connection",
        required_types=[EventType.PROCESS_SUSPICIOUS, EventType.CONNECTION_SUSPICIOUS],
        min_score=7.0,
        mitre_tactics=["execution", "command-and-control"],
        mitre_techniques=["T1059", "T1071"],
    ),
    CorrelationRule(
        name="LOLBin Execution + File Drop",
        description="Living-off-the-land binary executed followed by file creation in temp",
        required_types=[EventType.PROCESS_START, EventType.FILE_CREATED],
        min_score=6.0,
        mitre_tactics=["execution", "defense-evasion"],
        mitre_techniques=["T1218", "T1105"],
    ),
    CorrelationRule(
        name="File Tampering + Process Spawn",
        description="Critical file modified and new process started",
        required_types=[EventType.FILE_MODIFIED, EventType.PROCESS_START],
        min_score=5.0,
        mitre_tactics=["persistence", "execution"],
        mitre_techniques=["T1546"],
    ),
]


class CorrelationEngine:
    """Watches the event stream for multi-event attack patterns."""

    def __init__(self, window_seconds: int = 300, min_chain_score: float = 7.0) -> None:
        self._window_seconds = window_seconds
        self._min_chain_score = min_chain_score
        self._windows: dict[str, EventWindow] = defaultdict(EventWindow)
        self._rules = list(BUILTIN_RULES)
        self._bus: EventBus | None = None
        self._alerts_fired = 0

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        bus.subscribe_all(self._on_event)
        logger.info("Correlation engine started (%d rules, %ds window)",
                     len(self._rules), self._window_seconds)

    async def stop(self) -> None:
        logger.info("Correlation engine stopped (%d alerts fired)", self._alerts_fired)

    def add_rule(self, rule: CorrelationRule) -> None:
        self._rules.append(rule)

    async def _on_event(self, event: Event) -> None:
        # Don't correlate our own alerts (feedback loop)
        if event.type in (EventType.ALERT, EventType.CHAIN_DETECTED):
            return

        # Determine correlation key (group events by related entity)
        key = self._extract_key(event)
        if not key:
            return

        window = self._windows[key]
        window.events.append(event)
        window.score += event.severity

        # Prune old events from window
        cutoff = time.time() - self._window_seconds
        window.events = [e for e in window.events if e.timestamp > cutoff]
        window.score = sum(e.severity for e in window.events)

        # Check rules
        if window.score >= self._min_chain_score:
            for rule in self._rules:
                if rule.matches(window.events) and window.score >= rule.min_score:
                    await self._fire_alert(key, window, rule)
                    # Reset window after alert
                    self._windows[key] = EventWindow()
                    break

    def _extract_key(self, event: Event) -> str | None:
        """Extract a correlation key from an event (PID, IP, user, etc.)."""
        data = event.data
        # Try PID-based grouping
        if pid := data.get("pid"):
            return f"pid:{pid}"
        # Try IP-based
        if ip := data.get("ip") or data.get("SourceIp") or data.get("DestinationIp"):
            return f"ip:{ip}"
        # Try user-based
        if user := data.get("username") or data.get("User"):
            return f"user:{user}"
        return None

    async def _fire_alert(self, key: str, window: EventWindow, rule: CorrelationRule) -> None:
        if not self._bus:
            return
        alert_data: dict[str, Any] = {
            "rule": rule.name,
            "description": rule.description,
            "correlation_key": key,
            "event_count": len(window.events),
            "event_ids": [e.id for e in window.events],
            "total_score": window.score,
            "mitre_tactics": rule.mitre_tactics,
            "mitre_techniques": rule.mitre_techniques,
        }
        await self._bus.publish(Event(
            type=EventType.CHAIN_DETECTED,
            data=alert_data,
            source="correlation",
            severity=4,
        ))
        self._alerts_fired += 1
        logger.warning("CHAIN DETECTED: %s [key=%s, score=%.1f, events=%d]",
                       rule.name, key, window.score, len(window.events))
