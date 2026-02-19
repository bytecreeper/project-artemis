"""Plain-Language Alert Narrator.

Subscribes to the event bus and translates raw security events into
human-readable notifications that non-technical users can understand.

Every alert gets two versions:
- plain: "Someone may be trying to break into your computer"
- technical: "Correlation chain detected: lateral movement pattern (T1021)"
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from artemis.core.events import Event, EventBus, EventType

logger = logging.getLogger("artemis.alert_narrator")

# ── Severity labels ────────────────────────────────────────────────────

SEVERITY_LABELS = {
    1: ("Info", "ℹ️"),
    2: ("Low", "🔵"),
    3: ("Medium", "🟡"),
    4: ("High", "🔴"),
    5: ("Critical", "🚨"),
}

# ── Narrative templates ────────────────────────────────────────────────

# Maps event types → plain-language explanation generators
NARRATIVES: dict[EventType, dict[str, str]] = {
    EventType.PROCESS_SUSPICIOUS: {
        "plain": "A suspicious program was detected running on your computer.",
        "action": "Artemis is monitoring it. If you didn't start this program, consider stopping it.",
    },
    EventType.FILE_CREATED: {
        "plain": "A new file appeared in a monitored folder.",
        "action": "This is usually normal, but Artemis logged it for your records.",
    },
    EventType.FILE_MODIFIED: {
        "plain": "A monitored file was changed.",
        "action": "If you didn't make this change, it may be worth investigating.",
    },
    EventType.FILE_DELETED: {
        "plain": "A monitored file was deleted.",
        "action": "File deletions can be normal, but unexpected ones may indicate tampering.",
    },
    EventType.REGISTRY_CHANGE: {
        "plain": "A system setting (registry key) was modified.",
        "action": "Registry changes can affect how your computer starts up. Worth checking if unexpected.",
    },
    EventType.HOST_DISCOVERED: {
        "plain": "A new device joined your network.",
        "action": "Make sure you recognize this device. Unknown devices could be a security risk.",
    },
    EventType.HOST_LOST: {
        "plain": "A device left your network.",
        "action": "This is usually normal — someone turned off a device or disconnected.",
    },
    EventType.TRAFFIC_ANOMALY: {
        "plain": "Unusual network traffic was detected.",
        "action": "This could indicate data exfiltration or unauthorized communication.",
    },
    EventType.CONNECTION_SUSPICIOUS: {
        "plain": "A suspicious network connection was detected.",
        "action": "A program on your computer may be communicating with an unknown server.",
    },
    EventType.IOC_MATCH: {
        "plain": "A known threat indicator was found on your system.",
        "action": "This matches a known malicious signature. Immediate investigation recommended.",
    },
    EventType.CHAIN_DETECTED: {
        "plain": "Multiple suspicious activities were linked together — this may be an attack in progress.",
        "action": "Artemis detected a pattern of events that resembles a real attack. Review immediately.",
    },
    EventType.ALERT: {
        "plain": "A security alert was triggered.",
        "action": "Review the details below and take action if needed.",
    },
}


@dataclass
class PlainAlert:
    """A human-readable alert."""
    id: str
    timestamp: float
    severity: int
    severity_label: str
    severity_icon: str
    headline: str        # One-line plain English
    plain: str           # Paragraph explanation
    action: str          # What the user should do
    technical: str       # Full technical detail
    event_type: str
    source: str
    data: dict[str, Any] = field(default_factory=dict)
    dismissed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "severity_icon": self.severity_icon,
            "headline": self.headline,
            "plain": self.plain,
            "action": self.action,
            "technical": self.technical,
            "event_type": self.event_type,
            "source": self.source,
            "dismissed": self.dismissed,
        }


class AlertNarrator:
    """Listens for security events and produces plain-language alerts."""

    def __init__(self, max_alerts: int = 500, ai_provider=None):
        self._alerts: deque[PlainAlert] = deque(maxlen=max_alerts)
        self._ai = ai_provider
        self._bus: EventBus | None = None
        self._alert_count = 0

    async def start(self, bus: EventBus) -> None:
        """Subscribe to all alert-worthy event types."""
        self._bus = bus
        alert_types = [
            EventType.PROCESS_SUSPICIOUS,
            EventType.FILE_CREATED,
            EventType.FILE_MODIFIED,
            EventType.FILE_DELETED,
            EventType.REGISTRY_CHANGE,
            EventType.HOST_DISCOVERED,
            EventType.HOST_LOST,
            EventType.TRAFFIC_ANOMALY,
            EventType.CONNECTION_SUSPICIOUS,
            EventType.IOC_MATCH,
            EventType.CHAIN_DETECTED,
            EventType.ALERT,
        ]
        for et in alert_types:
            bus.subscribe(et, self._on_event)
        logger.info("Alert narrator started — listening for %d event types", len(alert_types))

    async def stop(self) -> None:
        logger.info("Alert narrator stopped (%d alerts generated)", self._alert_count)

    async def _on_event(self, event: Event) -> None:
        """Transform a raw event into a plain-language alert."""
        alert = await self._narrate(event)
        self._alerts.appendleft(alert)
        self._alert_count += 1

        sev_label = alert.severity_label
        logger.info("Alert [%s] %s: %s", sev_label, alert.event_type, alert.headline)

    async def _narrate(self, event: Event) -> PlainAlert:
        """Build a PlainAlert from a raw Event."""
        sev = event.severity
        sev_label, sev_icon = SEVERITY_LABELS.get(sev, ("Unknown", "❓"))
        narrative = NARRATIVES.get(event.type, {})
        data = event.data if isinstance(event.data, dict) else {}

        # Build headline from event data
        headline = self._build_headline(event)
        plain = narrative.get("plain", "A security event was detected.")
        action = narrative.get("action", "Review the event details.")
        technical = self._build_technical(event)

        # Try AI enrichment for high-severity events (non-blocking)
        if sev >= 4 and self._ai:
            try:
                ai_plain = await asyncio.wait_for(
                    self._ai_narrate(event, headline, technical),
                    timeout=5,
                )
                if ai_plain:
                    plain = ai_plain
            except (asyncio.TimeoutError, Exception) as e:
                logger.debug("AI narration skipped: %s", e)

        return PlainAlert(
            id=event.id,
            timestamp=event.timestamp,
            severity=sev,
            severity_label=sev_label,
            severity_icon=sev_icon,
            headline=headline,
            plain=plain,
            action=action,
            technical=technical,
            event_type=event.type.value,
            source=event.source,
            data=data,
        )

    def _build_headline(self, event: Event) -> str:
        """Generate a one-line headline from event data."""
        data = event.data if isinstance(event.data, dict) else {}
        etype = event.type

        if etype == EventType.PROCESS_SUSPICIOUS:
            name = data.get("name", data.get("process_name", "Unknown process"))
            return f"Suspicious program detected: {name}"

        if etype == EventType.CHAIN_DETECTED:
            rule = data.get("rule", "Unknown pattern")
            count = data.get("event_count", 0)
            return f"Attack pattern detected: {rule} ({count} linked events)"

        if etype == EventType.IOC_MATCH:
            ioc = data.get("indicator", data.get("ioc", "unknown"))
            return f"Known threat indicator matched: {ioc}"

        if etype == EventType.HOST_DISCOVERED:
            ip = data.get("ip", data.get("address", "unknown"))
            return f"New device on network: {ip}"

        if etype == EventType.HOST_LOST:
            ip = data.get("ip", data.get("address", "unknown"))
            return f"Device left network: {ip}"

        if etype in (EventType.FILE_CREATED, EventType.FILE_MODIFIED, EventType.FILE_DELETED):
            path = data.get("path", data.get("file_path", "unknown file"))
            action_word = {
                EventType.FILE_CREATED: "created",
                EventType.FILE_MODIFIED: "modified",
                EventType.FILE_DELETED: "deleted",
            }[etype]
            return f"File {action_word}: {path}"

        if etype == EventType.REGISTRY_CHANGE:
            key = data.get("key", data.get("registry_key", "unknown key"))
            return f"Registry modified: {key}"

        if etype == EventType.TRAFFIC_ANOMALY:
            return "Unusual network traffic pattern detected"

        if etype == EventType.CONNECTION_SUSPICIOUS:
            dst = data.get("destination", data.get("remote_addr", "unknown"))
            return f"Suspicious outbound connection to {dst}"

        if etype == EventType.ALERT:
            return data.get("description", "Security alert triggered")

        return f"Security event: {etype.value}"

    def _build_technical(self, event: Event) -> str:
        """Build a technical detail string for security professionals."""
        data = event.data if isinstance(event.data, dict) else {}
        parts = [f"Event: {event.type.value}", f"Source: {event.source}", f"Severity: {event.severity}/5"]

        if "mitre_tactics" in data:
            parts.append(f"MITRE Tactics: {', '.join(data['mitre_tactics'])}")
        if "mitre_techniques" in data:
            parts.append(f"MITRE Techniques: {', '.join(data['mitre_techniques'])}")
        if "rule" in data:
            parts.append(f"Rule: {data['rule']}")
        if "pid" in data:
            parts.append(f"PID: {data['pid']}")
        if "path" in data or "file_path" in data:
            parts.append(f"Path: {data.get('path', data.get('file_path', ''))}")
        if "cmdline" in data:
            parts.append(f"Command: {data['cmdline']}")
        if "hash" in data:
            parts.append(f"Hash: {data['hash']}")

        return " | ".join(parts)

    async def _ai_narrate(self, event: Event, headline: str, technical: str) -> str | None:
        """Use AI to generate a richer plain-language explanation."""
        if not self._ai:
            return None

        prompt = (
            f"You are a security assistant explaining alerts to non-technical users.\n"
            f"Explain this security alert in 2-3 simple sentences. No jargon.\n\n"
            f"Alert: {headline}\n"
            f"Technical: {technical}\n\n"
            f"Plain English explanation:"
        )
        try:
            response = await self._ai.generate(prompt, max_tokens=150)
            return response.strip() if response else None
        except Exception:
            return None

    # ── Public API ─────────────────────────────────────────────────────

    def get_alerts(self, limit: int = 50, include_dismissed: bool = False) -> list[dict]:
        """Get recent alerts as dicts."""
        alerts = list(self._alerts)
        if not include_dismissed:
            alerts = [a for a in alerts if not a.dismissed]
        return [a.to_dict() for a in alerts[:limit]]

    def dismiss(self, alert_id: str) -> bool:
        """Dismiss an alert by ID."""
        for a in self._alerts:
            if a.id == alert_id:
                a.dismissed = True
                return True
        return False

    def get_summary(self) -> dict[str, Any]:
        """Get alert summary stats."""
        active = [a for a in self._alerts if not a.dismissed]
        by_severity: dict[str, int] = {}
        for a in active:
            by_severity[a.severity_label] = by_severity.get(a.severity_label, 0) + 1

        return {
            "total": len(self._alerts),
            "active": len(active),
            "dismissed": len(self._alerts) - len(active),
            "by_severity": by_severity,
            "latest": active[0].to_dict() if active else None,
        }

    @property
    def alert_count(self) -> int:
        return self._alert_count
