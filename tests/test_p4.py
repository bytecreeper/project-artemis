"""P4 — Plain-Language Alert Narrator tests."""

import asyncio
import time
import pytest
from unittest.mock import MagicMock, AsyncMock

from artemis.ai.alert_narrator import (
    AlertNarrator, PlainAlert, SEVERITY_LABELS, NARRATIVES,
)
from artemis.core.events import Event, EventBus, EventType


# ── PlainAlert dataclass ──────────────────────────────────────────────

def test_plain_alert_to_dict():
    a = PlainAlert(
        id="test-1", timestamp=1000.0, severity=3,
        severity_label="Medium", severity_icon="🟡",
        headline="Test headline", plain="Something happened",
        action="Check it out", technical="Event: edr.process.suspicious",
        event_type="edr.process.suspicious", source="process_monitor",
    )
    d = a.to_dict()
    assert d["id"] == "test-1"
    assert d["severity"] == 3
    assert d["headline"] == "Test headline"
    assert d["dismissed"] is False


def test_severity_labels():
    assert SEVERITY_LABELS[1][0] == "Info"
    assert SEVERITY_LABELS[5][0] == "Critical"
    assert len(SEVERITY_LABELS) == 5


def test_narratives_coverage():
    """All alert-worthy event types have narrative templates."""
    expected = [
        EventType.PROCESS_SUSPICIOUS, EventType.FILE_CREATED,
        EventType.FILE_MODIFIED, EventType.FILE_DELETED,
        EventType.CHAIN_DETECTED, EventType.ALERT,
        EventType.HOST_DISCOVERED, EventType.HOST_LOST,
        EventType.IOC_MATCH, EventType.TRAFFIC_ANOMALY,
        EventType.CONNECTION_SUSPICIOUS, EventType.REGISTRY_CHANGE,
    ]
    for et in expected:
        assert et in NARRATIVES, f"Missing narrative for {et}"


# ── Narrator init ─────────────────────────────────────────────────────

def test_narrator_init():
    n = AlertNarrator()
    assert n.alert_count == 0
    assert n.get_alerts() == []


def test_narrator_summary_empty():
    n = AlertNarrator()
    s = n.get_summary()
    assert s["total"] == 0
    assert s["active"] == 0
    assert s["latest"] is None


# ── Event narration ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_narrate_suspicious_process():
    n = AlertNarrator()
    bus = EventBus()
    await bus.start()
    await n.start(bus)

    event = Event(
        type=EventType.PROCESS_SUSPICIOUS,
        data={"name": "mimikatz.exe", "pid": 1234},
        source="process_monitor",
        severity=4,
    )
    await bus.publish(event)
    await asyncio.sleep(0.1)

    alerts = n.get_alerts()
    assert len(alerts) == 1
    a = alerts[0]
    assert "mimikatz.exe" in a["headline"]
    assert a["severity"] == 4
    assert a["severity_label"] == "High"
    assert a["plain"]  # Has plain-language text
    assert a["action"]  # Has action recommendation
    assert a["technical"]  # Has technical detail
    assert n.alert_count == 1


@pytest.mark.asyncio
async def test_narrate_chain_detected():
    n = AlertNarrator()
    bus = EventBus()
    await bus.start()
    await n.start(bus)

    event = Event(
        type=EventType.CHAIN_DETECTED,
        data={
            "rule": "Lateral Movement",
            "event_count": 5,
            "mitre_tactics": ["Lateral Movement"],
            "mitre_techniques": ["T1021"],
        },
        source="correlation",
        severity=5,
    )
    await bus.publish(event)
    await asyncio.sleep(0.1)

    alerts = n.get_alerts()
    assert len(alerts) == 1
    a = alerts[0]
    assert "Lateral Movement" in a["headline"]
    assert "5 linked events" in a["headline"]
    assert a["severity_label"] == "Critical"
    assert "attack" in a["plain"].lower()


@pytest.mark.asyncio
async def test_narrate_file_events():
    n = AlertNarrator()
    bus = EventBus()
    await bus.start()
    await n.start(bus)

    for etype, word in [
        (EventType.FILE_CREATED, "created"),
        (EventType.FILE_MODIFIED, "modified"),
        (EventType.FILE_DELETED, "deleted"),
    ]:
        await bus.publish(Event(
            type=etype,
            data={"path": "C:\\test\\file.txt"},
            source="file_integrity",
            severity=2,
        ))

    await asyncio.sleep(0.1)
    alerts = n.get_alerts()
    assert len(alerts) == 3


@pytest.mark.asyncio
async def test_narrate_host_discovered():
    n = AlertNarrator()
    bus = EventBus()
    await bus.start()
    await n.start(bus)

    await bus.publish(Event(
        type=EventType.HOST_DISCOVERED,
        data={"ip": "192.168.1.50"},
        source="network_scanner",
        severity=2,
    ))
    await asyncio.sleep(0.1)

    a = n.get_alerts()[0]
    assert "192.168.1.50" in a["headline"]


@pytest.mark.asyncio
async def test_narrate_ioc_match():
    n = AlertNarrator()
    bus = EventBus()
    await bus.start()
    await n.start(bus)

    await bus.publish(Event(
        type=EventType.IOC_MATCH,
        data={"indicator": "evil.com", "ioc_type": "domain"},
        source="threat_intel",
        severity=4,
    ))
    await asyncio.sleep(0.1)

    a = n.get_alerts()[0]
    assert "evil.com" in a["headline"]


# ── Dismiss ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dismiss_alert():
    n = AlertNarrator()
    bus = EventBus()
    await bus.start()
    await n.start(bus)

    await bus.publish(Event(
        type=EventType.ALERT,
        data={"description": "Test alert"},
        source="test",
        severity=2,
    ))
    await asyncio.sleep(0.1)

    alerts = n.get_alerts()
    assert len(alerts) == 1
    alert_id = alerts[0]["id"]

    assert n.dismiss(alert_id) is True
    assert n.get_alerts() == []  # Dismissed, filtered out
    assert len(n.get_alerts(include_dismissed=True)) == 1


def test_dismiss_nonexistent():
    n = AlertNarrator()
    assert n.dismiss("nope") is False


# ── Summary ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_summary_with_alerts():
    n = AlertNarrator()
    bus = EventBus()
    await bus.start()
    await n.start(bus)

    await bus.publish(Event(type=EventType.PROCESS_SUSPICIOUS, data={"name": "x"}, source="t", severity=4))
    await bus.publish(Event(type=EventType.FILE_CREATED, data={"path": "y"}, source="t", severity=2))
    await asyncio.sleep(0.1)

    s = n.get_summary()
    assert s["total"] == 2
    assert s["active"] == 2
    assert s["latest"] is not None
    assert "by_severity" in s


# ── Technical detail builder ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_technical_detail_includes_mitre():
    n = AlertNarrator()
    bus = EventBus()
    await bus.start()
    await n.start(bus)

    await bus.publish(Event(
        type=EventType.CHAIN_DETECTED,
        data={"rule": "Test", "mitre_tactics": ["Execution"], "mitre_techniques": ["T1059"], "event_count": 2},
        source="correlation",
        severity=4,
    ))
    await asyncio.sleep(0.1)

    a = n.get_alerts()[0]
    assert "T1059" in a["technical"]
    assert "Execution" in a["technical"]


# ── API routes ────────────────────────────────────────────────────────

@pytest.fixture
def client():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    # Disable auth for tests
    os.environ["ARTEMIS_WEB__AUTH_ENABLED"] = "false"
    from artemis.web.app import create_app
    app = create_app()
    from httpx import AsyncClient, ASGITransport
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_api_plain_alerts(client):
    async with client as c:
        r = await c.get("/api/alerts/plain")
    # 200 if lifespan ran, 503 without full startup
    assert r.status_code in (200, 503)


@pytest.mark.asyncio
async def test_api_alert_summary(client):
    async with client as c:
        r = await c.get("/api/alerts/summary")
    assert r.status_code in (200, 503)


@pytest.mark.asyncio
async def test_alerts_page(client):
    async with client as c:
        r = await c.get("/alerts")
    assert r.status_code == 200
    assert b"ALERTS" in r.content
    assert b"SIMPLE VIEW" in r.content or b"TECHNICAL VIEW" in r.content
