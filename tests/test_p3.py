"""P3 — Adversary Simulation tests."""

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path

from artemis.redteam.simulator import (
    AdversarySimulator, SimCampaign, SimResult, SimStatus,
)


# ── Data classes ──────────────────────────────────────────────────────

def test_sim_result_defaults():
    r = SimResult()
    assert r.status == SimStatus.PENDING
    assert r.detected is False
    assert r.artifacts_created == []
    assert r.id.startswith("sim-")


def test_sim_campaign_empty():
    c = SimCampaign()
    assert c.coverage_pct == 0
    assert c.detected_count == 0
    assert c.missed_count == 0
    assert c.id.startswith("campaign-")


def test_campaign_summary_counts():
    c = SimCampaign()
    c.results = [
        SimResult(detected=True, status=SimStatus.DETECTED),
        SimResult(detected=False, status=SimStatus.MISSED),
        SimResult(detected=True, status=SimStatus.DETECTED),
    ]
    assert c.detected_count == 2
    assert c.missed_count == 1
    assert c.coverage_pct == pytest.approx(66.67, rel=0.1)
    s = c.summary()
    assert s["techniques_run"] == 3
    assert s["detected"] == 2


def test_sim_status_values():
    assert SimStatus.PENDING == "pending"
    assert SimStatus.DETECTED == "detected"
    assert SimStatus.MISSED == "missed"
    assert SimStatus.ERROR == "error"


# ── Simulator init ────────────────────────────────────────────────────

def test_simulator_init():
    sim = AdversarySimulator()
    assert sim.db is None
    assert sim.bus is None
    assert sim.campaigns == []


def test_simulator_init_with_deps():
    db = MagicMock()
    bus = MagicMock()
    sim = AdversarySimulator(db=db, event_bus=bus)
    assert sim.db is db
    assert sim.bus is bus


# ── Campaign run (mocked) ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_campaign_single_technique():
    """Run one technique with mocked subprocess."""
    sim = AdversarySimulator()
    with patch.object(sim, "_run_cmd", return_value=""):
        campaign = await sim.run_campaign(techniques=["T1057"])

    assert campaign.status == "complete"
    assert len(campaign.results) == 1
    r = campaign.results[0]
    assert r.technique_id == "T1057"
    assert r.technique_name == "Process Discovery"
    assert r.tactic == "Discovery"
    assert r.duration_seconds > 0


@pytest.mark.asyncio
async def test_run_campaign_all_techniques():
    """Run all 12 techniques."""
    sim = AdversarySimulator()
    with patch.object(sim, "_run_cmd", return_value=""):
        campaign = await sim.run_campaign()

    assert len(campaign.results) == 12
    assert campaign.status == "complete"
    ids = {r.technique_id for r in campaign.results}
    assert "T1059.001" in ids
    assert "T1003" in ids


@pytest.mark.asyncio
async def test_campaign_with_detection():
    """Verify detection works when db returns matching events."""
    db = MagicMock()
    db.search_events = MagicMock(return_value=[{"id": "e1", "data": "test"}])
    sim = AdversarySimulator(db=db)

    with patch.object(sim, "_run_cmd", return_value=""):
        campaign = await sim.run_campaign(techniques=["T1057"])

    r = campaign.results[0]
    assert r.detected is True
    assert r.status == SimStatus.DETECTED


@pytest.mark.asyncio
async def test_campaign_no_db_means_missed():
    """Without DB, all techniques should be MISSED."""
    sim = AdversarySimulator(db=None)
    with patch.object(sim, "_run_cmd", return_value=""):
        campaign = await sim.run_campaign(techniques=["T1082"])

    assert campaign.results[0].status == SimStatus.MISSED
    assert campaign.results[0].detected is False


@pytest.mark.asyncio
async def test_campaign_error_handling():
    """Technique that throws should get ERROR status."""
    sim = AdversarySimulator()

    async def _boom(result):
        raise RuntimeError("kaboom")

    sim._sim_process_discovery = _boom
    with patch.object(sim, "_run_cmd", return_value=""):
        campaign = await sim.run_campaign(techniques=["T1057"])

    r = campaign.results[0]
    assert r.status == SimStatus.ERROR
    assert "kaboom" in r.error


# ── to_dict serialization ────────────────────────────────────────────

def test_to_dict():
    sim = AdversarySimulator()
    c = SimCampaign()
    c.results = [
        SimResult(
            technique_id="T1059.001",
            technique_name="PowerShell Execution",
            tactic="Execution",
            detected=True,
            status=SimStatus.DETECTED,
            detection_source="event_bus",
            duration_seconds=1.234,
        )
    ]
    d = sim.to_dict(c)
    assert d["techniques_run"] == 1
    assert d["detected"] == 1
    assert len(d["results"]) == 1
    assert d["results"][0]["technique_id"] == "T1059.001"
    assert d["results"][0]["detected"] is True
    assert d["results"][0]["status"] == "detected"


# ── Cleanup ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cleanup_files(tmp_path):
    sim = AdversarySimulator()
    f = tmp_path / "artifact.txt"
    f.write_text("test")
    r = SimResult(artifacts_created=[str(f)])
    await sim._cleanup(r)
    assert not f.exists()
    assert r.artifacts_cleaned is True


@pytest.mark.asyncio
async def test_cleanup_registry():
    """Registry cleanup calls reg delete."""
    sim = AdversarySimulator()
    r = SimResult(artifacts_created=[
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\ArtemisSimTest"
    ])
    with patch.object(sim, "_run_cmd", return_value="") as mock:
        await sim._cleanup(r)
    mock.assert_called_once()
    assert "reg delete" in mock.call_args[0][0]


@pytest.mark.asyncio
async def test_cleanup_schtask():
    """Scheduled task cleanup calls schtasks /delete."""
    sim = AdversarySimulator()
    r = SimResult(artifacts_created=["schtask:ArtemisSimTask"])
    with patch.object(sim, "_run_cmd", return_value="") as mock:
        await sim._cleanup(r)
    assert "schtasks /delete" in mock.call_args[0][0]


# ── Campaign stored in history ────────────────────────────────────────

@pytest.mark.asyncio
async def test_campaigns_stored():
    sim = AdversarySimulator()
    with patch.object(sim, "_run_cmd", return_value=""):
        await sim.run_campaign(techniques=["T1082"])
        await sim.run_campaign(techniques=["T1057"])
    assert len(sim.campaigns) == 2


# ── API routes (via httpx) ────────────────────────────────────────────

@pytest.fixture
def client():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from artemis.web.app import create_app
    from httpx import AsyncClient, ASGITransport
    app = create_app()
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_api_techniques_list(client):
    async with client as c:
        r = await c.get("/api/simulate/techniques")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 12
    assert data[0]["id"]


@pytest.mark.asyncio
async def test_api_simulate_history(client):
    async with client as c:
        r = await c.get("/api/simulate/history")
    # 200 with empty list if state initialized, 503 if no lifespan ran
    assert r.status_code in (200, 503)


@pytest.mark.asyncio
async def test_simulate_page(client):
    async with client as c:
        r = await c.get("/simulate")
    assert r.status_code == 200
    assert b"ADVERSARY SIMULATION" in r.content
