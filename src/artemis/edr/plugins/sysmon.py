"""Sysmon event ingestion plugin.

Reads Sysmon events from the Windows Event Log, parses them,
and publishes structured events to the bus.
"""

from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Any

from artemis.core.events import Event, EventBus, EventType
from artemis.edr.plugin_base import EDRPlugin

logger = logging.getLogger("artemis.edr.sysmon")

# Sysmon Event ID → our event type mapping
SYSMON_MAP: dict[int, EventType] = {
    1: EventType.PROCESS_START,       # Process Create
    5: EventType.PROCESS_STOP,        # Process Terminate
    11: EventType.FILE_CREATED,       # File Create
    13: EventType.REGISTRY_CHANGE,    # Registry value set
    3: EventType.CONNECTION_SUSPICIOUS,  # Network Connection (initially)
}


class SysmonPlugin(EDRPlugin):
    name = "sysmon"
    description = "Ingest and parse Sysmon events from Windows Event Log"
    produces = [
        EventType.PROCESS_START,
        EventType.PROCESS_STOP,
        EventType.SYSMON_EVENT,
        EventType.FILE_CREATED,
        EventType.REGISTRY_CHANGE,
    ]
    consumes = []

    def __init__(self) -> None:
        self._bus: EventBus | None = None
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._events_processed = 0
        self._warned_access = False
        self._seen_ids: set[str] = set()  # dedup record IDs

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name="sysmon-poll")
        logger.info("Sysmon plugin started")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Sysmon plugin stopped (%d events processed)", self._events_processed)

    async def status(self) -> dict:
        return {
            "running": self._running,
            "events_processed": self._events_processed,
            "needs_admin": self._warned_access,
        }

    async def _poll_loop(self) -> None:
        """Poll Windows Event Log for new Sysmon events."""
        while self._running:
            try:
                events = await asyncio.to_thread(self._read_sysmon_events)
                for raw in events:
                    parsed = self._parse_event(raw)
                    if parsed and self._bus:
                        rid = parsed.data.get("record_id") or parsed.id
                        if rid not in self._seen_ids:
                            self._seen_ids.add(rid)
                            await self._bus.publish(parsed)
                            self._events_processed += 1
                # Cap seen set
                if len(self._seen_ids) > 5000:
                    self._seen_ids = set(list(self._seen_ids)[-2500:])
            except Exception:
                logger.exception("Sysmon poll error")
            await asyncio.sleep(2)

    def _read_sysmon_events(self) -> list[str]:
        """Read recent Sysmon events from Windows Event Log.

        Tries win32evtlog first (pip install pywin32), then wevtutil CLI.
        Both require admin/elevated privileges to read Sysmon logs.
        """
        # Try pywin32 first
        try:
            import win32evtlog  # type: ignore
            query = "*[System[TimeCreated[timediff(@SystemTime) <= 5000]]]"
            handle = win32evtlog.EvtQuery(
                "Microsoft-Windows-Sysmon/Operational",
                win32evtlog.EvtQueryReverseDirection,
                query,
            )
            results = []
            while True:
                events = win32evtlog.EvtNext(handle, 50, -1, 0)
                if not events:
                    break
                for event in events:
                    results.append(win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml))
            return results[:50]
        except ImportError:
            pass
        except Exception as e:
            if not self._warned_access:
                logger.warning("Sysmon: win32evtlog failed: %s (need admin?)", e)
                self._warned_access = True
            return []

        # Fallback: wevtutil CLI
        import subprocess
        try:
            result = subprocess.run(
                ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
                 "/c:50", "/rd:true", "/f:xml"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                if not self._warned_access:
                    logger.warning("Sysmon: wevtutil failed (need admin?): %s",
                                   result.stderr.strip()[:100])
                    self._warned_access = True
                return []
            if result.stdout.strip():
                xml_str = f"<Events>{result.stdout}</Events>"
                root = ET.fromstring(xml_str)
                return [ET.tostring(e, encoding="unicode") for e in root]
        except (subprocess.TimeoutExpired, FileNotFoundError, ET.ParseError) as e:
            if not self._warned_access:
                logger.warning("Sysmon: CLI fallback failed: %s", e)
                self._warned_access = True
        return []

    def _parse_event(self, xml_str: str) -> Event | None:
        """Parse a single Sysmon XML event into our Event model."""
        try:
            root = ET.fromstring(xml_str)
            ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            event_id_el = root.find(".//ns:EventID", ns)
            if event_id_el is None or event_id_el.text is None:
                return None
            
            event_id = int(event_id_el.text)
            event_type = SYSMON_MAP.get(event_id, EventType.SYSMON_EVENT)

            # Get record ID for dedup
            record_el = root.find(".//ns:EventRecordID", ns)
            record_id = record_el.text if record_el is not None and record_el.text else None

            # Extract EventData fields
            data: dict[str, Any] = {"sysmon_event_id": event_id, "record_id": record_id}
            for el in root.findall(".//ns:Data", ns):
                name = el.get("Name", "unknown")
                data[name] = el.text or ""

            return Event(
                type=event_type,
                data=data,
                source="sysmon",
                severity=self._estimate_severity(event_id, data),
            )
        except ET.ParseError:
            logger.warning("Failed to parse Sysmon event XML")
            return None

    def _estimate_severity(self, event_id: int, data: dict[str, Any]) -> int:
        """Quick severity estimate based on event type and data."""
        # Process creation with suspicious indicators
        if event_id == 1:
            cmd = data.get("CommandLine", "").lower()
            suspicious = ["powershell -enc", "cmd /c", "certutil", "bitsadmin",
                         "mshta", "regsvr32", "rundll32", "wscript", "cscript"]
            if any(s in cmd for s in suspicious):
                return 3  # high
            return 0
        # Network connections
        if event_id == 3:
            return 1  # low — correlation engine will escalate if needed
        return 0
