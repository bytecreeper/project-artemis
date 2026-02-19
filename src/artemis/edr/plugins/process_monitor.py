"""Process monitoring plugin — real-time process tree tracking."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import psutil

from artemis.core.events import Event, EventBus, EventType
from artemis.edr.plugin_base import EDRPlugin

logger = logging.getLogger("artemis.edr.procmon")


class ProcessMonitorPlugin(EDRPlugin):
    name = "process_monitor"
    description = "Real-time process creation/termination monitoring via psutil"
    produces = [EventType.PROCESS_START, EventType.PROCESS_STOP, EventType.PROCESS_SUSPICIOUS]
    consumes = []

    def __init__(self) -> None:
        self._bus: EventBus | None = None
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._known_pids: set[int] = set()
        self._events_emitted = 0

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._running = True
        # Snapshot current processes
        self._known_pids = set(psutil.pids())
        self._task = asyncio.create_task(self._monitor_loop(), name="procmon")
        logger.info("Process monitor started (tracking %d existing processes)", len(self._known_pids))

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Process monitor stopped (%d events emitted)", self._events_emitted)

    async def status(self) -> dict:
        return {
            "running": self._running,
            "tracked_pids": len(self._known_pids),
            "events_emitted": self._events_emitted,
        }

    async def _monitor_loop(self) -> None:
        while self._running:
            try:
                current = set(psutil.pids())
                new_pids = current - self._known_pids
                dead_pids = self._known_pids - current

                for pid in new_pids:
                    info = await asyncio.to_thread(self._get_process_info, pid)
                    if info and self._bus:
                        severity = self._assess_risk(info)
                        event_type = EventType.PROCESS_SUSPICIOUS if severity >= 3 else EventType.PROCESS_START
                        await self._bus.publish(Event(
                            type=event_type,
                            data=info,
                            source="process_monitor",
                            severity=severity,
                        ))
                        self._events_emitted += 1

                for pid in dead_pids:
                    if self._bus:
                        await self._bus.publish(Event(
                            type=EventType.PROCESS_STOP,
                            data={"pid": pid},
                            source="process_monitor",
                            severity=0,
                        ))
                        self._events_emitted += 1

                self._known_pids = current
            except Exception:
                logger.exception("Process monitor error")

            await asyncio.sleep(2)

    def _get_process_info(self, pid: int) -> dict[str, Any] | None:
        try:
            proc = psutil.Process(pid)
            return {
                "pid": pid,
                "name": proc.name(),
                "exe": proc.exe() or "",
                "cmdline": " ".join(proc.cmdline()),
                "username": proc.username() or "",
                "ppid": proc.ppid(),
                "create_time": proc.create_time(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _assess_risk(self, info: dict[str, Any]) -> int:
        """Heuristic risk scoring for new processes."""
        score = 0
        cmd = info.get("cmdline", "").lower()
        exe = info.get("exe", "").lower()
        name = info.get("name", "").lower()

        # Living-off-the-land binaries
        lolbins = ["powershell", "cmd.exe", "wscript", "cscript", "mshta",
                   "certutil", "bitsadmin", "regsvr32", "rundll32", "msiexec"]
        if any(l in exe for l in lolbins):
            score += 1

        # Encoded commands
        if "-enc" in cmd or "-encodedcommand" in cmd or "frombase64" in cmd:
            score += 3

        # Unusual parent (e.g., Office spawning cmd)
        try:
            parent = psutil.Process(info.get("ppid", 0))
            parent_name = parent.name().lower()
            if parent_name in ("winword.exe", "excel.exe", "outlook.exe") and name in ("cmd.exe", "powershell.exe"):
                score += 3
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Temp directory execution
        if "\\temp\\" in exe or "\\tmp\\" in exe or "\\appdata\\local\\temp" in exe:
            score += 2

        return min(score, 4)  # cap at critical
