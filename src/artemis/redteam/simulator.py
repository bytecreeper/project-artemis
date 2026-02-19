"""Adversary Simulation — test defenses with MITRE ATT&CK techniques.

Runs safe, non-destructive simulations of common attack techniques to verify
that Artemis EDR, correlation engine, and threat classifier detect them.

This is NOT exploitation — it's defense validation. Every technique:
1. Simulates observable behavior (creates files, registry keys, etc.)
2. Checks if Artemis detected it
3. Cleans up artifacts
4. Reports detection coverage gaps

Inspired by Repello AI (automated red teaming) and LMNTRIX (adversary simulation).
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("artemis.redteam")


class SimStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DETECTED = "detected"
    MISSED = "missed"
    ERROR = "error"
    CLEANED = "cleaned"


@dataclass
class SimResult:
    """Result of a single technique simulation."""
    id: str = field(default_factory=lambda: f"sim-{uuid.uuid4().hex[:8]}")
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    description: str = ""
    status: SimStatus = SimStatus.PENDING
    detected: bool = False
    detection_source: str = ""  # Which component detected it
    artifacts_created: list[str] = field(default_factory=list)
    artifacts_cleaned: bool = False
    duration_seconds: float = 0.0
    error: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class SimCampaign:
    """A full adversary simulation campaign."""
    id: str = field(default_factory=lambda: f"campaign-{uuid.uuid4().hex[:8]}")
    started: float = field(default_factory=time.time)
    results: list[SimResult] = field(default_factory=list)
    status: str = "running"
    duration_seconds: float = 0.0

    @property
    def detected_count(self) -> int:
        return sum(1 for r in self.results if r.detected)

    @property
    def missed_count(self) -> int:
        return sum(1 for r in self.results if r.status == SimStatus.MISSED)

    @property
    def coverage_pct(self) -> float:
        total = len(self.results)
        if total == 0:
            return 0
        return (self.detected_count / total) * 100

    def summary(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "techniques_run": len(self.results),
            "detected": self.detected_count,
            "missed": self.missed_count,
            "coverage_pct": round(self.coverage_pct, 1),
            "duration_seconds": self.duration_seconds,
        }


class AdversarySimulator:
    """Runs MITRE ATT&CK technique simulations against the local endpoint."""

    def __init__(self, db=None, event_bus=None):
        self.db = db
        self.bus = event_bus
        self.campaigns: list[SimCampaign] = []
        self._temp_dir = Path(tempfile.gettempdir()) / "artemis_sim"

    async def run_campaign(self, techniques: list[str] | None = None) -> SimCampaign:
        """Run a full simulation campaign."""
        campaign = SimCampaign()
        self._temp_dir.mkdir(exist_ok=True)

        # All available techniques
        all_techniques = {
            "T1059.001": self._sim_powershell_execution,
            "T1059.003": self._sim_cmd_execution,
            "T1547.001": self._sim_registry_persistence,
            "T1105": self._sim_file_download,
            "T1046": self._sim_port_scan,
            "T1057": self._sim_process_discovery,
            "T1082": self._sim_system_info_discovery,
            "T1083": self._sim_file_discovery,
            "T1070.004": self._sim_indicator_removal,
            "T1053.005": self._sim_scheduled_task,
            "T1218.011": self._sim_rundll32,
            "T1003": self._sim_credential_access_indicator,
        }

        to_run = all_techniques
        if techniques:
            to_run = {k: v for k, v in all_techniques.items() if k in techniques}

        for tech_id, sim_fn in to_run.items():
            result = SimResult(technique_id=tech_id)
            start = time.time()
            try:
                result.status = SimStatus.RUNNING
                result = await sim_fn(result)

                # Wait briefly for detection
                await asyncio.sleep(2)

                # Check if Artemis detected it
                result = await self._check_detection(result)

            except Exception as e:
                result.status = SimStatus.ERROR
                result.error = str(e)
                logger.error("Simulation %s failed: %s", tech_id, e)
            finally:
                result.duration_seconds = time.time() - start
                # Clean up artifacts
                await self._cleanup(result)

            campaign.results.append(result)

        campaign.status = "complete"
        campaign.duration_seconds = time.time() - campaign.started
        self.campaigns.append(campaign)

        detected = campaign.detected_count
        total = len(campaign.results)
        logger.info(
            "Campaign %s complete — %d/%d detected (%.0f%% coverage)",
            campaign.id, detected, total, campaign.coverage_pct
        )
        return campaign

    # ── Technique Simulations ─────────────────────────────────────────

    async def _sim_powershell_execution(self, result: SimResult) -> SimResult:
        """T1059.001 — PowerShell execution (benign command)."""
        result.technique_name = "PowerShell Execution"
        result.tactic = "Execution"
        result.description = "Executes a PowerShell command to test script execution detection."

        out_file = self._temp_dir / "ps_sim_output.txt"
        cmd = f'powershell -Command "Write-Output \'Artemis simulation test\' | Out-File -FilePath \'{out_file}\'"'
        await asyncio.to_thread(self._run_cmd, cmd)
        result.artifacts_created.append(str(out_file))
        return result

    async def _sim_cmd_execution(self, result: SimResult) -> SimResult:
        """T1059.003 — Windows Command Shell."""
        result.technique_name = "Windows Command Shell"
        result.tactic = "Execution"
        result.description = "Uses cmd.exe to execute commands, testing command shell monitoring."

        out_file = self._temp_dir / "cmd_sim_output.txt"
        cmd = f'cmd /c "echo Artemis simulation test > {out_file}"'
        await asyncio.to_thread(self._run_cmd, cmd)
        result.artifacts_created.append(str(out_file))
        return result

    async def _sim_registry_persistence(self, result: SimResult) -> SimResult:
        """T1547.001 — Registry Run key persistence."""
        result.technique_name = "Registry Run Key Persistence"
        result.tactic = "Persistence"
        result.description = "Creates a registry Run key entry to test persistence detection."

        key_name = "ArtemisSimTest"
        cmd = f'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v {key_name} /t REG_SZ /d "C:\\artemis_sim_test.exe" /f'
        await asyncio.to_thread(self._run_cmd, cmd)
        result.artifacts_created.append(f"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{key_name}")
        return result

    async def _sim_file_download(self, result: SimResult) -> SimResult:
        """T1105 — Ingress Tool Transfer (simulated)."""
        result.technique_name = "Ingress Tool Transfer"
        result.tactic = "Command and Control"
        result.description = "Creates a file in temp directory simulating a downloaded tool."

        fake_tool = self._temp_dir / "simulated_download.exe"
        fake_tool.write_bytes(b"MZ" + b"\x00" * 100 + b"ARTEMIS_SIM_TEST")
        result.artifacts_created.append(str(fake_tool))
        return result

    async def _sim_port_scan(self, result: SimResult) -> SimResult:
        """T1046 — Network Service Discovery."""
        result.technique_name = "Network Service Discovery"
        result.tactic = "Discovery"
        result.description = "Scans common ports on localhost to test network scan detection."

        import socket
        for port in [22, 80, 443, 445, 3389]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect_ex(("127.0.0.1", port))
                s.close()
            except Exception:
                pass
        return result

    async def _sim_process_discovery(self, result: SimResult) -> SimResult:
        """T1057 — Process Discovery."""
        result.technique_name = "Process Discovery"
        result.tactic = "Discovery"
        result.description = "Enumerates running processes using tasklist."

        out_file = self._temp_dir / "process_list.txt"
        cmd = f'tasklist /v > "{out_file}"'
        await asyncio.to_thread(self._run_cmd, cmd)
        result.artifacts_created.append(str(out_file))
        return result

    async def _sim_system_info_discovery(self, result: SimResult) -> SimResult:
        """T1082 — System Information Discovery."""
        result.technique_name = "System Information Discovery"
        result.tactic = "Discovery"
        result.description = "Gathers system information using systeminfo."

        out_file = self._temp_dir / "sysinfo_sim.txt"
        cmd = f'systeminfo > "{out_file}"'
        await asyncio.to_thread(self._run_cmd, cmd)
        result.artifacts_created.append(str(out_file))
        return result

    async def _sim_file_discovery(self, result: SimResult) -> SimResult:
        """T1083 — File and Directory Discovery."""
        result.technique_name = "File and Directory Discovery"
        result.tactic = "Discovery"
        result.description = "Enumerates files in sensitive directories."

        out_file = self._temp_dir / "file_enum_sim.txt"
        cmd = f'dir /s /b "C:\\Users\\*password*" > "{out_file}" 2>nul'
        await asyncio.to_thread(self._run_cmd, cmd)
        result.artifacts_created.append(str(out_file))
        return result

    async def _sim_indicator_removal(self, result: SimResult) -> SimResult:
        """T1070.004 — File Deletion (indicator removal)."""
        result.technique_name = "Indicator Removal: File Deletion"
        result.tactic = "Defense Evasion"
        result.description = "Creates and then deletes a file to test FIM detection."

        canary = self._temp_dir / "canary_file.txt"
        canary.write_text("This file will be deleted to test detection")
        result.artifacts_created.append(str(canary))
        await asyncio.sleep(1)
        canary.unlink(missing_ok=True)
        return result

    async def _sim_scheduled_task(self, result: SimResult) -> SimResult:
        """T1053.005 — Scheduled Task creation."""
        result.technique_name = "Scheduled Task"
        result.tactic = "Persistence"
        result.description = "Creates a scheduled task to test persistence detection."

        task_name = "ArtemisSimTask"
        cmd = f'schtasks /create /tn "{task_name}" /tr "cmd /c echo test" /sc once /st 23:59 /f'
        await asyncio.to_thread(self._run_cmd, cmd)
        result.artifacts_created.append(f"schtask:{task_name}")
        return result

    async def _sim_rundll32(self, result: SimResult) -> SimResult:
        """T1218.011 — Rundll32 proxy execution."""
        result.technique_name = "Rundll32 Proxy Execution"
        result.tactic = "Defense Evasion"
        result.description = "Uses rundll32.exe to execute a benign DLL function."

        # Use a known-safe Windows DLL function
        cmd = 'rundll32.exe shell32.dll,Control_RunDLL'
        await asyncio.to_thread(self._run_cmd, cmd, timeout=3)
        return result

    async def _sim_credential_access_indicator(self, result: SimResult) -> SimResult:
        """T1003 — OS Credential Dumping (indicator only)."""
        result.technique_name = "Credential Access Indicator"
        result.tactic = "Credential Access"
        result.description = "Creates a file named like credential dump tools to test static detection."

        # Just create a file with a suspicious name — no actual credential access
        fake = self._temp_dir / "mimikatz_sim.log"
        fake.write_text("ARTEMIS SIMULATION - NOT REAL MIMIKATZ\nThis tests filename-based detection.")
        result.artifacts_created.append(str(fake))
        return result

    # ── Detection Check ───────────────────────────────────────────────

    async def _check_detection(self, result: SimResult) -> SimResult:
        """Check if Artemis detected the simulated technique."""
        if not self.db:
            result.status = SimStatus.MISSED
            return result

        # Search for related events in the last 30 seconds
        try:
            import json
            rows = self.db.search_events(
                result.technique_id,
                limit=5, hours=1,
            )
            if not rows:
                # Also search by technique name keywords
                keywords = result.technique_name.lower().split()
                for kw in keywords[:2]:
                    rows = self.db.search_events(kw, limit=5, hours=1)
                    if rows:
                        break

            # Also check for process events matching our simulation
            for artifact in result.artifacts_created:
                if artifact.endswith((".exe", ".txt", ".log")):
                    name = Path(artifact).name
                    proc_rows = self.db.search_events(name, limit=5, hours=1)
                    if proc_rows:
                        rows = (rows or []) + list(proc_rows)

            if rows:
                result.detected = True
                result.status = SimStatus.DETECTED
                result.detection_source = "event_bus"
            else:
                result.status = SimStatus.MISSED

        except Exception as e:
            logger.debug("Detection check error: %s", e)
            result.status = SimStatus.MISSED

        return result

    # ── Cleanup ───────────────────────────────────────────────────────

    async def _cleanup(self, result: SimResult) -> None:
        """Remove all artifacts created by the simulation."""
        for artifact in result.artifacts_created:
            try:
                if artifact.startswith("HKCU\\") or artifact.startswith("HKLM\\"):
                    # Registry cleanup
                    parts = artifact.rsplit("\\", 1)
                    if len(parts) == 2:
                        key_path, value_name = parts
                        cmd = f'reg delete "{key_path}" /v {value_name} /f'
                        await asyncio.to_thread(self._run_cmd, cmd)
                elif artifact.startswith("schtask:"):
                    task_name = artifact.split(":", 1)[1]
                    cmd = f'schtasks /delete /tn "{task_name}" /f'
                    await asyncio.to_thread(self._run_cmd, cmd)
                else:
                    p = Path(artifact)
                    if p.exists():
                        p.unlink()
            except Exception as e:
                logger.debug("Cleanup failed for %s: %s", artifact, e)

        result.artifacts_cleaned = True

    # ── Helpers ────────────────────────────────────────────────────────

    def _run_cmd(self, cmd: str, timeout: int = 10) -> str:
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return ""
        except Exception as e:
            return str(e)

    def to_dict(self, campaign: SimCampaign) -> dict:
        return {
            **campaign.summary(),
            "results": [
                {
                    "id": r.id,
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "tactic": r.tactic,
                    "description": r.description,
                    "status": r.status.value,
                    "detected": r.detected,
                    "detection_source": r.detection_source,
                    "artifacts_cleaned": r.artifacts_cleaned,
                    "duration_seconds": round(r.duration_seconds, 2),
                    "error": r.error,
                }
                for r in campaign.results
            ],
        }
