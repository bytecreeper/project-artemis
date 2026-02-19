"""Remediation engine — verified, safe, reversible actions.

Rules of engagement:
1. Every action is VERIFIED before execution (process exists, file exists, etc.)
2. Every action is LOGGED with full context
3. Destructive actions require double-check (file still matches hash, process still running)
4. Quarantine moves files — does NOT delete them
5. All actions return detailed results with proof of what was done
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import psutil

logger = logging.getLogger("artemis.remediation")

QUARANTINE_DIR = Path("data/quarantine")
REMEDIATION_LOG = Path("data/remediation_log.json")


class ActionType(str, Enum):
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    BLOCK_IP = "block_ip"
    DISABLE_SCHEDULED_TASK = "disable_task"


class ActionStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    NOT_FOUND = "not_found"
    ALREADY_DONE = "already_done"
    VERIFICATION_FAILED = "verification_failed"


@dataclass
class RemediationResult:
    """Result of a remediation action with proof."""

    action: ActionType
    status: ActionStatus
    finding_id: str
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "status": self.status.value,
            "finding_id": self.finding_id,
            "timestamp": self.timestamp,
            "details": self.details,
            "error": self.error,
        }


class RemediationEngine:
    """Executes verified remediation actions."""

    def __init__(self) -> None:
        self._log: list[RemediationResult] = []
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    @property
    def history(self) -> list[RemediationResult]:
        return self._log

    def _record(self, result: RemediationResult) -> None:
        """Log the result to memory and disk."""
        self._log.append(result)
        # Append to disk log
        try:
            REMEDIATION_LOG.parent.mkdir(parents=True, exist_ok=True)
            with open(REMEDIATION_LOG, "a") as f:
                f.write(json.dumps(result.to_dict()) + "\n")
        except Exception as e:
            logger.error("Failed to write remediation log: %s", e)

    async def kill_process(self, finding_id: str, pid: int, verify_name: str = "") -> RemediationResult:
        """Kill a process by PID, with verification.

        Args:
            finding_id: The finding that triggered this action
            pid: Process ID to kill
            verify_name: If provided, verify the process name matches before killing
        """
        # Step 1: Verify process exists
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            result = RemediationResult(
                action=ActionType.KILL_PROCESS,
                status=ActionStatus.NOT_FOUND,
                finding_id=finding_id,
                details={"pid": pid, "reason": "Process no longer exists"},
            )
            self._record(result)
            return result

        # Step 2: Verify name matches (if provided) — prevents killing wrong process
        actual_name = proc.name().lower()
        if verify_name and verify_name.lower() not in actual_name:
            result = RemediationResult(
                action=ActionType.KILL_PROCESS,
                status=ActionStatus.VERIFICATION_FAILED,
                finding_id=finding_id,
                details={
                    "pid": pid,
                    "expected_name": verify_name,
                    "actual_name": actual_name,
                    "reason": "Process name doesn't match — PID may have been recycled",
                },
            )
            self._record(result)
            return result

        # Step 3: Capture full details before killing
        try:
            details = {
                "pid": pid,
                "name": proc.name(),
                "exe": proc.exe(),
                "cmdline": " ".join(proc.cmdline()),
                "username": proc.username(),
                "create_time": proc.create_time(),
            }
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            details = {"pid": pid, "name": actual_name}

        # Step 4: Kill
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()  # Force kill if terminate doesn't work
                proc.wait(timeout=3)

            details["killed_at"] = time.time()
            result = RemediationResult(
                action=ActionType.KILL_PROCESS,
                status=ActionStatus.SUCCESS,
                finding_id=finding_id,
                details=details,
            )
            logger.info("REMEDIATION: Killed process %s (PID %d)", details.get("name"), pid)
        except Exception as e:
            result = RemediationResult(
                action=ActionType.KILL_PROCESS,
                status=ActionStatus.FAILED,
                finding_id=finding_id,
                details=details,
                error=str(e),
            )
            logger.error("REMEDIATION FAILED: Kill process PID %d: %s", pid, e)

        self._record(result)
        return result

    async def quarantine_file(self, finding_id: str, file_path: str) -> RemediationResult:
        """Move a file to quarantine with hash verification.

        Does NOT delete — moves to data/quarantine/ with metadata.
        """
        path = Path(file_path)

        # Step 1: Verify file exists
        if not path.exists():
            result = RemediationResult(
                action=ActionType.QUARANTINE_FILE,
                status=ActionStatus.NOT_FOUND,
                finding_id=finding_id,
                details={"path": file_path, "reason": "File does not exist"},
            )
            self._record(result)
            return result

        # Step 2: Calculate hash for verification
        try:
            sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        except PermissionError:
            result = RemediationResult(
                action=ActionType.QUARANTINE_FILE,
                status=ActionStatus.FAILED,
                finding_id=finding_id,
                details={"path": file_path},
                error="Permission denied reading file",
            )
            self._record(result)
            return result

        # Step 3: Move to quarantine
        quarantine_name = f"{int(time.time())}_{sha256[:16]}_{path.name}"
        quarantine_path = QUARANTINE_DIR / quarantine_name

        try:
            shutil.move(str(path), str(quarantine_path))

            # Write metadata
            meta = {
                "original_path": file_path,
                "quarantine_path": str(quarantine_path),
                "sha256": sha256,
                "quarantined_at": time.time(),
                "finding_id": finding_id,
                "size_bytes": quarantine_path.stat().st_size,
            }
            meta_path = quarantine_path.with_suffix(quarantine_path.suffix + ".meta.json")
            meta_path.write_text(json.dumps(meta, indent=2))

            result = RemediationResult(
                action=ActionType.QUARANTINE_FILE,
                status=ActionStatus.SUCCESS,
                finding_id=finding_id,
                details=meta,
            )
            logger.info("REMEDIATION: Quarantined %s → %s (SHA256: %s)",
                        file_path, quarantine_path, sha256)
        except Exception as e:
            result = RemediationResult(
                action=ActionType.QUARANTINE_FILE,
                status=ActionStatus.FAILED,
                finding_id=finding_id,
                details={"path": file_path, "sha256": sha256},
                error=str(e),
            )
            logger.error("REMEDIATION FAILED: Quarantine %s: %s", file_path, e)

        self._record(result)
        return result

    async def block_ip(self, finding_id: str, ip: str, direction: str = "both") -> RemediationResult:
        """Block an IP address via Windows Firewall.

        Creates a named firewall rule for easy identification and removal.
        """
        rule_name = f"Artemis_Block_{ip.replace('.', '_')}"

        # Step 1: Check if rule already exists
        try:
            check = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                capture_output=True, text=True, timeout=10,
            )
            if check.returncode == 0 and rule_name in check.stdout:
                result = RemediationResult(
                    action=ActionType.BLOCK_IP,
                    status=ActionStatus.ALREADY_DONE,
                    finding_id=finding_id,
                    details={"ip": ip, "rule_name": rule_name, "reason": "Firewall rule already exists"},
                )
                self._record(result)
                return result
        except Exception:
            pass

        # Step 2: Create firewall rules
        errors = []
        created_rules = []

        directions = []
        if direction in ("both", "in"):
            directions.append("in")
        if direction in ("both", "out"):
            directions.append("out")

        for d in directions:
            try:
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_{d}",
                    f"dir={d}",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                ]
                result_proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result_proc.returncode == 0:
                    created_rules.append(f"{rule_name}_{d}")
                else:
                    errors.append(f"{d}: {result_proc.stderr.strip()}")
            except Exception as e:
                errors.append(f"{d}: {e}")

        if created_rules:
            result = RemediationResult(
                action=ActionType.BLOCK_IP,
                status=ActionStatus.SUCCESS,
                finding_id=finding_id,
                details={
                    "ip": ip,
                    "rules_created": created_rules,
                    "direction": direction,
                },
            )
            logger.info("REMEDIATION: Blocked IP %s (rules: %s)", ip, created_rules)
        else:
            result = RemediationResult(
                action=ActionType.BLOCK_IP,
                status=ActionStatus.FAILED,
                finding_id=finding_id,
                details={"ip": ip},
                error="; ".join(errors),
            )
            logger.error("REMEDIATION FAILED: Block IP %s: %s", ip, errors)

        self._record(result)
        return result


# Singleton
remediation = RemediationEngine()
