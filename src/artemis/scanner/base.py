"""Vulnerability scanner plugin base — modular, extensible scanning.

Inspired by CERT-Polska Artemis: each scanner is a self-contained module
that targets a specific check type. Scanners auto-register via __init_subclass__.

Results are VulnFindings — evidence-based, with remediation guidance.
"""

from __future__ import annotations

import abc
import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("artemis.scanner")


class VulnSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnCategory(str, Enum):
    OPEN_PORT = "open_port"
    WEAK_SERVICE = "weak_service"
    DEFAULT_CREDS = "default_credentials"
    MISSING_PATCH = "missing_patch"
    MISCONFIGURATION = "misconfiguration"
    EXPOSED_SERVICE = "exposed_service"
    WEAK_ENCRYPTION = "weak_encryption"
    INFO_DISCLOSURE = "information_disclosure"


@dataclass
class VulnFinding:
    """A vulnerability finding from a scanner module."""
    id: str = field(default_factory=lambda: f"vuln-{uuid.uuid4().hex[:8]}")
    scanner: str = ""
    target: str = ""  # IP, hostname, or path
    severity: VulnSeverity = VulnSeverity.INFO
    category: VulnCategory = VulnCategory.MISCONFIGURATION
    title: str = ""
    description: str = ""  # Plain language
    technical_detail: str = ""  # For security pros
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""  # What to do about it
    cve: str = ""  # CVE ID if applicable
    mitre_id: str = ""
    confidence: float = 1.0
    timestamp: float = field(default_factory=time.time)


class ScanTarget:
    """What to scan."""
    def __init__(self, host: str, ports: list[int] | None = None):
        self.host = host
        self.ports = ports or []


class ScannerPlugin(abc.ABC):
    """Base class for vulnerability scanner modules."""

    _registry: list[type[ScannerPlugin]] = []

    name: str = "base"
    description: str = ""
    category: str = "general"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.name != "base":
            ScannerPlugin._registry.append(cls)
            logger.debug("Registered scanner: %s", cls.name)

    @abc.abstractmethod
    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        """Run the scan against a target. Returns findings."""

    async def is_applicable(self, target: ScanTarget) -> bool:
        """Check if this scanner applies to the target."""
        return True


class ScanEngine:
    """Orchestrates scanner plugins against targets."""

    def __init__(self):
        self.scanners: list[ScannerPlugin] = []
        self.findings: list[VulnFinding] = []
        self._scan_history: list[dict] = []

    def load_scanners(self, names: list[str] | None = None) -> None:
        """Load scanner plugins. If names is None, load all registered."""
        for cls in ScannerPlugin._registry:
            if names is None or cls.name in names:
                self.scanners.append(cls())
                logger.info("Loaded scanner: %s", cls.name)

    async def scan_target(self, target: ScanTarget, rate_limit: float = 0) -> list[VulnFinding]:
        """Run all applicable scanners against a target."""
        results: list[VulnFinding] = []
        scan_start = time.time()

        for scanner in self.scanners:
            try:
                if not await scanner.is_applicable(target):
                    continue

                logger.info("Running %s against %s", scanner.name, target.host)
                findings = await scanner.scan(target)
                results.extend(findings)

                if rate_limit > 0:
                    await asyncio.sleep(rate_limit)

            except Exception as e:
                logger.error("Scanner %s failed on %s: %s", scanner.name, target.host, e)

        self.findings.extend(results)
        self._scan_history.append({
            "target": target.host,
            "scanners_run": len(self.scanners),
            "findings": len(results),
            "duration_seconds": time.time() - scan_start,
            "timestamp": time.time(),
        })

        return results

    async def scan_network(self, hosts: list[dict], rate_limit: float = 0.5) -> list[VulnFinding]:
        """Scan all discovered hosts."""
        all_findings: list[VulnFinding] = []
        for host_info in hosts:
            ip = host_info.get("ip", "")
            ports = host_info.get("open_ports", [])
            if isinstance(ports, str):
                import json
                try:
                    ports = json.loads(ports)
                except Exception:
                    ports = []
            target = ScanTarget(host=ip, ports=ports)
            findings = await self.scan_target(target, rate_limit=rate_limit)
            all_findings.extend(findings)
        return all_findings

    @property
    def scan_summary(self) -> dict:
        by_severity = {}
        for f in self.findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        return {
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "scanners_loaded": len(self.scanners),
            "scans_completed": len(self._scan_history),
        }
