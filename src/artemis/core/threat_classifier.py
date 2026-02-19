"""Threat classifier — evidence-based, no hallucinations.

Every finding MUST have:
1. What was observed (the raw evidence)
2. Why it matters (the rule that matched)
3. Confidence level (how sure we are)
4. Suggested action (what can be done)

NO AI inference for threat classification. Rules are deterministic.
AI is only used for optional human-readable summaries AFTER classification.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from artemis.core.events import Event, EventBus, EventType

logger = logging.getLogger("artemis.classifier")


class FindingSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCategory(str, Enum):
    SUSPICIOUS_PROCESS = "suspicious_process"
    MALICIOUS_PROCESS = "malicious_process"
    FILE_TAMPERING = "file_tampering"
    NETWORK_ANOMALY = "network_anomaly"
    PERSISTENCE = "persistence"
    CREDENTIAL_ACCESS = "credential_access"
    DEFENSE_EVASION = "defense_evasion"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass
class Finding:
    """A verified security finding with evidence."""

    id: str
    timestamp: float
    category: FindingCategory
    severity: FindingSeverity
    title: str              # Plain language: "Suspicious PowerShell command detected"
    description: str        # What happened in simple terms
    evidence: dict[str, Any]  # Raw data proving the finding
    confidence: float       # 0.0 - 1.0, how certain we are
    mitre_id: str = ""      # e.g., "T1059.001"
    mitre_tactic: str = ""  # e.g., "Execution"
    remediation_id: str = ""  # Links to a remediation action
    event_ids: list[str] = field(default_factory=list)
    dismissed: bool = False
    resolved: bool = False


# ── Deterministic Classification Rules ────────────────────────────────
# Each rule has: match function, severity, confidence, title template,
# description template, MITRE mapping. No guessing.

KNOWN_MALICIOUS_TOOLS = {
    "mimikatz": ("Credential theft tool Mimikatz detected", FindingCategory.CREDENTIAL_ACCESS,
                 FindingSeverity.CRITICAL, 1.0, "T1003", "Credential Access"),
    "lazagne": ("Credential recovery tool LaZagne detected", FindingCategory.CREDENTIAL_ACCESS,
                FindingSeverity.CRITICAL, 1.0, "T1003", "Credential Access"),
    "bloodhound": ("Active Directory recon tool BloodHound detected", FindingCategory.LATERAL_MOVEMENT,
                   FindingSeverity.HIGH, 0.95, "T1087", "Discovery"),
    "rubeus": ("Kerberos attack tool Rubeus detected", FindingCategory.CREDENTIAL_ACCESS,
               FindingSeverity.CRITICAL, 1.0, "T1558", "Credential Access"),
    "cobalt": ("Potential Cobalt Strike beacon detected", FindingCategory.MALICIOUS_PROCESS,
               FindingSeverity.CRITICAL, 0.85, "T1071", "Command and Control"),
    "psexec": ("Remote execution tool PsExec detected", FindingCategory.LATERAL_MOVEMENT,
               FindingSeverity.HIGH, 0.8, "T1570", "Lateral Movement"),
    "netcat": ("Network utility Netcat detected", FindingCategory.NETWORK_ANOMALY,
               FindingSeverity.MEDIUM, 0.7, "T1095", "Command and Control"),
    "nmap": ("Network scanner Nmap detected", FindingCategory.NETWORK_ANOMALY,
             FindingSeverity.MEDIUM, 0.6, "T1046", "Discovery"),
}

SUSPICIOUS_CMDLINE_PATTERNS = [
    # (pattern, title, category, severity, confidence, mitre_id, mitre_tactic)
    ("-encodedcommand", "Base64-encoded PowerShell command executed",
     FindingCategory.DEFENSE_EVASION, FindingSeverity.HIGH, 0.9, "T1059.001", "Execution"),
    ("-enc ", "Base64-encoded PowerShell command executed",
     FindingCategory.DEFENSE_EVASION, FindingSeverity.HIGH, 0.9, "T1059.001", "Execution"),
    ("frombase64string", "Base64 decoding in PowerShell",
     FindingCategory.DEFENSE_EVASION, FindingSeverity.HIGH, 0.85, "T1140", "Defense Evasion"),
    ("downloadstring", "PowerShell downloading remote content",
     FindingCategory.MALICIOUS_PROCESS, FindingSeverity.HIGH, 0.85, "T1105", "Command and Control"),
    ("downloadfile", "PowerShell downloading file from internet",
     FindingCategory.MALICIOUS_PROCESS, FindingSeverity.HIGH, 0.85, "T1105", "Command and Control"),
    ("invoke-expression", "PowerShell Invoke-Expression (dynamic code execution)",
     FindingCategory.DEFENSE_EVASION, FindingSeverity.MEDIUM, 0.75, "T1059.001", "Execution"),
    ("new-object net.webclient", "PowerShell creating web client",
     FindingCategory.SUSPICIOUS_PROCESS, FindingSeverity.MEDIUM, 0.7, "T1059.001", "Execution"),
    ("bypass executionpolicy", "PowerShell execution policy bypass",
     FindingCategory.DEFENSE_EVASION, FindingSeverity.MEDIUM, 0.8, "T1059.001", "Defense Evasion"),
    ("reg add.*\\run", "Registry Run key modification (persistence)",
     FindingCategory.PERSISTENCE, FindingSeverity.HIGH, 0.85, "T1547.001", "Persistence"),
    ("schtasks /create", "Scheduled task creation (persistence)",
     FindingCategory.PERSISTENCE, FindingSeverity.MEDIUM, 0.7, "T1053.005", "Persistence"),
    ("net user /add", "New user account creation",
     FindingCategory.PERSISTENCE, FindingSeverity.HIGH, 0.9, "T1136.001", "Persistence"),
    ("net localgroup administrators", "User added to administrators group",
     FindingCategory.PERSISTENCE, FindingSeverity.CRITICAL, 0.95, "T1098", "Persistence"),
    ("vssadmin delete shadows", "Volume shadow copy deletion (ransomware indicator)",
     FindingCategory.MALICIOUS_PROCESS, FindingSeverity.CRITICAL, 0.95, "T1490", "Impact"),
    ("bcdedit /set.*recoveryenabled no", "Boot recovery disabled (ransomware indicator)",
     FindingCategory.MALICIOUS_PROCESS, FindingSeverity.CRITICAL, 0.95, "T1490", "Impact"),
    ("wmic shadowcopy delete", "Shadow copy deletion via WMIC",
     FindingCategory.MALICIOUS_PROCESS, FindingSeverity.CRITICAL, 0.95, "T1490", "Impact"),
    ("certutil -urlcache", "Certutil used to download files (LOLBin abuse)",
     FindingCategory.DEFENSE_EVASION, FindingSeverity.HIGH, 0.85, "T1105", "Command and Control"),
    ("bitsadmin /transfer", "BITSAdmin file transfer (LOLBin abuse)",
     FindingCategory.DEFENSE_EVASION, FindingSeverity.HIGH, 0.8, "T1197", "Defense Evasion"),
    ("mshta vbscript", "MSHTA executing VBScript",
     FindingCategory.DEFENSE_EVASION, FindingSeverity.HIGH, 0.85, "T1218.005", "Defense Evasion"),
]

SUSPICIOUS_PARENT_CHILD = {
    # parent → child combos that are almost always malicious
    ("winword.exe", "cmd.exe"): ("Word spawned Command Prompt", FindingSeverity.HIGH, 0.9, "T1204.002", "Execution"),
    ("winword.exe", "powershell.exe"): ("Word spawned PowerShell", FindingSeverity.CRITICAL, 0.95, "T1204.002", "Execution"),
    ("excel.exe", "cmd.exe"): ("Excel spawned Command Prompt", FindingSeverity.HIGH, 0.9, "T1204.002", "Execution"),
    ("excel.exe", "powershell.exe"): ("Excel spawned PowerShell", FindingSeverity.CRITICAL, 0.95, "T1204.002", "Execution"),
    ("outlook.exe", "cmd.exe"): ("Outlook spawned Command Prompt", FindingSeverity.HIGH, 0.85, "T1204.002", "Execution"),
    ("outlook.exe", "powershell.exe"): ("Outlook spawned PowerShell", FindingSeverity.CRITICAL, 0.95, "T1204.002", "Execution"),
    ("svchost.exe", "cmd.exe"): ("Service Host spawned Command Prompt", FindingSeverity.MEDIUM, 0.6, "T1569.002", "Execution"),
}


class ThreatClassifier:
    """Deterministic threat classifier with evidence chain.

    Subscribes to the event bus and produces Findings.
    Every finding has concrete evidence — no speculation.
    """

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._bus: EventBus | None = None
        self._db = None
        self._max_findings = 500

    @property
    def findings(self) -> list[Finding]:
        return self._findings

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self._findings if not f.dismissed and not f.resolved]

    @property
    def security_score(self) -> int:
        """0-100 security score. 100 = no issues, 0 = critical problems."""
        if not self.active_findings:
            return 100

        penalty = 0
        for f in self.active_findings:
            if f.severity == FindingSeverity.CRITICAL:
                penalty += 25
            elif f.severity == FindingSeverity.HIGH:
                penalty += 15
            elif f.severity == FindingSeverity.MEDIUM:
                penalty += 8
            elif f.severity == FindingSeverity.LOW:
                penalty += 3
            else:
                penalty += 1

        return max(0, 100 - penalty)

    @property
    def score_label(self) -> str:
        s = self.security_score
        if s >= 90:
            return "SECURE"
        if s >= 70:
            return "FAIR"
        if s >= 50:
            return "AT RISK"
        if s >= 25:
            return "POOR"
        return "CRITICAL"

    def set_db(self, db) -> None:
        """Set database reference for persistence."""
        self._db = db

    def load_from_db(self) -> None:
        """Load existing findings from DuckDB on startup."""
        if not self._db:
            return
        try:
            rows = self._db.get_findings(active_only=False)
            for row in rows:
                try:
                    f = Finding(
                        id=row["id"], timestamp=row["timestamp"],
                        category=FindingCategory(row["category"]),
                        severity=FindingSeverity(row["severity"]),
                        title=row["title"], description=row["description"],
                        evidence=row.get("evidence", {}),
                        confidence=row.get("confidence", 0.0),
                        mitre_id=row.get("mitre_id", ""),
                        mitre_tactic=row.get("mitre_tactic", ""),
                        remediation_id=row.get("remediation_id", ""),
                        event_ids=row.get("event_ids", []),
                        dismissed=row.get("dismissed", False),
                        resolved=row.get("resolved", False),
                    )
                    self._findings.append(f)
                except (ValueError, KeyError):
                    continue
            logger.info("Loaded %d findings from database", len(self._findings))
        except Exception as e:
            logger.warning("Could not load findings from DB: %s", e)

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self.load_from_db()
        bus.subscribe(EventType.PROCESS_START, self._classify_process)
        bus.subscribe(EventType.PROCESS_SUSPICIOUS, self._classify_process)
        bus.subscribe(EventType.FILE_MODIFIED, self._classify_file_change)
        bus.subscribe(EventType.FILE_CREATED, self._classify_file_change)
        bus.subscribe(EventType.REGISTRY_CHANGE, self._classify_registry)
        bus.subscribe(EventType.CONNECTION_SUSPICIOUS, self._classify_network)
        bus.subscribe(EventType.CHAIN_DETECTED, self._classify_chain)
        logger.info("Threat classifier started")

    async def _add_finding(self, finding: Finding) -> None:
        self._findings.append(finding)
        if len(self._findings) > self._max_findings:
            self._findings = self._findings[-self._max_findings:]

        # Persist to DuckDB
        if self._db:
            try:
                self._db.upsert_finding({
                    "id": finding.id, "timestamp": finding.timestamp,
                    "category": finding.category.value, "severity": finding.severity.value,
                    "title": finding.title, "description": finding.description,
                    "evidence": finding.evidence, "confidence": finding.confidence,
                    "mitre_id": finding.mitre_id, "mitre_tactic": finding.mitre_tactic,
                    "remediation_id": finding.remediation_id,
                    "event_ids": finding.event_ids,
                    "dismissed": finding.dismissed, "resolved": finding.resolved,
                })
            except Exception as e:
                logger.error("Failed to persist finding: %s", e)

        logger.warning("FINDING [%s] %s (confidence=%.0f%%): %s",
                       finding.severity.value.upper(), finding.title,
                       finding.confidence * 100, finding.description)

    async def _classify_process(self, event: Event) -> None:
        """Classify process start/suspicious events."""
        data = event.data
        name = (data.get("name") or "").lower()
        cmdline = (data.get("cmdline") or "").lower()
        exe = (data.get("exe") or "").lower()
        pid = data.get("pid", 0)
        username = data.get("username", "")

        evidence = {
            "pid": pid,
            "process_name": data.get("name", ""),
            "executable": data.get("exe", ""),
            "command_line": data.get("cmdline", ""),
            "username": username,
            "parent_pid": data.get("ppid", 0),
        }

        # Check 1: Known malicious tools
        for tool_name, (title, category, severity, confidence, mitre_id, tactic) in KNOWN_MALICIOUS_TOOLS.items():
            if tool_name in name or tool_name in cmdline or tool_name in exe:
                await self._add_finding(Finding(
                    id=f"proc-{event.id}",
                    timestamp=event.timestamp,
                    category=category,
                    severity=severity,
                    title=title,
                    description=f"Process '{data.get('name')}' (PID {pid}) matches known malicious tool '{tool_name}'. "
                                f"Full command: {data.get('cmdline', 'N/A')}",
                    evidence=evidence,
                    confidence=confidence,
                    mitre_id=mitre_id,
                    mitre_tactic=tactic,
                    remediation_id="kill_process",
                    event_ids=[event.id],
                ))
                return  # One finding per event max

        # Check 2: Suspicious command-line patterns
        for pattern, title, category, severity, confidence, mitre_id, tactic in SUSPICIOUS_CMDLINE_PATTERNS:
            if pattern in cmdline:
                await self._add_finding(Finding(
                    id=f"cmd-{event.id}",
                    timestamp=event.timestamp,
                    category=category,
                    severity=severity,
                    title=title,
                    description=f"Process '{data.get('name')}' (PID {pid}) executed with suspicious command line "
                                f"matching pattern '{pattern}'. User: {username}",
                    evidence=evidence,
                    confidence=confidence,
                    mitre_id=mitre_id,
                    mitre_tactic=tactic,
                    remediation_id="kill_process",
                    event_ids=[event.id],
                ))
                return

        # Check 3: Suspicious parent-child relationships
        ppid = data.get("ppid", 0)
        if ppid:
            try:
                import psutil
                parent = psutil.Process(ppid)
                parent_name = parent.name().lower()
                key = (parent_name, name)
                if key in SUSPICIOUS_PARENT_CHILD:
                    title, severity, confidence, mitre_id, tactic = SUSPICIOUS_PARENT_CHILD[key]
                    evidence["parent_name"] = parent_name
                    evidence["parent_exe"] = parent.exe()
                    await self._add_finding(Finding(
                        id=f"parent-{event.id}",
                        timestamp=event.timestamp,
                        category=FindingCategory.SUSPICIOUS_PROCESS,
                        severity=severity,
                        title=title,
                        description=f"'{parent_name}' (PID {ppid}) spawned '{data.get('name')}' (PID {pid}). "
                                    f"This parent-child combination is commonly seen in malware execution.",
                        evidence=evidence,
                        confidence=confidence,
                        mitre_id=mitre_id,
                        mitre_tactic=tactic,
                        remediation_id="kill_process",
                        event_ids=[event.id],
                    ))
            except Exception:
                pass  # Parent already exited — can't verify

        # Check 4: Execution from temp directories
        if any(t in exe for t in ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp")):
            await self._add_finding(Finding(
                id=f"temp-{event.id}",
                timestamp=event.timestamp,
                category=FindingCategory.SUSPICIOUS_PROCESS,
                severity=FindingSeverity.MEDIUM,
                title="Program running from temporary directory",
                description=f"Process '{data.get('name')}' (PID {pid}) is running from a temporary directory. "
                            f"Legitimate software rarely executes from temp folders. Path: {data.get('exe')}",
                evidence=evidence,
                confidence=0.6,
                mitre_id="T1204",
                mitre_tactic="Execution",
                remediation_id="kill_process",
                event_ids=[event.id],
            ))

    async def _classify_file_change(self, event: Event) -> None:
        """Classify file creation/modification events."""
        data = event.data
        path = (data.get("path") or "").lower()

        # Critical system file modifications
        critical_paths = [
            ("\\windows\\system32\\", "System32 directory"),
            ("\\windows\\syswow64\\", "SysWOW64 directory"),
            ("\\windows\\system32\\drivers\\", "System driver directory"),
            ("\\windows\\system32\\config\\", "Registry hive directory"),
        ]
        for crit_path, location in critical_paths:
            if crit_path in path:
                await self._add_finding(Finding(
                    id=f"file-{event.id}",
                    timestamp=event.timestamp,
                    category=FindingCategory.FILE_TAMPERING,
                    severity=FindingSeverity.HIGH,
                    title=f"Critical system file modified in {location}",
                    description=f"A file was {'created' if event.type == EventType.FILE_CREATED else 'modified'} "
                                f"in a protected system directory: {data.get('path')}",
                    evidence={
                        "path": data.get("path", ""),
                        "action": event.type.value,
                        "hash": data.get("hash_sha256", ""),
                    },
                    confidence=0.8,
                    mitre_id="T1565",
                    mitre_tactic="Impact",
                    remediation_id="quarantine_file",
                    event_ids=[event.id],
                ))
                return

    async def _classify_registry(self, event: Event) -> None:
        """Classify registry change events."""
        data = event.data
        target = (data.get("TargetObject") or data.get("path") or "").lower()

        # Persistence via Run keys
        run_keys = ["\\currentversion\\run", "\\currentversion\\runonce",
                    "\\currentversion\\policies\\explorer\\run"]
        for key in run_keys:
            if key in target:
                await self._add_finding(Finding(
                    id=f"reg-{event.id}",
                    timestamp=event.timestamp,
                    category=FindingCategory.PERSISTENCE,
                    severity=FindingSeverity.HIGH,
                    title="Registry Run key modified (auto-start persistence)",
                    description=f"A program modified a Windows startup registry key. "
                                f"This is a common persistence technique. Key: {data.get('TargetObject', target)}",
                    evidence={
                        "registry_key": data.get("TargetObject", ""),
                        "value": data.get("Details", ""),
                        "process": data.get("Image", ""),
                    },
                    confidence=0.85,
                    mitre_id="T1547.001",
                    mitre_tactic="Persistence",
                    event_ids=[event.id],
                ))
                return

    async def _classify_network(self, event: Event) -> None:
        """Classify suspicious network connections."""
        data = event.data
        dst_ip = data.get("DestinationIp") or data.get("ip", "")
        dst_port = data.get("DestinationPort") or data.get("port", 0)

        # Known bad ports
        bad_ports = {4444: "Metasploit default", 1337: "Common backdoor",
                     31337: "Back Orifice", 6666: "IRC backdoor", 6667: "IRC C2",
                     8888: "Common RAT", 9999: "Common RAT"}

        if int(dst_port) in bad_ports:
            reason = bad_ports[int(dst_port)]
            await self._add_finding(Finding(
                id=f"net-{event.id}",
                timestamp=event.timestamp,
                category=FindingCategory.NETWORK_ANOMALY,
                severity=FindingSeverity.HIGH,
                title=f"Connection to suspicious port {dst_port} ({reason})",
                description=f"A process connected to {dst_ip}:{dst_port}. "
                            f"Port {dst_port} is commonly associated with: {reason}",
                evidence={
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "process": data.get("Image", ""),
                    "reason": reason,
                },
                confidence=0.75,
                mitre_id="T1071",
                mitre_tactic="Command and Control",
                remediation_id="block_connection",
                event_ids=[event.id],
            ))

    async def _classify_chain(self, event: Event) -> None:
        """Correlation engine already verified this chain — promote to finding."""
        data = event.data
        await self._add_finding(Finding(
            id=f"chain-{event.id}",
            timestamp=event.timestamp,
            category=FindingCategory.MALICIOUS_PROCESS,
            severity=FindingSeverity.CRITICAL,
            title=f"Attack chain detected: {data.get('rule', 'Unknown')}",
            description=data.get("description", "Multiple correlated events detected"),
            evidence={
                "rule": data.get("rule", ""),
                "event_count": data.get("event_count", 0),
                "correlation_key": data.get("correlation_key", ""),
                "score": data.get("total_score", 0),
                "mitre_tactics": data.get("mitre_tactics", []),
                "mitre_techniques": data.get("mitre_techniques", []),
            },
            confidence=0.9,
            mitre_id=",".join(data.get("mitre_techniques", [])),
            mitre_tactic=",".join(data.get("mitre_tactics", [])),
            event_ids=data.get("event_ids", []),
        ))


# Singleton
classifier = ThreatClassifier()
