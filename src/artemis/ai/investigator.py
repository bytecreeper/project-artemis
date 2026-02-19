"""AI Investigation Agent — autonomous alert investigation.

Inspired by LMNTRIX Artemis: takes an alert or finding, gathers related
context from multiple sources (events, network, processes), builds a
timeline/kill chain, and recommends specific actions.

Works with or without AI:
- With AI: Rich narrative analysis + MITRE kill chain mapping
- Without AI: Deterministic context gathering + structured report
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("artemis.ai.investigator")


@dataclass
class Investigation:
    """Complete investigation of a security event/finding."""
    id: str = ""
    trigger: str = ""  # What started the investigation
    trigger_type: str = ""  # "alert", "finding", "event"
    timestamp: float = field(default_factory=time.time)
    # Gathered context
    related_events: list[dict] = field(default_factory=list)
    related_hosts: list[dict] = field(default_factory=list)
    related_processes: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    # Analysis
    severity_assessment: str = ""
    kill_chain_phase: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    narrative: str = ""  # Human-readable investigation summary
    recommendations: list[str] = field(default_factory=list)
    confidence: float = 0.0
    # Status
    status: str = "pending"  # pending, investigating, complete, escalated
    duration_seconds: float = 0.0


class InvestigationEngine:
    """Investigates security events by gathering context and analyzing patterns."""

    def __init__(self, db, ai_provider, classifier=None):
        self.db = db
        self.ai = ai_provider
        self.classifier = classifier
        self.investigations: list[Investigation] = []

    async def investigate_finding(self, finding_data: dict) -> Investigation:
        """Investigate a threat classifier finding."""
        inv = Investigation(
            id=f"inv-{int(time.time())}-{finding_data.get('id', 'unknown')[:8]}",
            trigger=finding_data.get("title", "Unknown finding"),
            trigger_type="finding",
        )
        inv.status = "investigating"
        start = time.time()

        # 1. Gather related events
        inv.related_events = await self._gather_related_events(finding_data)

        # 2. Gather network context
        inv.related_hosts = await self._gather_network_context(finding_data)

        # 3. Gather process context
        inv.related_processes = await self._gather_process_context(finding_data)

        # 4. Build timeline
        inv.timeline = self._build_timeline(inv)

        # 5. Map to MITRE kill chain
        inv.mitre_techniques = self._map_mitre(finding_data, inv.related_events)
        inv.kill_chain_phase = self._determine_kill_chain_phase(inv.mitre_techniques)

        # 6. Assess severity
        inv.severity_assessment = self._assess_severity(finding_data, inv)

        # 7. Generate narrative (AI-enhanced or deterministic)
        inv.narrative = await self._generate_narrative(finding_data, inv)

        # 8. Generate recommendations
        inv.recommendations = self._generate_recommendations(finding_data, inv)

        inv.confidence = self._calculate_confidence(inv)
        inv.status = "complete"
        inv.duration_seconds = time.time() - start

        self.investigations.append(inv)
        if len(self.investigations) > 100:
            self.investigations = self.investigations[-100:]

        logger.info("Investigation %s complete in %.1fs — %s",
                     inv.id, inv.duration_seconds, inv.severity_assessment)
        return inv

    async def investigate_alert(self, alert_data: dict) -> Investigation:
        """Investigate an alert (from correlation engine)."""
        # Convert alert to finding-like format for reuse
        finding_like = {
            "id": alert_data.get("id", ""),
            "title": alert_data.get("title", ""),
            "description": alert_data.get("description", ""),
            "severity": alert_data.get("severity", 0),
            "category": "alert",
            "evidence": alert_data,
            "event_ids": alert_data.get("event_ids", []),
        }
        inv = await self.investigate_finding(finding_like)
        inv.trigger_type = "alert"
        return inv

    # ── Context Gathering ─────────────────────────────────────────────

    async def _gather_related_events(self, finding: dict) -> list[dict]:
        """Find events related to this finding."""
        events = []

        # Search by evidence keywords
        evidence = finding.get("evidence", {})
        search_terms = []

        # Extract searchable terms from evidence
        for key in ("name", "process_name", "path", "file_path", "ip", "src_ip", "dst_ip", "command_line"):
            if key in evidence:
                search_terms.append(str(evidence[key]))

        for term in search_terms[:5]:  # Limit searches
            try:
                rows = self.db.search_events(term, limit=20, hours=24)
                for r in rows:
                    data = r[5]
                    if isinstance(data, str):
                        try:
                            data = json.loads(data)
                        except Exception:
                            data = {}
                    events.append({
                        "id": r[0], "timestamp": str(r[1]), "type": r[2],
                        "source": r[3], "severity": r[4], "data": data,
                    })
            except Exception as e:
                logger.debug("Event search failed for '%s': %s", term, e)

        # Deduplicate by ID
        seen = set()
        unique = []
        for e in events:
            if e["id"] not in seen:
                seen.add(e["id"])
                unique.append(e)

        return sorted(unique, key=lambda x: x["timestamp"])

    async def _gather_network_context(self, finding: dict) -> list[dict]:
        """Get network info related to the finding."""
        evidence = finding.get("evidence", {})
        hosts = []

        # Look for IPs in evidence
        for key in ("ip", "src_ip", "dst_ip", "remote_ip", "host"):
            ip = evidence.get(key)
            if ip:
                db_hosts = self.db.get_hosts()
                for h in db_hosts:
                    if h.get("ip") == ip:
                        hosts.append(h)

        return hosts

    async def _gather_process_context(self, finding: dict) -> list[dict]:
        """Get process info related to the finding."""
        evidence = finding.get("evidence", {})
        processes = []

        pid = evidence.get("pid")
        if pid:
            try:
                rows = self.db.get_process_tree(int(pid))
                for r in rows:
                    data = r[5]
                    if isinstance(data, str):
                        try:
                            data = json.loads(data)
                        except Exception:
                            data = {}
                    processes.append({
                        "timestamp": str(r[1]), "type": r[2], "data": data,
                    })
            except Exception:
                pass

        return processes

    # ── Analysis ──────────────────────────────────────────────────────

    def _build_timeline(self, inv: Investigation) -> list[dict]:
        """Build a chronological timeline from all gathered data."""
        entries = []

        for e in inv.related_events:
            entries.append({
                "time": e["timestamp"],
                "type": "event",
                "detail": f"[{e['type']}] {e.get('source', '')} (severity: {e.get('severity', 0)})",
                "data": e,
            })

        for p in inv.related_processes:
            name = p.get("data", {}).get("name", "unknown") if isinstance(p.get("data"), dict) else "unknown"
            entries.append({
                "time": p["timestamp"],
                "type": "process",
                "detail": f"Process: {name}",
                "data": p,
            })

        return sorted(entries, key=lambda x: str(x["time"]))

    def _map_mitre(self, finding: dict, events: list[dict]) -> list[str]:
        """Map finding and events to MITRE ATT&CK techniques."""
        techniques = []

        # From the finding itself
        if finding.get("mitre_id"):
            techniques.append(finding["mitre_id"])

        # From event types
        event_mitre_map = {
            "edr.process.start": "T1059",       # Execution
            "edr.process.suspicious": "T1059",
            "edr.file.modified": "T1565",        # Data Manipulation
            "edr.file.created": "T1105",         # Ingress Tool Transfer
            "edr.registry.change": "T1547",      # Boot/Logon Autostart
            "correlation.chain": "T1078",        # Valid Accounts (multi-stage)
            "network.host.new": "T1046",         # Network Service Discovery
        }

        for e in events:
            t = event_mitre_map.get(e.get("type", ""))
            if t and t not in techniques:
                techniques.append(t)

        return techniques

    def _determine_kill_chain_phase(self, techniques: list[str]) -> str:
        """Map techniques to kill chain phase."""
        phase_map = {
            "T1595": "Reconnaissance",
            "T1046": "Discovery",
            "T1059": "Execution",
            "T1105": "Command and Control",
            "T1547": "Persistence",
            "T1078": "Initial Access",
            "T1210": "Lateral Movement",
            "T1565": "Impact",
            "T1562": "Defense Evasion",
            "T1557": "Credential Access",
        }

        phases = []
        for t in techniques:
            base = t.split(".")[0]
            phase = phase_map.get(base)
            if phase and phase not in phases:
                phases.append(phase)

        if not phases:
            return "Unknown"
        return " → ".join(phases)

    def _assess_severity(self, finding: dict, inv: Investigation) -> str:
        """Assess overall severity of the investigation."""
        severity = finding.get("severity", "info")
        if isinstance(severity, int):
            if severity >= 8:
                severity = "critical"
            elif severity >= 5:
                severity = "high"
            elif severity >= 3:
                severity = "medium"
            else:
                severity = "low"

        # Escalate if multiple correlated events
        if len(inv.related_events) > 10:
            if severity in ("low", "medium"):
                severity = "high"
                return f"{severity} (escalated — {len(inv.related_events)} related events)"

        if len(inv.mitre_techniques) > 2:
            if severity in ("low", "medium"):
                severity = "high"
                return f"{severity} (escalated — multi-technique attack chain)"

        return severity

    async def _generate_narrative(self, finding: dict, inv: Investigation) -> str:
        """Generate human-readable investigation narrative."""
        # Build context for AI or deterministic narrative
        context = {
            "finding": finding.get("title", ""),
            "description": finding.get("description", ""),
            "severity": inv.severity_assessment,
            "related_events": len(inv.related_events),
            "related_hosts": len(inv.related_hosts),
            "related_processes": len(inv.related_processes),
            "kill_chain": inv.kill_chain_phase,
            "mitre": inv.mitre_techniques,
            "timeline_entries": len(inv.timeline),
        }

        # Try AI narrative
        from artemis.ai.provider import NullProvider
        if not isinstance(self.ai, NullProvider):
            try:
                import asyncio
                result = await asyncio.wait_for(self.ai.generate(
                    f"Write a concise investigation summary for this security finding:\n\n{json.dumps(context, indent=2)}",
                    system=(
                        "You are a SOC analyst writing an investigation report. Be concise and factual. "
                        "Include: what happened, potential impact, and confidence level. "
                        "Write for both technical and non-technical readers."
                    ),
                    temperature=0.3,
                ), timeout=15)
                return result
            except Exception as e:
                logger.debug("AI narrative failed: %s", e)

        # Deterministic narrative
        parts = [f"Investigation of: {finding.get('title', 'Unknown')}"]
        parts.append(f"\nSeverity: {inv.severity_assessment}")
        parts.append(f"Kill chain phase: {inv.kill_chain_phase}")

        if inv.related_events:
            parts.append(f"\n{len(inv.related_events)} related events were found in the last 24 hours.")
        if inv.related_processes:
            parts.append(f"{len(inv.related_processes)} related process events were identified.")
        if inv.related_hosts:
            hosts = ", ".join(h.get("ip", "?") for h in inv.related_hosts[:5])
            parts.append(f"Involved hosts: {hosts}")
        if inv.mitre_techniques:
            parts.append(f"MITRE ATT&CK techniques: {', '.join(inv.mitre_techniques)}")

        return "\n".join(parts)

    def _generate_recommendations(self, finding: dict, inv: Investigation) -> list[str]:
        """Generate actionable recommendations."""
        recs = []

        severity = inv.severity_assessment.lower()

        if "critical" in severity:
            recs.append("IMMEDIATE: Isolate the affected system from the network")
            recs.append("Preserve forensic evidence before remediation")

        if inv.related_processes:
            recs.append("Review and terminate suspicious processes identified in this investigation")

        evidence = finding.get("evidence", {})
        if evidence.get("pid"):
            recs.append(f"Investigate process PID {evidence['pid']} and its parent process chain")
        if evidence.get("path") or evidence.get("file_path"):
            path = evidence.get("path") or evidence.get("file_path")
            recs.append(f"Analyze file: {path} — check VirusTotal or similar")
        if evidence.get("ip") or evidence.get("remote_ip"):
            ip = evidence.get("ip") or evidence.get("remote_ip")
            recs.append(f"Check IP reputation for {ip} — block if malicious")

        if len(inv.mitre_techniques) > 1:
            recs.append("Multi-stage attack detected — review full kill chain before partial remediation")

        if not recs:
            recs.append("Monitor the situation — no immediate action required")
            recs.append("Review this finding during next security review")

        return recs

    def _calculate_confidence(self, inv: Investigation) -> float:
        """Calculate confidence in the investigation."""
        score = 0.5  # Base

        if inv.related_events:
            score += min(0.2, len(inv.related_events) * 0.02)
        if inv.related_processes:
            score += 0.1
        if inv.mitre_techniques:
            score += 0.1
        if inv.timeline:
            score += 0.1

        return min(1.0, score)

    def to_dict(self, inv: Investigation) -> dict:
        """Serialize an investigation for API response."""
        return {
            "id": inv.id,
            "trigger": inv.trigger,
            "trigger_type": inv.trigger_type,
            "timestamp": inv.timestamp,
            "status": inv.status,
            "severity_assessment": inv.severity_assessment,
            "kill_chain_phase": inv.kill_chain_phase,
            "mitre_techniques": inv.mitre_techniques,
            "narrative": inv.narrative,
            "recommendations": inv.recommendations,
            "confidence": inv.confidence,
            "related_events_count": len(inv.related_events),
            "related_hosts_count": len(inv.related_hosts),
            "related_processes_count": len(inv.related_processes),
            "timeline_entries": len(inv.timeline),
            "timeline": inv.timeline[:20],  # Cap for API response size
            "duration_seconds": inv.duration_seconds,
        }
