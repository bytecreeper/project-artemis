"""API routes — JSON endpoints for the frontend and external consumers."""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["api"])


def _get_state():
    from artemis.web.app import state
    if not state:
        raise HTTPException(503, "Not initialized")
    return state


# ── Health / Stats ────────────────────────────────────────────────────

@router.get("/health")
async def health() -> dict[str, Any]:
    s = _get_state()

    plugin_status = {}
    for p in s.edr_plugins:
        plugin_status[p.name] = await p.status()

    return {
        "status": "ok",
        "version": "3.0.0",
        "uptime_seconds": time.time() - s.start_time,
        "edr_plugins": plugin_status,
        "correlation": {"enabled": s.config.correlation.enabled},
        "network": {
            "enabled": s.config.network.enabled,
            "scan_range": s.config.network.scan_range,
        },
        "ai": {"provider": s.config.ai.provider, "model": s.config.ai.model},
    }


@router.get("/stats")
async def stats() -> dict[str, Any]:
    """Dashboard summary stats."""
    s = _get_state()
    return {
        "events_24h": s.db.count_events_since(24),
        "open_alerts": s.db.count_open_alerts(),
        "network_hosts": s.db.count_hosts(),
        "edr_plugins": len(s.edr_plugins),
    }


# ── Events ────────────────────────────────────────────────────────────

@router.get("/events")
async def get_events(limit: int = 50, event_type: str | None = None) -> list[dict]:
    s = _get_state()
    rows = s.db.get_recent_events(limit=limit, event_type=event_type)
    results = []
    for r in rows:
        data = r[5]
        # DuckDB may return JSON as string or dict
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                pass
        results.append({
            "id": r[0],
            "timestamp": str(r[1]),
            "type": r[2],
            "source": r[3],
            "severity": r[4],
            "data": data,
        })
    return results


# ── Alerts ────────────────────────────────────────────────────────────

@router.get("/alerts")
async def get_alerts() -> list[dict]:
    s = _get_state()
    rows = s.db.get_open_alerts()
    results = []
    for r in rows:
        results.append({
            "id": r[0],
            "timestamp": str(r[1]),
            "title": r[2],
            "description": r[3],
            "severity": r[4],
            "event_ids": r[5],
            "status": r[6],
        })
    return results


# ── Network ───────────────────────────────────────────────────────────

@router.get("/network/hosts")
async def get_hosts() -> list[dict]:
    s = _get_state()
    # Merge in-memory discovered hosts + DB hosts
    live_hosts = list(s.network._known_hosts.values())
    db_hosts = s.db.get_hosts()
    # Prefer live data, fall back to DB
    seen_ips = {h["ip"] for h in live_hosts}
    for h in db_hosts:
        if h["ip"] not in seen_ips:
            live_hosts.append(h)
    return live_hosts


# ── Rule Generation ──────────────────────────────────────────────────

class GenerateRequest(BaseModel):
    description: str
    format: str = "sigma"
    severity: str = "medium"


@router.post("/generate")
async def generate_rule(req: GenerateRequest) -> dict[str, Any]:
    s = _get_state()

    prompt = f"Generate a {req.format.upper()} detection rule for: {req.description}\nSeverity: {req.severity}"
    try:
        result = await s.ai.generate(
            prompt,
            system=f"You are a detection engineer. Generate a valid {req.format} rule. Output ONLY the rule, no explanation.",
        )
        return {"rule": result, "format": req.format}
    except Exception as e:
        raise HTTPException(500, f"AI generation failed: {e}")


# ── EDR Plugins ───────────────────────────────────────────────────────

@router.get("/edr/status")
async def edr_status() -> dict[str, Any]:
    s = _get_state()
    statuses = {}
    for p in s.edr_plugins:
        statuses[p.name] = await p.status()
    return statuses


# ── Config (read-only for UI) ────────────────────────────────────────

@router.get("/config")
async def get_config() -> dict[str, Any]:
    s = _get_state()
    return {
        "ai": {"provider": s.config.ai.provider, "model": s.config.ai.model},
        "network": {"scan_range": s.config.network.scan_range, "interval": s.config.network.scan_interval_seconds},
        "edr": {"enabled": s.config.edr.enabled, "plugins": s.config.edr.plugins},
        "correlation": {
            "enabled": s.config.correlation.enabled,
            "window_seconds": s.config.correlation.window_seconds,
        },
    }


# ── Hunt / Search ────────────────────────────────────────────────────

@router.get("/search")
async def search_events(
    q: str = "",
    event_type: str | None = None,
    min_severity: int = 0,
    hours: int | None = None,
    limit: int = 100,
) -> list[dict]:
    s = _get_state()
    rows = s.db.search_events(q, limit=limit, event_type=event_type,
                               min_severity=min_severity, hours=hours)
    results = []
    for r in rows:
        data = r[5]
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                pass
        results.append({
            "id": r[0], "timestamp": str(r[1]), "type": r[2],
            "source": r[3], "severity": r[4], "data": data,
        })
    return results


@router.get("/timeline")
async def event_timeline(hours: int = 24, bucket_minutes: int = 15) -> list[dict]:
    s = _get_state()
    return s.db.get_event_timeline(hours=hours, bucket_minutes=bucket_minutes)


class AnalyzeRequest(BaseModel):
    context: str
    question: str = "Analyze this security event for potential threats."


@router.post("/analyze")
async def ai_analyze(req: AnalyzeRequest) -> dict[str, Any]:
    s = _get_state()
    prompt = f"Security context:\n{req.context}\n\nQuestion: {req.question}"
    try:
        result = await s.ai.generate(
            prompt,
            system="You are a senior SOC analyst. Analyze the security data and provide: "
                   "1) Threat assessment 2) MITRE ATT&CK mapping 3) Recommended actions. "
                   "Be concise and actionable.",
        )
        return {"analysis": result}
    except Exception as e:
        raise HTTPException(500, f"AI analysis failed: {e}")


# ── Findings / Security Score ─────────────────────────────────────────

@router.get("/findings")
async def get_findings(active_only: bool = True) -> dict[str, Any]:
    from artemis.core.threat_classifier import classifier
    findings = classifier.active_findings if active_only else classifier.findings
    return {
        "security_score": classifier.security_score,
        "score_label": classifier.score_label,
        "finding_count": len(findings),
        "findings": [
            {
                "id": f.id,
                "timestamp": f.timestamp,
                "category": f.category.value,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "confidence": f.confidence,
                "mitre_id": f.mitre_id,
                "mitre_tactic": f.mitre_tactic,
                "remediation_id": f.remediation_id,
                "dismissed": f.dismissed,
                "resolved": f.resolved,
            }
            for f in findings
        ],
    }


@router.get("/security-score")
async def get_security_score() -> dict[str, Any]:
    from artemis.core.threat_classifier import classifier
    s = _get_state()
    active = classifier.active_findings
    by_sev = {}
    for f in active:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return {
        "score": classifier.security_score,
        "label": classifier.score_label,
        "total_findings": len(active),
        "by_severity": by_sev,
        "edr_plugins_active": len(s.edr_plugins),
        "network_hosts": s.db.count_hosts(),
        "events_24h": s.db.count_events_since(24),
        "uptime_seconds": time.time() - s.start_time,
    }


# ── Remediation ──────────────────────────────────────────────────────

class KillProcessRequest(BaseModel):
    finding_id: str
    pid: int
    verify_name: str = ""


@router.post("/remediate/kill")
async def remediate_kill(req: KillProcessRequest) -> dict[str, Any]:
    from artemis.core.remediation import remediation
    result = await remediation.kill_process(req.finding_id, req.pid, req.verify_name)
    return result.to_dict()


class QuarantineRequest(BaseModel):
    finding_id: str
    file_path: str


@router.post("/remediate/quarantine")
async def remediate_quarantine(req: QuarantineRequest) -> dict[str, Any]:
    from artemis.core.remediation import remediation
    result = await remediation.quarantine_file(req.finding_id, req.file_path)
    return result.to_dict()


class BlockIPRequest(BaseModel):
    finding_id: str
    ip: str
    direction: str = "both"


@router.post("/remediate/block")
async def remediate_block(req: BlockIPRequest) -> dict[str, Any]:
    from artemis.core.remediation import remediation
    result = await remediation.block_ip(req.finding_id, req.ip, req.direction)
    return result.to_dict()


@router.post("/findings/{finding_id}/dismiss")
async def dismiss_finding(finding_id: str) -> dict[str, str]:
    from artemis.core.threat_classifier import classifier
    for f in classifier.findings:
        if f.id == finding_id:
            f.dismissed = True
            return {"status": "dismissed", "id": finding_id}
    raise HTTPException(404, "Finding not found")


@router.get("/remediation/history")
async def remediation_history() -> list[dict]:
    from artemis.core.remediation import remediation
    return [r.to_dict() for r in remediation.history]


# SSE endpoint — real-time event stream for Guardian
from fastapi import Request
from artemis.web.sse import create_sse_response


@router.get("/events/stream")
async def event_stream(request: Request):
    return create_sse_response(request)


# ── Vulnerability Scanner ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str = "localhost"  # IP or "localhost" or "network"
    scanners: list[str] | None = None  # None = all


@router.post("/scan")
async def run_scan(req: ScanRequest) -> dict[str, Any]:
    """Run vulnerability scanners against a target."""
    s = _get_state()
    from artemis.scanner.base import ScanEngine, ScanTarget
    import artemis.scanner.plugins  # noqa — registers plugins
    import artemis.scanner.config_audit  # noqa — registers config audit plugins

    engine = ScanEngine()
    engine.load_scanners(req.scanners)

    if req.target == "network":
        # Scan all discovered hosts
        hosts = s.db.get_hosts()
        findings = await engine.scan_network(hosts)
    else:
        host = "127.0.0.1" if req.target == "localhost" else req.target
        # Get known ports for this host if available
        known_ports = []
        for h in s.db.get_hosts():
            if h.get("ip") == host:
                ports = h.get("open_ports", [])
                if isinstance(ports, str):
                    import json as _json
                    try:
                        ports = _json.loads(ports)
                    except Exception:
                        ports = []
                known_ports = ports
                break
        target = ScanTarget(host=host, ports=known_ports)
        findings = await engine.scan_target(target)

    return {
        "target": req.target,
        "findings_count": len(findings),
        "summary": engine.scan_summary,
        "findings": [
            {
                "id": f.id, "scanner": f.scanner, "target": f.target,
                "severity": f.severity.value, "category": f.category.value,
                "title": f.title, "description": f.description,
                "technical_detail": f.technical_detail,
                "evidence": f.evidence, "remediation": f.remediation,
                "cve": f.cve, "mitre_id": f.mitre_id,
                "confidence": f.confidence,
            }
            for f in findings
        ],
    }


@router.get("/scan/scanners")
async def list_scanners() -> list[dict]:
    """List available scanner plugins."""
    from artemis.scanner.base import ScannerPlugin
    import artemis.scanner.plugins  # noqa
    import artemis.scanner.config_audit  # noqa
    return [
        {"name": cls.name, "description": cls.description, "category": cls.category}
        for cls in ScannerPlugin._registry
    ]


# ── AI Investigation ──────────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    finding_id: str = ""
    alert_id: str = ""


@router.post("/investigate")
async def investigate(req: InvestigateRequest) -> dict[str, Any]:
    """Launch an AI-powered investigation of a finding or alert."""
    s = _get_state()
    from artemis.ai.investigator import InvestigationEngine
    from artemis.core.threat_classifier import classifier

    engine = InvestigationEngine(s.db, s.ai, classifier)

    if req.finding_id:
        # Find the finding
        for f in classifier.findings:
            if f.id == req.finding_id:
                finding_data = {
                    "id": f.id, "title": f.title, "description": f.description,
                    "severity": f.severity.value, "category": f.category.value,
                    "evidence": f.evidence, "mitre_id": f.mitre_id,
                    "event_ids": f.event_ids,
                }
                inv = await engine.investigate_finding(finding_data)
                return engine.to_dict(inv)
        raise HTTPException(404, "Finding not found")

    elif req.alert_id:
        # Find the alert
        alerts = s.db.get_open_alerts()
        for a in alerts:
            if a[0] == req.alert_id:
                alert_data = {
                    "id": a[0], "title": a[2], "description": a[3],
                    "severity": a[4], "event_ids": a[5],
                }
                inv = await engine.investigate_alert(alert_data)
                return engine.to_dict(inv)
        raise HTTPException(404, "Alert not found")

    else:
        raise HTTPException(400, "Provide finding_id or alert_id")


@router.get("/investigations")
async def list_investigations() -> list[dict]:
    """List recent investigations."""
    s = _get_state()
    if not hasattr(s, '_investigator'):
        return []
    return [s._investigator.to_dict(inv) for inv in s._investigator.investigations[-20:]]


# ── Adversary Simulation ──────────────────────────────────────────────

class SimulateRequest(BaseModel):
    techniques: list[str] | None = None  # None = all


@router.post("/simulate")
async def run_simulation(req: SimulateRequest) -> dict[str, Any]:
    """Run adversary simulation campaign."""
    s = _get_state()
    from artemis.redteam.simulator import AdversarySimulator

    from artemis.core.events import bus
    sim = AdversarySimulator(db=s.db, event_bus=bus)
    campaign = await sim.run_campaign(req.techniques)

    # Store on app state for history
    if not hasattr(s, '_sim_campaigns'):
        s._sim_campaigns = []
    s._sim_campaigns.append((sim, campaign))

    return sim.to_dict(campaign)


@router.get("/simulate/techniques")
async def list_techniques() -> list[dict]:
    """List available simulation techniques."""
    return [
        {"id": "T1059.001", "name": "PowerShell Execution", "tactic": "Execution"},
        {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
        {"id": "T1547.001", "name": "Registry Run Key Persistence", "tactic": "Persistence"},
        {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery"},
        {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        {"id": "T1070.004", "name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion"},
        {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Persistence"},
        {"id": "T1218.011", "name": "Rundll32 Proxy Execution", "tactic": "Defense Evasion"},
        {"id": "T1003", "name": "Credential Access Indicator", "tactic": "Credential Access"},
    ]


@router.get("/simulate/history")
async def sim_history() -> list[dict]:
    s = _get_state()
    if not hasattr(s, '_sim_campaigns'):
        return []
    return [sim.to_dict(camp) for sim, camp in s._sim_campaigns[-10:]]


# ── Chat — Natural Language Interface ─────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    session_id: str = "default"


@router.post("/chat")
async def chat(req: ChatRequest) -> dict[str, Any]:
    s = _get_state()
    from artemis.ai.chat import ChatEngine
    from artemis.core.threat_classifier import classifier

    # Lazy-init chat engine on app state
    if not hasattr(s, '_chat_engine'):
        s._chat_engine = ChatEngine(s.db, s.ai, classifier)

    msg = await s._chat_engine.process(req.message, req.session_id)
    return {
        "response": msg.content,
        "data": msg.data,
        "timestamp": msg.timestamp,
    }


# ── Reports ───────────────────────────────────────────────────────────

@router.get("/report")
async def generate_report_endpoint() -> Any:
    """Generate and return an HTML security report."""
    from fastapi.responses import HTMLResponse
    from artemis.reporting.generator import generate_report
    from artemis.core.threat_classifier import classifier

    s = _get_state()
    html = await generate_report(
        db=s.db,
        classifier=classifier,
        ai_provider=s.ai,
        network_scanner=s.network,
        edr_plugins=s.edr_plugins,
        start_time=s.start_time,
    )
    return HTMLResponse(content=html)


@router.post("/report/save")
async def save_report() -> dict[str, str]:
    """Generate and save report to disk."""
    from artemis.reporting.generator import generate_report
    from artemis.core.threat_classifier import classifier

    s = _get_state()
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = f"reports/artemis_report_{timestamp}.html"

    await generate_report(
        db=s.db,
        classifier=classifier,
        ai_provider=s.ai,
        network_scanner=s.network,
        edr_plugins=s.edr_plugins,
        start_time=s.start_time,
        output_path=output_path,
    )
    return {"status": "saved", "path": output_path}


@router.get("/chat/history")
async def chat_history(session_id: str = "default") -> list[dict]:
    s = _get_state()
    if not hasattr(s, '_chat_engine'):
        return []
    session = s._chat_engine.sessions.get(session_id)
    if not session:
        return []
    return [
        {"role": m.role, "content": m.content, "timestamp": m.timestamp}
        for m in session.messages
    ]
