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
