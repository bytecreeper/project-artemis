"""Security Report Generator — human-readable HTML reports.

Generates professional security reports that a non-technical user can
hand to their board, insurer, or MSP. Inspired by Repello AI and CERT-Polska.

Features:
- Executive summary (plain language)
- Security score with color-coded status
- Findings with MITRE ATT&CK mapping
- Remediation steps (prioritized)
- Network inventory
- Event timeline
- Remediation history
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("artemis.reporting")


@dataclass
class ReportData:
    """All data needed to render a report."""
    generated_at: str = ""
    hostname: str = ""
    # Score
    security_score: int = 100
    score_label: str = "Healthy"
    score_color: str = "#00ff41"
    # Counts
    total_events_24h: int = 0
    total_alerts: int = 0
    total_hosts: int = 0
    edr_plugins: int = 0
    uptime_hours: float = 0
    # Detail lists
    findings: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    hosts: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    remediation_history: list[dict] = field(default_factory=list)
    # AI summary
    executive_summary: str = ""


def _score_color(score: int) -> str:
    if score >= 80:
        return "#00ff41"  # Green
    elif score >= 50:
        return "#ffbf00"  # Amber
    else:
        return "#ff3333"  # Red


def _severity_color(severity: str) -> str:
    return {
        "critical": "#ff3333",
        "high": "#ff6633",
        "medium": "#ffbf00",
        "low": "#66ccff",
        "info": "#888888",
    }.get(severity.lower(), "#888888")


def _severity_badge(severity: str) -> str:
    color = _severity_color(severity)
    return f'<span style="background:{color};color:#000;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;text-transform:uppercase;">{severity}</span>'


async def collect_report_data(db, classifier=None, ai_provider=None,
                               network_scanner=None, edr_plugins=None,
                               start_time: float = 0) -> ReportData:
    """Gather all data for report generation."""
    import socket

    data = ReportData()
    data.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        data.hostname = socket.gethostname()
    except Exception:
        data.hostname = "Unknown"

    # Score
    if classifier:
        data.security_score = classifier.security_score
        data.score_label = classifier.score_label
        data.findings = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "description": f.description,
                "evidence": f.evidence,
                "confidence": f.confidence,
                "mitre_id": f.mitre_id or "",
                "mitre_tactic": f.mitre_tactic or "",
                "remediation_id": f.remediation_id or "",
            }
            for f in classifier.active_findings
        ]

    data.score_color = _score_color(data.security_score)

    # Counts
    data.total_events_24h = db.count_events_since(24)
    data.total_alerts = db.count_open_alerts()
    data.total_hosts = db.count_hosts()
    data.edr_plugins = len(edr_plugins) if edr_plugins else 0
    data.uptime_hours = (time.time() - start_time) / 3600 if start_time else 0

    # Hosts
    data.hosts = db.get_hosts()

    # Alerts
    raw_alerts = db.get_open_alerts()
    data.alerts = [
        {"id": a[0], "timestamp": str(a[1]), "title": a[2],
         "description": a[3], "severity": a[4]}
        for a in raw_alerts
    ]

    # Timeline
    try:
        data.timeline = db.get_event_timeline(hours=24, bucket_minutes=60)
    except Exception:
        data.timeline = []

    # Remediation history
    try:
        from artemis.core.remediation import remediation
        data.remediation_history = [r.to_dict() for r in remediation.history]
    except Exception:
        data.remediation_history = []

    # AI executive summary (skip if NullProvider or AI disabled)
    from artemis.ai.provider import NullProvider
    use_ai = ai_provider and not isinstance(ai_provider, NullProvider)
    if use_ai:
        try:
            context = (
                f"Security Score: {data.security_score}/100 ({data.score_label})\n"
                f"Active Findings: {len(data.findings)}\n"
                f"Open Alerts: {data.total_alerts}\n"
                f"Events (24h): {data.total_events_24h}\n"
                f"Network Hosts: {data.total_hosts}\n"
            )
            if data.findings:
                context += "\nTop findings:\n"
                for f in data.findings[:5]:
                    context += f"- [{f['severity']}] {f['title']}: {f['description']}\n"

            import asyncio
            data.executive_summary = await asyncio.wait_for(ai_provider.generate(
                f"Write a 3-4 sentence executive summary of this security report:\n\n{context}",
                system=(
                    "You are writing a security report executive summary for a non-technical audience. "
                    "Be clear, concise, and avoid jargon. State the overall status, highlight any concerns, "
                    "and recommend one key action if needed."
                ),
                temperature=0.3,
            ), timeout=10)
        except Exception as e:
            logger.warning("AI summary failed: %s", e)
            data.executive_summary = ""

    if not data.executive_summary:
        # Deterministic fallback
        if data.security_score >= 80 and len(data.findings) == 0:
            data.executive_summary = (
                f"System security is in good standing with a score of {data.security_score}/100. "
                f"No active security findings were detected. {data.total_events_24h} events were "
                f"processed in the last 24 hours with {data.total_hosts} devices on the network. "
                "No immediate action is required."
            )
        elif data.security_score >= 50:
            data.executive_summary = (
                f"System security score is {data.security_score}/100, indicating some areas need attention. "
                f"{len(data.findings)} security finding(s) were identified. "
                "Review the findings section below for recommended actions."
            )
        else:
            data.executive_summary = (
                f"System security score is {data.security_score}/100, which requires immediate attention. "
                f"{len(data.findings)} security finding(s) were identified, including "
                f"{sum(1 for f in data.findings if f['severity'] in ('critical','high'))} high/critical issues. "
                "Review the findings section and take remediation steps as soon as possible."
            )

    return data


def generate_html_report(data: ReportData) -> str:
    """Render the full HTML report."""

    # Build findings rows
    findings_html = ""
    if data.findings:
        for f in sorted(data.findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x["severity"],5)):
            evidence_items = ""
            if f.get("evidence"):
                for k, v in f["evidence"].items():
                    evidence_items += f"<li><strong>{k}:</strong> {_esc(str(v))}</li>"

            mitre_cell = f'{_esc(f["mitre_id"])}' if f.get("mitre_id") else '<span style="color:#666;">—</span>'

            findings_html += f"""
            <tr>
                <td>{_severity_badge(f['severity'])}</td>
                <td style="font-weight:600;">{_esc(f['title'])}</td>
                <td>{_esc(f['category'])}</td>
                <td><code>{mitre_cell}</code></td>
                <td style="font-size:12px;">{_esc(f['description'])}
                    {'<ul style="margin:4px 0 0;padding-left:16px;font-size:11px;">' + evidence_items + '</ul>' if evidence_items else ''}
                </td>
                <td style="text-align:center;">{int(f.get('confidence',0)*100)}%</td>
            </tr>"""
    else:
        findings_html = '<tr><td colspan="6" style="text-align:center;color:#666;padding:24px;">No active security findings. ✓</td></tr>'

    # Build hosts rows
    hosts_html = ""
    if data.hosts:
        for h in data.hosts[:30]:
            hosts_html += f"""
            <tr>
                <td><code>{_esc(h.get('ip',''))}</code></td>
                <td>{_esc(h.get('hostname','') or '—')}</td>
                <td><code style="font-size:11px;">{_esc(h.get('mac','') or '—')}</code></td>
                <td>{_esc(h.get('os_guess','') or '—')}</td>
                <td style="font-size:11px;">{_esc(str(h.get('last_seen',''))[:19])}</td>
            </tr>"""
    else:
        hosts_html = '<tr><td colspan="5" style="text-align:center;color:#666;padding:24px;">No hosts discovered.</td></tr>'

    # Build alerts rows
    alerts_html = ""
    if data.alerts:
        for a in data.alerts:
            alerts_html += f"""
            <tr>
                <td>{_severity_badge(str(a.get('severity','0')))}</td>
                <td style="font-weight:600;">{_esc(a.get('title',''))}</td>
                <td style="font-size:12px;">{_esc(a.get('description','') or '—')}</td>
                <td style="font-size:11px;">{_esc(str(a.get('timestamp',''))[:19])}</td>
            </tr>"""
    else:
        alerts_html = '<tr><td colspan="4" style="text-align:center;color:#666;padding:24px;">No open alerts. ✓</td></tr>'

    # Remediation history
    remediation_html = ""
    if data.remediation_history:
        for r in data.remediation_history[:20]:
            status_color = "#00ff41" if r.get("success") else "#ff3333"
            remediation_html += f"""
            <tr>
                <td style="font-size:11px;">{_esc(str(r.get('timestamp',''))[:19])}</td>
                <td>{_esc(r.get('action',''))}</td>
                <td style="font-size:12px;">{_esc(r.get('target',''))}</td>
                <td><span style="color:{status_color};font-weight:700;">{'SUCCESS' if r.get('success') else 'FAILED'}</span></td>
            </tr>"""
    else:
        remediation_html = '<tr><td colspan="4" style="text-align:center;color:#666;padding:24px;">No remediation actions taken.</td></tr>'

    # Timeline chart (simple ASCII/CSS bar chart)
    timeline_chart = ""
    if data.timeline:
        max_count = max((t.get("count", 0) for t in data.timeline), default=1)
        for t in data.timeline:
            count = t.get("count", 0)
            pct = (count / max_count * 100) if max_count > 0 else 0
            hour_label = str(t.get("time", ""))[-8:-3]  # HH:MM
            sev = t.get("max_severity", 0)
            bar_color = "#ff3333" if sev >= 8 else "#ffbf00" if sev >= 5 else "#00ff41"
            timeline_chart += f"""
            <div style="display:flex;align-items:center;gap:8px;margin:2px 0;">
                <span style="width:50px;font-size:11px;color:#888;text-align:right;font-family:monospace;">{hour_label}</span>
                <div style="flex:1;background:#1a1a2e;border-radius:2px;height:14px;">
                    <div style="width:{pct}%;background:{bar_color};height:100%;border-radius:2px;min-width:{1 if count else 0}px;"></div>
                </div>
                <span style="width:30px;font-size:11px;color:#888;font-family:monospace;">{count}</span>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Artemis Security Report — {_esc(data.hostname)} — {data.generated_at}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: #0a0a1a;
        color: #e0e0e0;
        line-height: 1.6;
    }}
    .report {{
        max-width: 1100px;
        margin: 0 auto;
        padding: 40px 32px;
    }}
    .report-header {{
        text-align: center;
        margin-bottom: 40px;
        padding-bottom: 24px;
        border-bottom: 2px solid #ffbf00;
    }}
    .report-header h1 {{
        color: #ffbf00;
        font-family: monospace;
        font-size: 28px;
        letter-spacing: 4px;
    }}
    .report-header .meta {{
        color: #888;
        font-size: 13px;
        margin-top: 8px;
    }}
    .score-card {{
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 32px;
        margin: 32px 0;
        padding: 32px;
        background: #111128;
        border-radius: 12px;
        border: 1px solid #222;
    }}
    .score-circle {{
        width: 120px;
        height: 120px;
        border-radius: 50%;
        border: 4px solid {data.score_color};
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;
    }}
    .score-number {{
        font-size: 36px;
        font-weight: 800;
        color: {data.score_color};
        font-family: monospace;
    }}
    .score-label {{
        font-size: 11px;
        color: #888;
        text-transform: uppercase;
        letter-spacing: 1px;
    }}
    .score-details {{ font-size: 14px; }}
    .score-details .metric {{
        display: flex;
        justify-content: space-between;
        padding: 6px 0;
        border-bottom: 1px solid #1a1a2e;
        min-width: 280px;
    }}
    .score-details .metric span:first-child {{ color: #888; }}
    .score-details .metric span:last-child {{ font-family: monospace; font-weight: 600; }}

    .section {{
        margin: 32px 0;
    }}
    .section h2 {{
        color: #ffbf00;
        font-family: monospace;
        font-size: 16px;
        padding: 8px 0;
        border-bottom: 1px solid #333;
        margin-bottom: 16px;
        letter-spacing: 2px;
    }}
    .executive-summary {{
        background: #111128;
        border-left: 3px solid #ffbf00;
        padding: 16px 20px;
        border-radius: 0 8px 8px 0;
        font-size: 15px;
        line-height: 1.7;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 13px;
    }}
    th {{
        text-align: left;
        padding: 10px 12px;
        background: #111128;
        color: #ffbf00;
        font-family: monospace;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1px;
        border-bottom: 2px solid #333;
    }}
    td {{
        padding: 10px 12px;
        border-bottom: 1px solid #1a1a2e;
        vertical-align: top;
    }}
    tr:hover {{ background: rgba(255,191,0,0.03); }}
    code {{
        background: #1a1a2e;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 12px;
    }}
    .footer {{
        text-align: center;
        margin-top: 48px;
        padding-top: 24px;
        border-top: 1px solid #333;
        color: #666;
        font-size: 12px;
    }}
    @media print {{
        body {{ background: #fff; color: #000; }}
        .report-header h1 {{ color: #b8860b; }}
        .section h2 {{ color: #b8860b; }}
        th {{ background: #f0f0f0; color: #333; }}
        td {{ border-bottom-color: #ddd; }}
        .score-card {{ background: #f8f8f8; border-color: #ddd; }}
    }}
</style>
</head>
<body>
<div class="report">

    <div class="report-header">
        <h1>[ ARTEMIS SECURITY REPORT ]</h1>
        <div class="meta">
            Host: {_esc(data.hostname)} &nbsp;|&nbsp;
            Generated: {_esc(data.generated_at)} &nbsp;|&nbsp;
            Artemis v3.0.0
        </div>
    </div>

    <!-- Security Score -->
    <div class="score-card">
        <div class="score-circle">
            <div class="score-number">{data.security_score}</div>
            <div class="score-label">{_esc(data.score_label)}</div>
        </div>
        <div class="score-details">
            <div class="metric"><span>Events (24h)</span><span>{data.total_events_24h}</span></div>
            <div class="metric"><span>Open Alerts</span><span>{data.total_alerts}</span></div>
            <div class="metric"><span>Active Findings</span><span>{len(data.findings)}</span></div>
            <div class="metric"><span>Network Devices</span><span>{data.total_hosts}</span></div>
            <div class="metric"><span>EDR Plugins</span><span>{data.edr_plugins}</span></div>
            <div class="metric"><span>Monitoring Uptime</span><span>{data.uptime_hours:.1f}h</span></div>
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <h2>[ EXECUTIVE SUMMARY ]</h2>
        <div class="executive-summary">{_esc(data.executive_summary)}</div>
    </div>

    <!-- Findings -->
    <div class="section">
        <h2>[ SECURITY FINDINGS ]</h2>
        <table>
            <thead><tr>
                <th>Severity</th><th>Finding</th><th>Category</th>
                <th>MITRE</th><th>Details</th><th>Confidence</th>
            </tr></thead>
            <tbody>{findings_html}</tbody>
        </table>
    </div>

    <!-- Alerts -->
    <div class="section">
        <h2>[ ALERTS ]</h2>
        <table>
            <thead><tr><th>Severity</th><th>Alert</th><th>Description</th><th>Time</th></tr></thead>
            <tbody>{alerts_html}</tbody>
        </table>
    </div>

    <!-- Event Timeline -->
    <div class="section">
        <h2>[ 24-HOUR EVENT TIMELINE ]</h2>
        <div style="background:#111128;border-radius:8px;padding:16px;">
            {timeline_chart if timeline_chart else '<p style="color:#666;text-align:center;padding:16px;">No timeline data available.</p>'}
        </div>
    </div>

    <!-- Network Inventory -->
    <div class="section">
        <h2>[ NETWORK INVENTORY ]</h2>
        <table>
            <thead><tr><th>IP Address</th><th>Hostname</th><th>MAC</th><th>OS</th><th>Last Seen</th></tr></thead>
            <tbody>{hosts_html}</tbody>
        </table>
    </div>

    <!-- Remediation History -->
    <div class="section">
        <h2>[ REMEDIATION ACTIONS ]</h2>
        <table>
            <thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Status</th></tr></thead>
            <tbody>{remediation_html}</tbody>
        </table>
    </div>

    <div class="footer">
        <p>Generated by Project Artemis v3.0.0 — AI-Powered Security Operations</p>
        <p>This report is confidential. Distribute only to authorized personnel.</p>
    </div>

</div>
</body>
</html>"""


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


async def generate_report(db, classifier=None, ai_provider=None,
                           network_scanner=None, edr_plugins=None,
                           start_time: float = 0,
                           output_path: str | Path | None = None) -> str:
    """Generate a full HTML security report. Returns HTML string and optionally saves to file."""
    data = await collect_report_data(
        db, classifier, ai_provider, network_scanner, edr_plugins, start_time
    )
    html = generate_html_report(data)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        logger.info("Report saved to %s", path)

    return html
