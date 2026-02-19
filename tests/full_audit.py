"""Full system audit — every page, API, link, asset."""

import asyncio
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from httpx import AsyncClient, ASGITransport
from artemis.web.app import create_app

# Import scanner plugins to register them
import artemis.scanner.plugins
import artemis.scanner.config_audit

app = create_app()
passed = 0
failed = 0
issues = []


def check(label, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        print(f"  [PASS] {label}" + (f" — {detail}" if detail else ""))
    else:
        failed += 1
        issues.append(f"{label}: {detail}")
        print(f"  [FAIL] {label}" + (f" — {detail}" if detail else ""))


async def audit():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", timeout=30) as c:

        # ═══════════════════════════════════════
        # 1. PAGE ROUTES
        # ═══════════════════════════════════════
        print("\n=== 1. PAGE ROUTES ===")
        pages = [
            ("/", "simple", "Shield Home"),
            ("/ops", "ops", "Archer Dashboard"),
            ("/dashboard", "ops", "Dashboard alias"),
            ("/guardian", "ops", "Guardian"),
            ("/hunt", "ops", "Hunt"),
            ("/alerts", "simple", "Alerts default"),
            ("/alerts?mode=ops", "ops", "Alerts ops"),
            ("/network", "simple", "Network default"),
            ("/network?mode=ops", "ops", "Network ops"),
            ("/events", "ops", "Events"),
            ("/scan", "simple", "Scan default"),
            ("/scan?mode=simple", "simple", "Scan simple explicit"),
            ("/scan?mode=ops", "ops", "Scan ops"),
            ("/simulate", "ops", "Simulate"),
            ("/generate", "ops", "Rule Gen"),
            ("/reports", "simple", "Reports default"),
            ("/reports?mode=ops", "ops", "Reports ops"),
            ("/reports?mode=simple", "simple", "Reports simple explicit"),
            ("/chat", "simple", "Chat default"),
            ("/chat?mode=ops", "ops", "Chat ops"),
            ("/settings", "simple", "Settings default"),
            ("/settings?mode=ops", "ops", "Settings ops"),
        ]

        for url, expected_mode, label in pages:
            r = await c.get(url)
            content = r.text
            has_shield = "logo_shield.png" in content
            has_archer = "logo_archer.png" in content
            actual_mode = "simple" if has_shield else ("ops" if has_archer else "unknown")
            mode_ok = actual_mode == expected_mode
            check(
                f"{label} ({url})",
                r.status_code == 200 and mode_ok,
                f"status={r.status_code} mode={actual_mode}" + ("" if mode_ok else f" EXPECTED={expected_mode}"),
            )

        # ═══════════════════════════════════════
        # 2. API GET ENDPOINTS
        # ═══════════════════════════════════════
        print("\n=== 2. API GET ENDPOINTS ===")
        api_gets = [
            ("/api/stats", "Stats"),
            ("/api/alerts", "Alerts"),
            ("/api/alerts/plain", "Plain Alerts"),
            ("/api/alerts/summary", "Alert Summary"),
            ("/api/network/hosts", "Network Hosts"),
            ("/api/edr/status", "EDR Status"),
            ("/api/events?limit=5", "Events"),
            ("/api/security-score", "Security Score"),
            ("/api/findings?active_only=true", "Findings"),
            ("/api/remediation/history", "Remediation History"),
            ("/api/scan/scanners", "Scanner List"),
            ("/api/simulate/techniques", "Sim Techniques"),
            ("/api/simulate/history", "Sim History"),
            ("/api/chat/history", "Chat History"),
            ("/api/report", "Report Gen"),
            ("/api/investigations", "Investigations"),
        ]

        for url, label in api_gets:
            r = await c.get(url)
            try:
                data = r.json()
                if isinstance(data, list):
                    detail = f"list[{len(data)}]"
                elif isinstance(data, dict):
                    keys = list(data.keys())[:4]
                    detail = f"dict keys={keys}"
                else:
                    detail = str(data)[:50]
            except Exception:
                detail = f"non-json ({len(r.content)} bytes)"
            check(f"GET {label}", r.status_code == 200, f"{r.status_code} {detail}")

        # ═══════════════════════════════════════
        # 3. API POST ENDPOINTS
        # ═══════════════════════════════════════
        print("\n=== 3. API POST ENDPOINTS ===")

        r = await c.post("/api/chat", json={"message": "status", "session_id": "audit"})
        check("POST Chat", r.status_code == 200, f"{r.status_code}")

        r = await c.post("/api/report/save")
        check("POST Report Save", r.status_code == 200, f"{r.status_code}")

        r = await c.post("/api/findings/nonexistent/dismiss")
        check("POST Finding Dismiss (404)", r.status_code == 404, f"{r.status_code}")

        r = await c.post("/api/alerts/nonexistent/dismiss")
        check("POST Alert Dismiss (404)", r.status_code == 404, f"{r.status_code}")

        r = await c.post("/api/investigate", json={})
        check("POST Investigate (400/422)", r.status_code in (400, 422), f"{r.status_code}")

        # ═══════════════════════════════════════
        # 4. SHIELD NAV LINK WIRING
        # ═══════════════════════════════════════
        print("\n=== 4. SHIELD SIDEBAR LINK WIRING ===")
        r = await c.get("/")
        shield_html = r.text

        # Extract sidebar links only (between <nav class="sidebar"> and </nav>)
        sidebar_match = re.search(r'<nav class="sidebar">(.*?)</nav>', shield_html, re.DOTALL)
        if sidebar_match:
            sidebar = sidebar_match.group(1)
            links = re.findall(r'href="([^"]+)"', sidebar)
            # Remove image/static links
            nav_links = [l for l in links if not l.startswith("/static") and not l.startswith("http")]
            for link in nav_links:
                r2 = await c.get(link)
                has_shield = "logo_shield.png" in r2.text
                mode = "Shield" if has_shield else "Archer"
                check(f"Shield nav → {link}", has_shield, f"renders as {mode}")

        # ═══════════════════════════════════════
        # 5. ARCHER NAV LINK WIRING
        # ═══════════════════════════════════════
        print("\n=== 5. ARCHER SIDEBAR LINK WIRING ===")
        r = await c.get("/ops")
        archer_html = r.text

        sidebar_match = re.search(r'<nav class="sidebar">(.*?)</nav>', archer_html, re.DOTALL)
        if sidebar_match:
            sidebar = sidebar_match.group(1)
            links = re.findall(r'href="([^"]+)"', sidebar)
            nav_links = [l for l in links if not l.startswith("/static") and not l.startswith("http")]
            for link in nav_links:
                r2 = await c.get(link)
                has_archer = "logo_archer.png" in r2.text
                mode = "Archer" if has_archer else "Shield"
                check(f"Archer nav → {link}", has_archer, f"renders as {mode}")

        # ═══════════════════════════════════════
        # 6. HEADER MODE TOGGLE
        # ═══════════════════════════════════════
        print("\n=== 6. MODE TOGGLE ===")
        r = await c.get("/")
        check("Shield page has SHIELD toggle", "SHIELD" in r.text and "ARCHER" in r.text)
        check("Shield toggle: SHIELD is active", 'active-mode' in r.text)

        r = await c.get("/ops")
        check("Archer page has toggle", "SHIELD" in r.text and "ARCHER" in r.text)

        # ═══════════════════════════════════════
        # 7. SHIELD HOME CONTENT
        # ═══════════════════════════════════════
        print("\n=== 7. SHIELD HOME CONTENT ===")
        r = await c.get("/")
        h = r.text
        check("Score orb element", "shield-orb" in h)
        check("Fetches security-score", "/api/security-score" in h)
        check("Fetches findings", "/api/findings" in h)
        check("Fetches plain alerts", "/api/alerts/plain" in h)
        check("Fetches stats", "/api/stats" in h)
        check("Protection Status section", "Protection Status" in h)
        check("Quick Actions section", "Quick Actions" in h)
        check("Ask Artemis button", "Ask Artemis" in h)
        check("Security Check button", "Security Check" in h or "Run Security Check" in h)
        check("Generate Report button", "Generate Report" in h)
        check("Dismiss finding function", "dismissFinding" in h)
        check("All Clear state", "All Clear" in h)

        # ═══════════════════════════════════════
        # 8. ARCHER DASHBOARD CONTENT
        # ═══════════════════════════════════════
        print("\n=== 8. ARCHER DASHBOARD CONTENT ===")
        r = await c.get("/ops")
        h = r.text
        check("Timeline chart canvas", "timelineChart" in h)
        check("Severity chart canvas", "severityChart" in h)
        check("Chart.js new Chart calls", "new Chart" in h)
        check("Event feed element", "event-feed" in h)
        check("Host grid", "host-grid" in h or "host-tile" in h)
        check("EDR status section", "EDR" in h)
        check("Fetches /api/stats", "/api/stats" in h)
        check("Fetches /api/alerts", "/api/alerts" in h)
        check("Fetches /api/events", "/api/events" in h)
        check("Fetches /api/network/hosts", "/api/network/hosts" in h)
        check("Fetches /api/edr/status", "/api/edr/status" in h)
        check("Auto-refresh interval", "setInterval" in h)
        check("Severity breakdown", "severityBreakdown" in h)

        # ═══════════════════════════════════════
        # 9. ALERTS PAGE
        # ═══════════════════════════════════════
        print("\n=== 9. ALERTS PAGE ===")
        r = await c.get("/alerts")
        h = r.text
        check("Alerts page renders", r.status_code == 200)
        check("Has simple/technical toggle", "SIMPLE VIEW" in h or "TECHNICAL VIEW" in h)
        check("Fetches /api/alerts/plain", "/api/alerts/plain" in h)
        check("Fetches /api/alerts/summary", "/api/alerts/summary" in h)
        check("Dismiss function", "dismiss" in h.lower())

        # ═══════════════════════════════════════
        # 10. CHAT PAGE
        # ═══════════════════════════════════════
        print("\n=== 10. CHAT PAGE ===")
        r = await c.get("/chat")
        h = r.text
        check("Chat page renders", r.status_code == 200)
        check("Chat input", "message" in h.lower() or "input" in h.lower())
        check("Chat API endpoint", "/api/chat" in h)

        # ═══════════════════════════════════════
        # 11. SCAN PAGE
        # ═══════════════════════════════════════
        print("\n=== 11. SCAN PAGE ===")
        r = await c.get("/scan?mode=simple")
        h = r.text
        check("Scan page renders (Shield)", r.status_code == 200)
        check("Scan page in Shield mode", "logo_shield.png" in h)
        check("Scanner list endpoint", "/api/scan/scanners" in h)
        check("Run scan button", "scan" in h.lower())

        r = await c.get("/scan?mode=ops")
        check("Scan page renders (Archer)", r.status_code == 200)
        check("Scan page in Archer mode", "logo_archer.png" in r.text)

        # ═══════════════════════════════════════
        # 12. SIMULATE PAGE
        # ═══════════════════════════════════════
        print("\n=== 12. SIMULATE PAGE ===")
        r = await c.get("/simulate")
        h = r.text
        check("Simulate page renders", r.status_code == 200)
        check("In Archer mode", "logo_archer.png" in h)
        check("Run button", "RUN ALL" in h or "SIMULAT" in h.upper())
        check("Techniques endpoint", "/api/simulate/techniques" in h)

        # ═══════════════════════════════════════
        # 13. REPORTS PAGE
        # ═══════════════════════════════════════
        print("\n=== 13. REPORTS PAGE ===")
        r = await c.get("/reports?mode=simple")
        check("Reports page (Shield)", r.status_code == 200 and "logo_shield.png" in r.text)
        r = await c.get("/reports?mode=ops")
        check("Reports page (Archer)", r.status_code == 200 and "logo_archer.png" in r.text)

        # ═══════════════════════════════════════
        # 14. SCANNER REGISTRY
        # ═══════════════════════════════════════
        print("\n=== 14. SCANNER REGISTRY ===")
        r = await c.get("/api/scan/scanners")
        scanners = r.json()
        registered = [s["name"] for s in scanners]
        expected = [
            "port_scanner", "ssl_checker", "smb_checker", "default_creds",
            "windows_config", "password_policy", "audit_policy",
            "powershell_policy", "network_shares", "autorun_check",
        ]
        for name in expected:
            check(f"Scanner: {name}", name in registered)

        # ═══════════════════════════════════════
        # 15. SIMULATION TECHNIQUES
        # ═══════════════════════════════════════
        print("\n=== 15. SIMULATION TECHNIQUES ===")
        r = await c.get("/api/simulate/techniques")
        techs = r.json()
        check(f"12 techniques registered", len(techs) == 12, f"got {len(techs)}")
        tech_ids = [t["id"] for t in techs]
        for tid in ["T1059.001", "T1059.003", "T1547.001", "T1003", "T1046"]:
            check(f"Technique {tid}", tid in tech_ids)

        # ═══════════════════════════════════════
        # 16. STATIC ASSETS
        # ═══════════════════════════════════════
        print("\n=== 16. STATIC ASSETS ===")
        assets = [
            "/static/css/artemis.css",
            "/static/img/favicon.png",
            "/static/img/favicon_32.png",
            "/static/img/icon_192.png",
            "/static/img/logo_shield.png",
            "/static/img/logo_shield_sm.png",
            "/static/img/logo_archer.png",
            "/static/img/logo_archer_sm.png",
            "/static/img/logo_main.png",
        ]
        for asset in assets:
            r = await c.get(asset)
            size_kb = len(r.content) / 1024
            check(f"Asset: {asset}", r.status_code == 200, f"{size_kb:.1f} KB")

        # ═══════════════════════════════════════
        # 17. CSS CHECKS
        # ═══════════════════════════════════════
        print("\n=== 17. CSS INTEGRITY ===")
        r = await c.get("/static/css/artemis.css")
        css = r.text
        check("Font imports", "@import" in css and "Inter" in css)
        check("Shield orb styles", ".shield-orb" in css)
        check("Archer feed styles", ".event-feed" in css)
        check("Card glass styles", ".card-glass" in css)
        check("Animation keyframes", "@keyframes breathe" in css)
        check("Stagger animation", ".stagger" in css)
        check("Stat card hover", ".stat-card:hover" in css)
        check("Host tile styles", ".host-tile" in css)
        check("Badge styles", ".badge.critical" in css)
        check("Responsive breakpoints", "@media" in css)
        check("Sim stat styles", ".sim-stat" in css)

        # ═══════════════════════════════════════
        # 18. GUARDIAN PAGE
        # ═══════════════════════════════════════
        print("\n=== 18. GUARDIAN PAGE ===")
        r = await c.get("/guardian")
        h = r.text
        check("Guardian renders", r.status_code == 200)
        check("Guardian in Archer mode", "logo_archer.png" in h)
        check("Has SSE/EventSource", "EventSource" in h or "event-stream" in h.lower() or "sse" in h.lower())

        # ═══════════════════════════════════════
        # 19. HUNT PAGE
        # ═══════════════════════════════════════
        print("\n=== 19. HUNT PAGE ===")
        r = await c.get("/hunt")
        h = r.text
        check("Hunt renders", r.status_code == 200)
        check("Hunt in Archer mode", "logo_archer.png" in h)
        check("Search functionality", "search" in h.lower())

        # ═══════════════════════════════════════
        # 20. SETTINGS PAGE
        # ═══════════════════════════════════════
        print("\n=== 20. SETTINGS PAGE ===")
        r = await c.get("/settings")
        check("Settings renders (Shield)", r.status_code == 200 and "logo_shield.png" in r.text)
        r = await c.get("/settings?mode=ops")
        check("Settings renders (Archer)", r.status_code == 200 and "logo_archer.png" in r.text)

        # ═══════════════════════════════════════
        # 21. REPORT GENERATION CONTENT
        # ═══════════════════════════════════════
        print("\n=== 21. REPORT GENERATION ===")
        r = await c.get("/api/report")
        h = r.text
        check("Report is HTML", r.status_code == 200 and "<html" in h.lower())
        check("Report has title", "artemis" in h.lower() or "security" in h.lower())
        check("Report has score", "score" in h.lower())
        check("Report has findings", "findings" in h.lower() or "finding" in h.lower())
        check("Report has executive summary", "executive" in h.lower() or "summary" in h.lower())
        check("Report is print-ready", "@media print" in h)

    # ═══════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════
    print("\n" + "=" * 60)
    print(f"AUDIT COMPLETE: {passed} passed, {failed} failed")
    print("=" * 60)

    if issues:
        print(f"\n🔴 ISSUES FOUND ({len(issues)}):")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")

    return failed


if __name__ == "__main__":
    fails = asyncio.run(audit())
    sys.exit(0 if fails == 0 else 1)
