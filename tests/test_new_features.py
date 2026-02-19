"""Test P0 features: Chat interface, Reports, Home page."""
import httpx
import json
import sys

BASE = "http://127.0.0.1:8000"
passed = 0
failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} — {detail}")

print("\n=== Testing P0 Features ===\n")

with httpx.Client(base_url=BASE, timeout=60) as c:

    # 1. Home page
    print("[Home Page]")
    r = c.get("/")
    check("GET / returns 200", r.status_code == 200)
    check("home.html rendered", "Security Status" in r.text or "ASK ARTEMIS" in r.text or "homeApp" in r.text)

    # 2. Chat page
    print("\n[Chat Page]")
    r = c.get("/chat")
    check("GET /chat returns 200", r.status_code == 200)
    check("chat.html rendered", "chatApp" in r.text)
    check("Quick buttons present", "How" in r.text and "alerts" in r.text.lower())

    # 3. Chat API — status query
    print("\n[Chat API]")
    r = c.post("/api/chat", json={"message": "How is my system?"})
    check("POST /api/chat returns 200", r.status_code == 200)
    data = r.json()
    check("Response has content", len(data.get("response", "")) > 10, data.get("response", "")[:80])
    check("Response has data dict", isinstance(data.get("data"), dict))
    check("Contains score info", "score" in data.get("response", "").lower() or "score" in str(data.get("data", {})).lower())

    # 4. Chat API — alerts query
    r = c.post("/api/chat", json={"message": "Any alerts?"})
    check("Alerts query works", r.status_code == 200)
    check("Alerts response", len(r.json().get("response", "")) > 5)

    # 5. Chat API — network query
    r = c.post("/api/chat", json={"message": "What devices are on my network?"})
    check("Network query works", r.status_code == 200)
    check("Network response", "device" in r.json().get("response", "").lower() or "host" in r.json().get("response", "").lower() or "network" in r.json().get("response", "").lower())

    # 6. Chat API — help
    r = c.post("/api/chat", json={"message": "help"})
    check("Help query works", r.status_code == 200)
    check("Help lists capabilities", "ask" in r.json().get("response", "").lower() or "security" in r.json().get("response", "").lower())

    # 7. Chat API — events query
    r = c.post("/api/chat", json={"message": "What happened today?"})
    check("Events query works", r.status_code == 200)
    check("Events response has content", len(r.json().get("response", "")) > 5)

    # 8. Chat API — score query
    r = c.post("/api/chat", json={"message": "What is my security score?"})
    check("Score query works", r.status_code == 200)
    check("Score in response", "100" in r.json().get("response", "") or "score" in r.json().get("response", "").lower())

    # 9. Chat history
    print("\n[Chat History]")
    r = c.get("/api/chat/history")
    check("GET /api/chat/history returns 200", r.status_code == 200)
    history = r.json()
    check("History is list", isinstance(history, list))
    check("History has messages", len(history) >= 10, f"got {len(history)} messages")

    # 10. Reports page
    print("\n[Reports Page]")
    r = c.get("/reports")
    check("GET /reports returns 200", r.status_code == 200)
    check("reports.html rendered", "reportsApp" in r.text)
    check("Report features listed", "Executive Summary" in r.text)

    # 11. Report generation
    print("\n[Report Generation]")
    r = c.get("/api/report")
    check("GET /api/report returns 200", r.status_code == 200)
    check("Report is HTML", "<!DOCTYPE html>" in r.text)
    check("Report has title", "ARTEMIS SECURITY REPORT" in r.text)
    check("Report has score", "Security Score" in r.text or "score-circle" in r.text)
    check("Report has findings section", "SECURITY FINDINGS" in r.text)
    check("Report has network inventory", "NETWORK INVENTORY" in r.text)
    check("Report has timeline", "TIMELINE" in r.text)
    check("Report has executive summary", "EXECUTIVE SUMMARY" in r.text)
    check("Report has remediation section", "REMEDIATION" in r.text)
    check("Report is print-ready", "@media print" in r.text)

    # 12. Save report
    r = c.post("/api/report/save")
    check("POST /api/report/save returns 200", r.status_code == 200)
    save_data = r.json()
    check("Save returns path", "path" in save_data, str(save_data))

    # 13. Sidebar nav
    print("\n[Navigation]")
    r = c.get("/")
    check("Simple nav has Ask Artemis", "Ask Artemis" in r.text)
    check("Simple nav has Reports", "Reports" in r.text)
    r = c.get("/ops")
    check("Ops nav has Reports", "Reports" in r.text)

print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed out of {passed+failed}")
print(f"{'='*50}\n")
sys.exit(0 if failed == 0 else 1)
