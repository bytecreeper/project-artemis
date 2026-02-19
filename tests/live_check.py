"""Check all endpoints against the live server."""
import urllib.request
import json

BASE = "http://127.0.0.1:8000"

endpoints = [
    "/api/stats", "/api/alerts", "/api/alerts/plain", "/api/alerts/summary",
    "/api/network/hosts", "/api/edr/status", "/api/events?limit=3",
    "/api/security-score", "/api/simulate/history", "/api/chat/history",
    "/api/report", "/api/investigations",
    "/api/findings?active_only=true", "/api/remediation/history",
    "/api/scan/scanners", "/api/simulate/techniques",
]

print("=== LIVE SERVER API CHECK ===")
for ep in endpoints:
    try:
        r = urllib.request.urlopen(f"{BASE}{ep}", timeout=10)
        status = r.status
        icon = "PASS" if status == 200 else "FAIL"
        print(f"  [{icon}] {ep} -> {status}")
    except Exception as e:
        print(f"  [FAIL] {ep} -> {e}")

print("\n=== LIVE PAGE CHECKS ===")
pages = [
    ("/", "Shield", "logo_shield.png"),
    ("/ops", "Archer", "logo_archer.png"),
    ("/dashboard", "Archer", "logo_archer.png"),
    ("/guardian", "Archer", "logo_archer.png"),
    ("/hunt", "Archer", "logo_archer.png"),
    ("/alerts", "Shield", "logo_shield.png"),
    ("/alerts?mode=ops", "Archer", "logo_archer.png"),
    ("/scan", "Shield", "logo_shield.png"),
    ("/scan?mode=ops", "Archer", "logo_archer.png"),
    ("/chat", "Shield", "logo_shield.png"),
    ("/chat?mode=ops", "Archer", "logo_archer.png"),
    ("/reports", "Shield", "logo_shield.png"),
    ("/reports?mode=ops", "Archer", "logo_archer.png"),
    ("/settings", "Shield", "logo_shield.png"),
    ("/settings?mode=ops", "Archer", "logo_archer.png"),
    ("/network", "Shield", "logo_shield.png"),
    ("/network?mode=ops", "Archer", "logo_archer.png"),
    ("/events", "Archer", "logo_archer.png"),
    ("/simulate", "Archer", "logo_archer.png"),
    ("/generate", "Archer", "logo_archer.png"),
]

for url, expected, marker in pages:
    try:
        r = urllib.request.urlopen(f"{BASE}{url}", timeout=5)
        html = r.read().decode()
        actual = expected if marker in html else ("Shield" if "logo_shield.png" in html else "Archer")
        ok = marker in html
        icon = "PASS" if ok else "FAIL"
        print(f"  [{icon}] {url} -> expected={expected} actual={actual}")
    except Exception as e:
        print(f"  [FAIL] {url} -> {e}")

print("\n=== POST ENDPOINTS ===")
# Chat
try:
    data = json.dumps({"message": "status", "session_id": "audit"}).encode()
    req = urllib.request.Request(f"{BASE}/api/chat", data=data, headers={"Content-Type": "application/json"})
    r = urllib.request.urlopen(req, timeout=10)
    print(f"  [PASS] POST /api/chat -> {r.status}")
except Exception as e:
    print(f"  [FAIL] POST /api/chat -> {e}")

# Report save
try:
    req = urllib.request.Request(f"{BASE}/api/report/save", method="POST")
    r = urllib.request.urlopen(req, timeout=10)
    print(f"  [PASS] POST /api/report/save -> {r.status}")
except Exception as e:
    print(f"  [FAIL] POST /api/report/save -> {e}")
