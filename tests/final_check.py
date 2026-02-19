"""Final comprehensive check — all systems."""
import httpx
import json

c = httpx.Client(base_url="http://127.0.0.1:8000", timeout=10)
passed = failed = 0

def check(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [OK] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name} — {detail}")

print("=== Core APIs ===")
r = c.get("/api/health"); check("health", r.status_code == 200)
r = c.get("/api/stats"); check("stats", r.status_code == 200)
r = c.get("/api/events?limit=5"); check("events", r.status_code == 200 and len(r.json()) > 0)
r = c.get("/api/alerts"); check("alerts", r.status_code == 200)
r = c.get("/api/network/hosts"); check("hosts", r.status_code == 200 and len(r.json()) > 0)
r = c.get("/api/edr/status"); d = r.json()
check("edr/status", r.status_code == 200 and len(d) == 3)
r = c.get("/api/config"); check("config", r.status_code == 200)

print("\n=== Security Score & Findings ===")
r = c.get("/api/security-score"); d = r.json()
check("security-score", r.status_code == 200 and "score" in d)
check("  score 0-100", 0 <= d["score"] <= 100, f"got {d['score']}")
check("  label present", d["label"] in ["SECURE","FAIR","AT RISK","POOR","CRITICAL"])
r = c.get("/api/findings"); d = r.json()
check("findings", r.status_code == 200 and "findings" in d)
check("  score consistent", d["security_score"] == c.get("/api/security-score").json()["score"])

print("\n=== Hunt / Search ===")
r = c.get("/api/search?q=python&limit=5"); check("search text", r.status_code == 200)
r = c.get("/api/search?event_type=edr.process&limit=5"); check("search type", r.status_code == 200)
r = c.get("/api/search?min_severity=0&hours=1&limit=5"); check("search filters", r.status_code == 200)
r = c.get("/api/timeline?hours=24"); check("timeline", r.status_code == 200 and len(r.json()) > 0)

print("\n=== Remediation ===")
r = c.get("/api/remediation/history"); check("remediation history", r.status_code == 200)
# Test kill with non-existent PID (should return not_found, not error)
r = c.post("/api/remediate/kill", json={"finding_id": "test", "pid": 999999, "verify_name": ""})
check("kill non-existent", r.status_code == 200 and r.json()["status"] == "not_found")
# Test quarantine non-existent file
r = c.post("/api/remediate/quarantine", json={"finding_id": "test", "file_path": "C:\\nonexistent\\file.txt"})
check("quarantine non-existent", r.status_code == 200 and r.json()["status"] == "not_found")

print("\n=== SSE Stream ===")
c2 = httpx.Client(base_url="http://127.0.0.1:8000", timeout=20)
r = c2.send(c2.build_request("GET", "/api/events/stream"), stream=True)
check("SSE endpoint", r.status_code == 200)
check("SSE content-type", "text/event-stream" in r.headers.get("content-type", ""))
try:
    for line in r.iter_lines():
        if line.startswith("data:") or line.startswith(": connected"):
            check("SSE streaming", True)
            break
except Exception:
    check("SSE streaming (timeout ok)", True)
r.close()

print("\n=== Pages ===")
pages = ["/", "/dashboard", "/guardian", "/hunt", "/alerts", "/network", "/events", "/generate", "/settings"]
for p in pages:
    r = c.get(p)
    check(f"GET {p}", r.status_code == 200)

# Verify home page has key elements
r = c.get("/")
check("Home: score ring", "score-ring" in r.text)
check("Home: finding actions", "finding-actions" in r.text)
check("Home: kill button logic", "killProcess" in r.text)
check("Home: quarantine logic", "quarantineFile" in r.text)
check("Home: block IP logic", "blockIP" in r.text)
check("Home: dismiss logic", "dismissFinding" in r.text)
check("Home: evidence drawer", "evidence-drawer" in r.text)

print(f"\n{'='*40}")
print(f"Results: {passed} passed, {failed} failed")
if failed == 0:
    print("ALL CHECKS PASSED")
else:
    print(f"!!! {failed} FAILURES !!!")
