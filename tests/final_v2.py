"""Final v2 check — dual view, all systems."""
import httpx

c = httpx.Client(base_url="http://127.0.0.1:8000", timeout=10)
p = f = 0

def ok(n, cond, d=""):
    global p, f
    if cond: p += 1; print(f"  [OK] {n}")
    else: f += 1; print(f"  [FAIL] {n} -- {d}")

print("=== Views ===")
# Simple view (home)
r = c.get("/")
ok("Home page", r.status_code == 200)
ok("  Has SIMPLE/OPS toggle", "SIMPLE" in r.text and "OPS" in r.text)
ok("  Simple sidebar (Security Status)", "[S] Security Status" in r.text)
ok("  No emojis in home", all(e not in r.text for e in ["🔍", "✓", "✕", "⛨"]))
ok("  Score ring", "score-ring" in r.text)
ok("  Kill action", "TERMINATE PID" in r.text)
ok("  Quarantine action", "QUARANTINE FILE" in r.text)
ok("  Block action", "BLOCK" in r.text and "doBlock" in r.text)
ok("  Evidence panel", "VIEW EVIDENCE" in r.text)

# Ops view
r = c.get("/ops")
ok("Ops dashboard", r.status_code == 200)
ok("  Ops sidebar (Dashboard/Guardian/Hunt)", "[>] Dashboard" in r.text and "[#] Guardian" in r.text)

r = c.get("/guardian")
ok("Guardian", r.status_code == 200)
ok("  Ops mode sidebar", "[~] Hunt" in r.text)
ok("  No emojis", all(e not in r.text for e in ["🔍", "✓", "✕", "●"]))

r = c.get("/hunt")
ok("Hunt", r.status_code == 200)
ok("  No emojis", all(e not in r.text for e in ["🔍"]))

print("\n=== APIs ===")
r = c.get("/api/health"); ok("health", r.status_code == 200)
r = c.get("/api/security-score"); d = r.json()
ok("security-score", d["score"] >= 0 and d["label"] in ["SECURE","FAIR","AT RISK","POOR","CRITICAL"])
r = c.get("/api/findings"); ok("findings", r.status_code == 200 and "findings" in r.json())
r = c.get("/api/remediation/history"); ok("remediation history", r.status_code == 200)
r = c.post("/api/remediate/kill", json={"finding_id":"t","pid":999999,"verify_name":""})
ok("kill (not found)", r.json()["status"] == "not_found")
r = c.post("/api/remediate/quarantine", json={"finding_id":"t","file_path":"C:\\no\\file"})
ok("quarantine (not found)", r.json()["status"] == "not_found")

print("\n=== All Pages ===")
for path in ["/", "/ops", "/dashboard", "/guardian", "/hunt", "/alerts", "/network", "/events", "/generate", "/settings"]:
    r = c.get(path); ok(f"GET {path}", r.status_code == 200)

print(f"\n{'='*40}")
print(f"{p} passed, {f} failed")
if f == 0: print("ALL CHECKS PASSED")
