"""Test home dashboard, findings, and remediation APIs."""
import httpx
import json

c = httpx.Client(base_url="http://127.0.0.1:8000", timeout=10)

# Security score
r = c.get("/api/security-score")
print(f"Security Score: {r.status_code}")
d = r.json()
print(f"  Score: {d['score']}/100 ({d['label']})")
print(f"  Plugins: {d['edr_plugins_active']}, Hosts: {d['network_hosts']}, Events: {d['events_24h']}")

# Findings
r = c.get("/api/findings")
print(f"\nFindings: {r.status_code}")
d = r.json()
print(f"  Total: {d['finding_count']}, Score: {d['security_score']}")
for f in d["findings"][:5]:
    print(f"  [{f['severity']}] {f['title']} (conf={f['confidence']:.0%})")

# Remediation history
r = c.get("/api/remediation/history")
print(f"\nRemediation history: {r.status_code}, {len(r.json())} actions")

# Home page
r = c.get("/")
print(f"\nHome page: {r.status_code}")
has_score = "score-ring" in r.text
has_findings = "finding-item" in r.text
has_buttons = "btn-danger" in r.text
print(f"  Score ring: {'YES' if has_score else 'NO'}")
print(f"  Finding cards: {'YES' if has_findings else 'NO'}")
print(f"  Action buttons: {'YES' if has_buttons else 'NO'}")

# Dashboard still works
r = c.get("/dashboard")
print(f"\nDashboard: {r.status_code}")

# All other pages
for p in ["/guardian", "/hunt", "/alerts", "/network", "/events", "/generate", "/settings"]:
    r = c.get(p)
    print(f"  {p}: {r.status_code}")

print("\nAll home checks complete!")
