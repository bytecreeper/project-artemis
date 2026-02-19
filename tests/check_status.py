"""Quick status check for all systems."""
import httpx
import json

c = httpx.Client(base_url="http://127.0.0.1:8000", timeout=5)

# Health
h = c.get("/api/health").json()
print(f"Health: {h['status']}")

# Stats
s = c.get("/api/stats").json()
print(f"Events 24h: {s['events_24h']}, Hosts: {s['network_hosts']}")

# EDR
e = c.get("/api/edr/status").json()
for k, v in e.items():
    print(f"  EDR {k}: {v.get('status','?')} events={v.get('events_processed', v.get('events_emitted', '?'))}")

# All pages
for p in ["/", "/guardian", "/hunt", "/alerts", "/network", "/events", "/generate", "/settings"]:
    r = c.get(p)
    tag = "OK" if r.status_code == 200 else f"FAIL({r.status_code})"
    print(f"  Page {p}: {tag}")

# SSE test
print("\nSSE stream test...")
r = c.send(c.build_request("GET", "/api/events/stream"), stream=True)
print(f"  SSE status: {r.status_code}, type: {r.headers.get('content-type')}")
count = 0
for line in r.iter_lines():
    if line.startswith("data:"):
        count += 1
        if count == 1:
            d = json.loads(line[5:].strip())
            print(f"  First event: {d['event_type']} src={d['source']}")
    if count >= 3:
        break
print(f"  Got {count} events via SSE")
r.close()
print("\nAll checks complete.")
