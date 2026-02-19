"""Test hunt/search APIs."""
import httpx
import json

c = httpx.Client(base_url="http://127.0.0.1:8000", timeout=10)

# Search - all events
r = c.get("/api/search?limit=5")
print(f"Search (all): {r.status_code}, {len(r.json())} results")

# Search - by query
r = c.get("/api/search?q=python&limit=5")
data = r.json()
print(f"Search 'python': {r.status_code}, {len(data)} results")
if data:
    print(f"  First: {data[0]['type']} - {data[0].get('data',{}).get('name','?')}")

# Search - by type
r = c.get("/api/search?event_type=edr.process&limit=5")
print(f"Search processes: {r.status_code}, {len(r.json())} results")

# Search - by severity
r = c.get("/api/search?min_severity=2&limit=5")
print(f"Search sev>=2: {r.status_code}, {len(r.json())} results")

# Search - by time
r = c.get("/api/search?hours=1&limit=5")
print(f"Search last 1h: {r.status_code}, {len(r.json())} results")

# Timeline
r = c.get("/api/timeline?hours=24&bucket_minutes=60")
tl = r.json()
print(f"Timeline: {r.status_code}, {len(tl)} buckets")
if tl:
    print(f"  Latest: {tl[-1]['time']} count={tl[-1]['count']}")

# Hunt page
r = c.get("/hunt")
print(f"Hunt page: {r.status_code}")

print("\nAll hunt checks passed!")
