"""Test adversary simulation."""
import httpx
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

print("\n=== Adversary Simulation Tests ===\n")

with httpx.Client(base_url=BASE, timeout=180) as c:

    # Techniques list
    print("[Technique Registry]")
    r = c.get("/api/simulate/techniques")
    check("GET techniques", r.status_code == 200)
    techs = r.json()
    check("Has 12 techniques", len(techs) == 12, f"got {len(techs)}")
    ids = [t["id"] for t in techs]
    check("Has T1059.001", "T1059.001" in ids)
    check("Has T1547.001", "T1547.001" in ids)
    check("Has T1003", "T1003" in ids)

    # Simulate page
    print("\n[Simulate Page]")
    r = c.get("/simulate")
    check("GET /simulate", r.status_code == 200)
    check("simulate.html rendered", "simApp" in r.text)
    check("Has run button", "RUN ALL" in r.text)

    # Run simulation (this is the big one)
    print("\n[Run Campaign]")
    r = c.post("/api/simulate", json={})
    check("POST /api/simulate", r.status_code == 200)
    data = r.json()
    check("Has techniques_run", "techniques_run" in data)
    check("Has detected count", "detected" in data)
    check("Has missed count", "missed" in data)
    check("Has coverage_pct", "coverage_pct" in data)
    check("Has results list", isinstance(data.get("results"), list))
    check("12 results", len(data.get("results", [])) == 12, f"got {len(data.get('results', []))}")

    # Check result structure
    if data.get("results"):
        r0 = data["results"][0]
        check("Result has technique_id", bool(r0.get("technique_id")))
        check("Result has technique_name", bool(r0.get("technique_name")))
        check("Result has tactic", bool(r0.get("tactic")))
        check("Result has status", r0.get("status") in ("detected", "missed", "error"))
        check("Result has detected flag", "detected" in r0)
        check("Result has artifacts_cleaned", r0.get("artifacts_cleaned") is True)

    # Print coverage report
    print(f"\n  Coverage: {data.get('coverage_pct', 0)}%")
    print(f"  Detected: {data.get('detected', 0)}/{data.get('techniques_run', 0)}")
    for r_item in data.get("results", []):
        status_icon = "✓" if r_item["detected"] else "✗" if r_item["status"] == "missed" else "⚠"
        print(f"    {status_icon} {r_item['technique_id']} {r_item['technique_name']} — {r_item['status']}")

    # History
    print("\n[History]")
    r = c.get("/api/simulate/history")
    check("GET history", r.status_code == 200)
    check("History has campaign", len(r.json()) >= 1)

    # Nav
    print("\n[Navigation]")
    r = c.get("/ops")
    check("Ops nav has Red Team", "Red Team" in r.text)

print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed out of {passed+failed}")
print(f"{'='*50}\n")
sys.exit(0 if failed == 0 else 1)
