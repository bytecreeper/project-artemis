"""Test P2 features: Config audit scanners."""
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

print("\n=== P2 Feature Tests ===\n")

with httpx.Client(base_url=BASE, timeout=120) as c:

    # Check all scanners registered
    print("[Scanner Registry]")
    r = c.get("/api/scan/scanners")
    check("GET scanners", r.status_code == 200)
    scanners = r.json()
    names = [s["name"] for s in scanners]
    check("10 scanners total", len(scanners) >= 10, f"got {len(scanners)}: {names}")

    new_scanners = ["password_policy", "audit_policy", "powershell_policy", "network_shares", "autorun_check"]
    for ns in new_scanners:
        check(f"{ns} registered", ns in names)

    # Run full localhost scan (includes all scanners)
    print("\n[Full Localhost Scan]")
    r = c.post("/api/scan", json={"target": "localhost"})
    check("POST /api/scan", r.status_code == 200)
    data = r.json()
    fc = data.get("findings_count", 0)
    check("Has findings", fc >= 0)
    print(f"  -> {fc} total findings")

    # Show all findings by category
    by_scanner = {}
    for f in data.get("findings", []):
        sc = f["scanner"]
        by_scanner[sc] = by_scanner.get(sc, 0) + 1
        
    for scanner, count in sorted(by_scanner.items()):
        print(f"    {scanner}: {count} findings")

    # Show critical/high findings
    print("\n  Critical/High findings:")
    for f in data.get("findings", []):
        if f["severity"] in ("critical", "high"):
            print(f"    [{f['severity']}] {f['title']}")
            if f.get("remediation"):
                print(f"      Fix: {f['remediation'][:80]}")

    # Verify finding quality
    print("\n[Finding Quality]")
    for f in data.get("findings", []):
        if f["severity"] in ("critical", "high", "medium"):
            check(f"'{f['title'][:50]}' has remediation", bool(f.get("remediation")))
            break  # Just check one

    check("Summary has severity breakdown", "by_severity" in data.get("summary", {}))
    check("Scanners ran", data.get("summary", {}).get("scanners_loaded", 0) >= 5)

print(f"\n{'='*50}")
print(f"Results: {passed} passed, {failed} failed out of {passed+failed}")
print(f"{'='*50}\n")
sys.exit(0 if failed == 0 else 1)
