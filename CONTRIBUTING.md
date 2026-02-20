# Contributing to Project Artemis

Thank you for your interest in Project Artemis. This document explains what the project needs, where help is most valuable, and how to get involved.

## What Artemis Is

An AI-assisted endpoint detection and response platform built for small businesses, nonprofits, and resource-constrained organizations. It runs locally on Windows, monitors system activity, detects threats, and explains what is happening in language that non-technical users can understand.

The platform architecture, UI, and analysis layer are functional. What needs the most work now is the security depth — the detection engineering, low-level Windows visibility, and real-world threat coverage that separates a monitoring dashboard from a genuine security tool.

## Where Help Is Needed

These are listed in order of impact. If you have expertise in any of these areas, your contributions would be significant.

### Detection Engineering

The detection layer is the highest priority. Artemis currently has three hardcoded correlation rules and pattern-based threat classification. It needs:

- **YAML-based detection rules** — Externalized rule format that can be loaded, updated, and contributed without code changes. The framework for this is planned but not built.
- **Sigma rule integration** — Artemis generates Sigma rules but does not consume them. Being able to load and evaluate community Sigma rules against the event stream would immediately expand coverage.
- **Sysmon event parsing** — The current Sysmon plugin ingests events generically. Proper parsing of all 26+ event types with field-level extraction would unlock meaningful detection logic.
- **False positive tuning** — A feedback mechanism where dismissed findings adjust detection thresholds over time. Without this, alert fatigue will drive users away.
- **Detection testing** — Running real malware samples in isolated environments against Artemis and documenting what gets caught, what gets missed, and why.

If you write detection rules professionally, understand MITRE ATT&CK at the technique-variation level, or have experience tuning security tools for real environments, this is the area where your work would have the most immediate effect.

### Windows Internals

The current sensor layer uses psutil and Sysmon from userland Python. This works for monitoring but has fundamental visibility limits:

- **ETW (Event Tracing for Windows) integration** — Direct consumption of ETW providers would give Artemis deeper visibility without depending on Sysmon as an intermediary.
- **Windows service implementation** — Artemis currently runs as a console application and stops when the user logs out. It needs to run as a Windows service with automatic startup and self-recovery.
- **Self-protection** — A real EDR protects its own process, database, and configuration from tampering. This requires understanding of Windows security descriptors, process protection levels, and secure storage.
- **Memory and process inspection** — Detection of in-memory threats, process injection, reflective DLL loading, and other techniques that leave no disk artifacts. This is where modern attacks operate.
- **AMSI integration** — The Windows Antimalware Scan Interface exists specifically for tools like Artemis. Integrating it would add a significant detection capability.

This work requires C, C++, or Rust experience and familiarity with Windows kernel interfaces. If you build Windows security tools or drivers, this is where you can make Artemis a fundamentally more capable product.

### Correlation and Analysis

The correlation engine needs to evolve from its current state (three rules, PID-based grouping) into a real analysis layer:

- **Session-based event correlation** — Grouping events by Windows logon session rather than process ID. Related activity across multiple processes in the same session should be linked.
- **Entity relationship modeling** — Building a graph of relationships: process spawned child, process wrote file, process connected to IP, file was loaded by process. Detecting suspicious paths through the graph.
- **Time-proximity scoring** — Events that occur closer together in time should receive higher correlation weight.
- **Behavioral baselining** — Learning what normal activity looks like on a specific machine over time and flagging meaningful deviations. This is the bridge between pattern matching and genuine anomaly detection.

### Frontend and Accessibility

The UI has two modes (Shield for non-technical users, Archer for security professionals) built with HTMX, Alpine.js, and Chart.js. Areas that need work:

- **Shield guided experience** — A security checkup wizard that walks non-technical users through improving their posture step by step. Plain language throughout.
- **Accessibility** — If Artemis is for underserved organizations, it needs to work for all users, including those using screen readers or other assistive technology.
- **Real-time reliability** — The SSE-based live feeds work but need stress testing and graceful reconnection handling.
- **Mobile responsiveness** — Many small organization users will check their security status from a phone.

### Infrastructure and Hardening

- **Encrypted storage** — Findings, alerts, and investigation data sit in plaintext DuckDB. Sensitive security data should be encrypted at rest.
- **Log integrity** — The database file is unprotected. An attacker with file access can delete the evidence trail. Append-only logging or integrity verification would address this.
- **API hardening** — Rate limiting, input validation, CSRF protection, and security headers for the web interface.
- **Installer and packaging** — A Windows installer (Inno Setup or similar) that bundles Python, dependencies, and configures the service. One-click deployment for non-technical users.
- **Update mechanism** — A way to push updated detection rules to deployed instances without requiring a full application update.

## Project Structure

```
project-artemis/
  config/              Configuration files (TOML)
  src/artemis/
    ai/                Chat interface, investigation agent, alert narrator
    core/              Event bus, config, database, auth, threat classifier, remediation
    correlation/       Multi-event correlation engine
    edr/plugins/       Sysmon, process monitor, file integrity monitor
    network/           ARP-based network scanner
    redteam/           Adversary simulation (12 MITRE ATT&CK techniques)
    reporting/         HTML report generation
    scanner/           10 vulnerability and configuration audit scanners
    web/               FastAPI app, templates, static assets, API routes
  tests/               117 tests across 5 test files
```

## Technical Stack

- **Python 3.12** — core application, analysis layer, web server
- **FastAPI + Uvicorn** — web framework and ASGI server
- **DuckDB** — embedded analytics database (no external server)
- **HTMX + Alpine.js** — frontend interactivity without a build step
- **Chart.js** — dashboard visualizations
- **Ollama** — local AI inference (optional, all features work without it)

## Getting Started

1. Clone the repository and follow the installation steps in README.md
2. Run the test suite to verify everything works: `pytest tests/test_p3.py tests/test_p4.py -v`
3. Start the server with `python run.py` and explore both Shield and Archer modes
4. Read through the codebase — start with `core/events.py` (event bus), `core/threat_classifier.py` (detection logic), and `correlation/engine.py` (correlation rules) to understand the architecture
5. Pick an area from the list above and open an issue describing what you want to work on

## Guidelines

- **All detection must be evidence-based.** Findings require proof. No AI guessing about whether something is malicious. AI is for explanation and narration, not classification.
- **Degrade gracefully.** Every feature must work without AI, without Sysmon, without admin privileges. Reduced capability is acceptable. Crashes are not.
- **Test what you build.** The existing test suite covers all modules. New features should include tests.
- **Shield users are not technical.** Anything that surfaces in Shield mode must be understandable by someone who has never opened a terminal. If it requires security knowledge to interpret, it belongs in Archer.
- **No telemetry without consent.** Artemis runs locally. If a feature sends data anywhere — even to a local AI model — the user must know and agree.

## What This Project Is Not

Artemis is not trying to replace CrowdStrike, SentinelOne, or any enterprise EDR. It is not trying to be a comprehensive security program. It is designed to be a practical, accessible layer of protection for organizations that currently have nothing — and to produce clear, structured data that helps security professionals when they do get involved.

The bar is not "detect every APT." The bar is "be genuinely useful to a small nonprofit that currently has no visibility into what is happening on their machines."

## Contact

Open an issue on this repository or reach out directly. All contributions, feedback, and questions are welcome.
