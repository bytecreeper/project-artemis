# Project Artemis v3

AI-powered security operations platform — detection engineering, EDR, network monitoring, and red team capabilities.

Enterprise-grade capabilities without the enterprise price tag. For defenders.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Web UI     │────▶│  Event Bus   │◀────│  Correlation    │
│  (FastAPI)  │     │  (async)     │     │  Engine         │
└─────────────┘     └──────┬───────┘     └─────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
      ┌──────────┐  ┌──────────┐  ┌──────────┐
      │ EDR      │  │ Network  │  │ Rule     │
      │ Plugins  │  │ Scanner  │  │ Generators│
      └──────────┘  └──────────┘  └──────────┘
```

- **Event Bus** — all components communicate through typed events
- **EDR Plugins** — modular, enable/disable per deployment (Sysmon, process monitor, FIM)
- **Correlation Engine** — detects multi-event attack chains with MITRE ATT&CK mapping
- **AI Provider** — swappable (Ollama/OpenAI/none), degrades gracefully
- **DuckDB** — embedded time-series storage, no external database needed

## Quick Start

```bash
# Create venv (Python 3.12+)
python -m venv .venv
.venv\Scripts\activate

# Install
pip install -e ".[dev]"

# Run
python run.py
# → http://127.0.0.1:8000
```

## Configuration

Copy `config/default.toml` to `config/local.toml` and customize.
Environment variables: `ARTEMIS_AI__PROVIDER=openai`, `ARTEMIS_WEB__PORT=9000`, etc.

## Stack

- Python 3.12 | FastAPI | DuckDB | HTMX + Alpine.js
- Ollama/DeepSeek (local AI) | OpenAI (cloud AI) | No-AI fallback
- Sysmon | psutil | scapy | watchdog

## License

MIT
