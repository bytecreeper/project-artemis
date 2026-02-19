"""Quick dev server runner."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

if __name__ == "__main__":
    from artemis.core.admin import require_admin, is_admin
    if not is_admin():
        import logging
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger("artemis.admin").warning(
            "Running WITHOUT admin privileges — Sysmon, firewall rules, and some remediations will fail. "
            "For full functionality, run as Administrator."
        )

    import uvicorn
    dev_mode = "--reload" in sys.argv or os.environ.get("ARTEMIS_DEV") == "1"
    uvicorn.run(
        "artemis.web.app:app",
        host="127.0.0.1",
        port=8000,
        log_level="info",
        reload=dev_mode,
        reload_excludes=["tests/*", "data/*", "*.pyc", ".git/*", "reports/*"],
    )
