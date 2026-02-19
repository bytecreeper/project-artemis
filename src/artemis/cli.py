"""CLI entry point for Artemis."""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(prog="artemis", description="Project Artemis — Security Operations Platform")
    sub = parser.add_subparsers(dest="command")

    # Server
    serve = sub.add_parser("serve", help="Start the web server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")

    # Version
    sub.add_parser("version", help="Show version")

    # Health check
    sub.add_parser("health", help="Check server health")

    args = parser.parse_args()

    if args.command == "serve":
        import uvicorn
        uvicorn.run(
            "artemis.web.app:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            log_level="info",
        )
    elif args.command == "version":
        from artemis import __version__
        print(f"Artemis v{__version__}")
    elif args.command == "health":
        import httpx
        try:
            r = httpx.get("http://127.0.0.1:8000/api/health", timeout=5)
            print(r.json())
        except Exception as e:
            print(f"Server unreachable: {e}")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
