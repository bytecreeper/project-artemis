"""Admin privilege enforcement.

Artemis is a security tool — it MUST run as Administrator to:
- Read Sysmon event logs
- Monitor all processes (not just user-owned)
- Manage firewall rules for remediation
- Quarantine files
"""

from __future__ import annotations

import ctypes
import logging
import sys

logger = logging.getLogger("artemis.admin")


def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        # Non-Windows — check for root
        import os
        return os.getuid() == 0


def require_admin() -> None:
    """Exit with a clear message if not running as Administrator.

    Call this at startup before any components initialize.
    """
    if is_admin():
        logger.info("Running with administrator privileges")
        return

    print("\n" + "=" * 60)
    print("  ARTEMIS — Administrator Privileges Required")
    print("=" * 60)
    print()
    print("  Artemis is a security monitoring tool that requires")
    print("  elevated privileges to function properly.")
    print()
    print("  Without admin access, Artemis cannot:")
    print("    - Read Sysmon event logs")
    print("    - Monitor all system processes")
    print("    - Apply firewall rules")
    print("    - Quarantine malicious files")
    print()
    print("  To fix: Right-click your terminal and select")
    print('  "Run as Administrator", then start Artemis again.')
    print()
    print("=" * 60)
    sys.exit(1)
