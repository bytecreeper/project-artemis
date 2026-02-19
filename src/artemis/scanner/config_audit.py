"""Configuration Auditing — check for weak configs, exposed services, missing hardening.

Runs local checks that don't require network scanning. Inspired by CIS Benchmarks
and CERT-Polska's approach to automated security auditing.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from pathlib import Path

from artemis.scanner.base import (
    ScannerPlugin, ScanTarget, VulnFinding,
    VulnSeverity, VulnCategory,
)

logger = logging.getLogger("artemis.scanner.config_audit")


class PasswordPolicyChecker(ScannerPlugin):
    """Check Windows password policy settings."""

    name = "password_policy"
    description = "Windows password policy audit"
    category = "configuration"

    async def is_applicable(self, target: ScanTarget) -> bool:
        import platform
        return platform.system() == "Windows" and target.host in ("127.0.0.1", "localhost")

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []
        policy = await asyncio.to_thread(self._get_policy)
        if not policy:
            return findings

        min_len = policy.get("min_password_length", 0)
        if min_len < 8:
            findings.append(VulnFinding(
                scanner=self.name, target="localhost",
                severity=VulnSeverity.HIGH,
                category=VulnCategory.MISCONFIGURATION,
                title=f"Weak minimum password length ({min_len} chars)",
                description=f"Minimum password length is set to {min_len}. CIS recommends at least 14 characters.",
                evidence=policy,
                remediation="Set minimum password length to 14+ via Local Security Policy or Group Policy.",
                mitre_id="T1110",
            ))

        max_age = policy.get("max_password_age", 0)
        if max_age == 0 or max_age > 365:
            findings.append(VulnFinding(
                scanner=self.name, target="localhost",
                severity=VulnSeverity.MEDIUM,
                category=VulnCategory.MISCONFIGURATION,
                title="Password expiration not enforced" if max_age == 0 else f"Password max age too long ({max_age} days)",
                description="Passwords should be rotated periodically. CIS recommends max 365 days.",
                evidence=policy,
                remediation="Configure maximum password age in Local Security Policy.",
            ))

        lockout = policy.get("lockout_threshold", 0)
        if lockout == 0:
            findings.append(VulnFinding(
                scanner=self.name, target="localhost",
                severity=VulnSeverity.HIGH,
                category=VulnCategory.MISCONFIGURATION,
                title="Account lockout not configured",
                description="No account lockout threshold is set, allowing unlimited password guessing.",
                evidence=policy,
                remediation="Set account lockout threshold to 5 attempts via Local Security Policy.",
                mitre_id="T1110.001",
            ))

        return findings

    def _get_policy(self) -> dict | None:
        try:
            result = subprocess.run(
                ["net", "accounts"],
                capture_output=True, text=True, timeout=10
            )
            policy = {}
            for line in result.stdout.splitlines():
                if "Minimum password length" in line:
                    val = line.split(":")[-1].strip()
                    policy["min_password_length"] = int(val) if val.isdigit() else 0
                elif "Maximum password age" in line:
                    val = line.split(":")[-1].strip()
                    policy["max_password_age"] = int(val.split()[0]) if val.split()[0].isdigit() else 0
                elif "Lockout threshold" in line:
                    val = line.split(":")[-1].strip()
                    policy["lockout_threshold"] = int(val) if val != "Never" and val.isdigit() else 0
                elif "Minimum password age" in line:
                    val = line.split(":")[-1].strip()
                    policy["min_password_age"] = int(val.split()[0]) if val.split()[0].isdigit() else 0
            return policy if policy else None
        except Exception:
            return None


class AuditPolicyChecker(ScannerPlugin):
    """Check Windows audit policy configuration."""

    name = "audit_policy"
    description = "Windows audit/logging policy check"
    category = "configuration"

    async def is_applicable(self, target: ScanTarget) -> bool:
        import platform
        return platform.system() == "Windows" and target.host in ("127.0.0.1", "localhost")

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []
        policies = await asyncio.to_thread(self._get_audit_policy)
        if not policies:
            return findings

        # Critical audit categories that should have Success and/or Failure enabled
        required = {
            "Logon": ("Logon/Logoff events", VulnSeverity.HIGH),
            "Account Logon": ("Account logon attempts", VulnSeverity.HIGH),
            "Object Access": ("File/registry access monitoring", VulnSeverity.MEDIUM),
            "Privilege Use": ("Privilege escalation tracking", VulnSeverity.MEDIUM),
            "Process Creation": ("Process creation events", VulnSeverity.HIGH),
            "Policy Change": ("Security policy changes", VulnSeverity.MEDIUM),
        }

        for category, (desc, severity) in required.items():
            found = False
            for policy_name, setting in policies.items():
                if category.lower() in policy_name.lower():
                    found = True
                    if "No Auditing" in setting:
                        findings.append(VulnFinding(
                            scanner=self.name, target="localhost",
                            severity=severity,
                            category=VulnCategory.MISCONFIGURATION,
                            title=f"Audit policy disabled: {category}",
                            description=f"{desc} are not being audited. This limits incident investigation capability.",
                            evidence={"category": category, "setting": setting},
                            remediation=f"Enable auditing for {category} via auditpol or Group Policy.",
                            mitre_id="T1562.002",
                        ))
                    break

        return findings

    def _get_audit_policy(self) -> dict | None:
        try:
            result = subprocess.run(
                ["auditpol", "/get", "/category:*"],
                capture_output=True, text=True, timeout=10
            )
            policies = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("System") and not line.startswith("Machine"):
                    parts = line.rsplit("  ", 1)
                    if len(parts) == 2:
                        policies[parts[0].strip()] = parts[1].strip()
            return policies if policies else None
        except Exception:
            return None


class PowerShellPolicyChecker(ScannerPlugin):
    """Check PowerShell security configuration."""

    name = "powershell_policy"
    description = "PowerShell execution and logging policy"
    category = "configuration"

    async def is_applicable(self, target: ScanTarget) -> bool:
        import platform
        return platform.system() == "Windows" and target.host in ("127.0.0.1", "localhost")

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []

        # Check execution policy
        exec_policy = await asyncio.to_thread(self._check_execution_policy)
        if exec_policy and exec_policy.lower() in ("unrestricted", "bypass"):
            findings.append(VulnFinding(
                scanner=self.name, target="localhost",
                severity=VulnSeverity.MEDIUM,
                category=VulnCategory.MISCONFIGURATION,
                title=f"PowerShell execution policy is '{exec_policy}'",
                description="Unrestricted execution policy allows any script to run. Attackers commonly use PowerShell for post-exploitation.",
                evidence={"execution_policy": exec_policy},
                remediation="Set execution policy to RemoteSigned or AllSigned: Set-ExecutionPolicy RemoteSigned",
                mitre_id="T1059.001",
            ))

        # Check script block logging
        logging_enabled = await asyncio.to_thread(self._check_script_logging)
        if not logging_enabled:
            findings.append(VulnFinding(
                scanner=self.name, target="localhost",
                severity=VulnSeverity.MEDIUM,
                category=VulnCategory.MISCONFIGURATION,
                title="PowerShell script block logging is disabled",
                description="Script block logging records the content of all PowerShell scripts that are executed. Without it, malicious scripts leave no trace.",
                evidence={"script_block_logging": False},
                remediation="Enable via Group Policy: Computer Config > Admin Templates > Windows Components > PowerShell > Turn on Script Block Logging",
                mitre_id="T1562.002",
            ))

        return findings

    def _check_execution_policy(self) -> str | None:
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-ExecutionPolicy"],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except Exception:
            return None

    def _check_script_logging(self) -> bool:
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            )
            val, _ = winreg.QueryValueEx(key, "EnableScriptBlockLogging")
            winreg.CloseKey(key)
            return val == 1
        except Exception:
            return False


class NetworkShareChecker(ScannerPlugin):
    """Check for exposed network shares."""

    name = "network_shares"
    description = "Network share exposure check"
    category = "configuration"

    async def is_applicable(self, target: ScanTarget) -> bool:
        import platform
        return platform.system() == "Windows" and target.host in ("127.0.0.1", "localhost")

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []
        shares = await asyncio.to_thread(self._get_shares)

        # Default admin shares are expected (C$, ADMIN$, IPC$)
        admin_shares = {"C$", "D$", "ADMIN$", "IPC$", "print$"}

        for share in shares:
            name = share.get("name", "")
            if name in admin_shares:
                continue  # Skip default admin shares

            perms = share.get("permissions", "")
            if "Everyone" in perms or "ANONYMOUS" in perms.upper():
                findings.append(VulnFinding(
                    scanner=self.name, target="localhost",
                    severity=VulnSeverity.HIGH,
                    category=VulnCategory.MISCONFIGURATION,
                    title=f"Network share '{name}' accessible to Everyone",
                    description=f"The share '{name}' ({share.get('path', '?')}) is accessible to all users, which could expose sensitive data.",
                    evidence=share,
                    remediation=f"Restrict permissions on share '{name}' — remove 'Everyone' access.",
                    mitre_id="T1135",
                ))
            elif name not in admin_shares:
                findings.append(VulnFinding(
                    scanner=self.name, target="localhost",
                    severity=VulnSeverity.INFO,
                    category=VulnCategory.INFO_DISCLOSURE,
                    title=f"Custom network share: {name}",
                    description=f"Share '{name}' at {share.get('path', '?')} — verify permissions are appropriate.",
                    evidence=share,
                    remediation="Review share permissions and restrict as needed.",
                ))

        return findings

    def _get_shares(self) -> list[dict]:
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-SmbShare | Select-Object Name,Path,Description | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                import json
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                return data
        except Exception:
            pass
        return []


class AutorunChecker(ScannerPlugin):
    """Check for suspicious autorun/startup entries."""

    name = "autorun_check"
    description = "Startup and autorun entry audit"
    category = "persistence"

    async def is_applicable(self, target: ScanTarget) -> bool:
        import platform
        return platform.system() == "Windows" and target.host in ("127.0.0.1", "localhost")

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []
        entries = await asyncio.to_thread(self._get_autoruns)

        # Known suspicious paths/patterns
        suspicious_paths = [
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
            "\\downloads\\", "\\public\\",
        ]
        suspicious_exts = [".vbs", ".js", ".wsf", ".bat", ".ps1", ".hta"]

        for entry in entries:
            path = entry.get("command", "").lower()
            name = entry.get("name", "")

            is_suspicious = False
            reason = ""

            for sp in suspicious_paths:
                if sp in path:
                    is_suspicious = True
                    reason = f"runs from suspicious location ({sp.strip(chr(92))})"
                    break

            if not is_suspicious:
                for ext in suspicious_exts:
                    if path.endswith(ext) or ext + " " in path:
                        is_suspicious = True
                        reason = f"runs a script file ({ext})"
                        break

            if is_suspicious:
                findings.append(VulnFinding(
                    scanner=self.name, target="localhost",
                    severity=VulnSeverity.MEDIUM,
                    category=VulnCategory.MISCONFIGURATION,
                    title=f"Suspicious autorun entry: {name}",
                    description=f"Startup entry '{name}' {reason}. This could indicate persistence by malware.",
                    evidence=entry,
                    remediation=f"Investigate and remove if not recognized: {entry.get('command', '')}",
                    mitre_id="T1547.001",
                ))

        return findings

    def _get_autoruns(self) -> list[dict]:
        entries = []
        try:
            import winreg
            # Check common autorun locations
            locations = [
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            hive_names = {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM"}

            for hive, path in locations:
                try:
                    key = winreg.OpenKey(hive, path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            entries.append({
                                "name": name,
                                "command": value,
                                "location": f"{hive_names.get(hive, '?')}\\{path}",
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except OSError:
                    pass
        except Exception:
            pass

        # Also check startup folder
        startup_dirs = [
            Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
        ]
        for sd in startup_dirs:
            if sd.exists():
                for f in sd.iterdir():
                    if f.is_file() and f.suffix.lower() not in (".ini", ".desktop"):
                        entries.append({
                            "name": f.name,
                            "command": str(f),
                            "location": str(sd),
                        })

        return entries
