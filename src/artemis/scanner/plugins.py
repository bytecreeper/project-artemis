"""Built-in vulnerability scanner plugins.

Each plugin is self-contained: detects one class of vulnerability,
provides evidence, and recommends remediation.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import struct
from datetime import datetime, timezone
from typing import Any

from artemis.scanner.base import (
    ScannerPlugin, ScanTarget, VulnFinding,
    VulnSeverity, VulnCategory,
)

logger = logging.getLogger("artemis.scanner.plugins")


# ── Port Scanner ──────────────────────────────────────────────────────

class PortScanner(ScannerPlugin):
    """TCP connect scan — finds open ports and identifies services."""

    name = "port_scanner"
    description = "TCP port scan with service identification"
    category = "network"

    # Common ports to check
    PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
        8443, 9200, 27017,
    ]

    SERVICE_NAMES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
    }

    # Ports that are risky when open
    RISKY_PORTS = {
        23: ("Telnet is unencrypted — credentials sent in cleartext", VulnSeverity.HIGH),
        21: ("FTP often uses plaintext authentication", VulnSeverity.MEDIUM),
        445: ("SMB can be exploited for lateral movement (EternalBlue, etc.)", VulnSeverity.MEDIUM),
        3389: ("RDP exposed — common target for brute force and exploits", VulnSeverity.MEDIUM),
        5900: ("VNC often has weak or no authentication", VulnSeverity.MEDIUM),
        6379: ("Redis typically has no authentication by default", VulnSeverity.HIGH),
        9200: ("Elasticsearch often exposes data without authentication", VulnSeverity.HIGH),
        27017: ("MongoDB frequently has no authentication enabled", VulnSeverity.HIGH),
        135: ("MSRPC can be used for lateral movement", VulnSeverity.LOW),
        111: ("RPC portmapper can reveal internal services", VulnSeverity.LOW),
    }

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []
        ports_to_scan = target.ports if target.ports else self.PORTS
        open_ports = await asyncio.to_thread(self._scan_ports, target.host, ports_to_scan)

        for port in open_ports:
            service = self.SERVICE_NAMES.get(port, f"unknown-{port}")
            banner = await asyncio.to_thread(self._grab_banner, target.host, port)

            # Check if this is a risky port
            if port in self.RISKY_PORTS:
                risk_desc, severity = self.RISKY_PORTS[port]
                findings.append(VulnFinding(
                    scanner=self.name,
                    target=target.host,
                    severity=severity,
                    category=VulnCategory.EXPOSED_SERVICE,
                    title=f"Risky service exposed: {service} (port {port})",
                    description=risk_desc,
                    technical_detail=f"Port {port}/{service} open on {target.host}. Banner: {banner or 'none'}",
                    evidence={"port": port, "service": service, "banner": banner, "host": target.host},
                    remediation=f"Close port {port} if not needed, or restrict access via firewall rules.",
                    mitre_id="T1046" if port not in (23, 3389) else "T1021",
                ))
            else:
                # Info-level finding for open ports
                findings.append(VulnFinding(
                    scanner=self.name,
                    target=target.host,
                    severity=VulnSeverity.INFO,
                    category=VulnCategory.OPEN_PORT,
                    title=f"Open port: {service} ({port})",
                    description=f"Port {port} ({service}) is open on {target.host}.",
                    evidence={"port": port, "service": service, "banner": banner},
                ))

        return findings

    def _scan_ports(self, host: str, ports: list[int]) -> list[int]:
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        return open_ports

    def _grab_banner(self, host: str, port: int) -> str | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((host, port))
            # Send a small probe for HTTP
            if port in (80, 8080, 8443, 443):
                s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            else:
                s.send(b"\r\n")
            banner = s.recv(256).decode("utf-8", errors="replace").strip()
            s.close()
            return banner[:200] if banner else None
        except Exception:
            return None


# ── SSL/TLS Checker ───────────────────────────────────────────────────

class SSLChecker(ScannerPlugin):
    """Checks SSL/TLS configuration for weaknesses."""

    name = "ssl_checker"
    description = "SSL/TLS configuration and certificate validation"
    category = "encryption"

    async def is_applicable(self, target: ScanTarget) -> bool:
        return bool(target.ports) and any(p in target.ports for p in [443, 8443, 993, 995])

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []
        ssl_ports = [p for p in target.ports if p in [443, 8443, 993, 995]]

        for port in ssl_ports:
            info = await asyncio.to_thread(self._check_ssl, target.host, port)
            if not info:
                continue

            # Check certificate expiry
            if info.get("days_until_expiry") is not None:
                days = info["days_until_expiry"]
                if days < 0:
                    findings.append(VulnFinding(
                        scanner=self.name, target=target.host,
                        severity=VulnSeverity.CRITICAL,
                        category=VulnCategory.WEAK_ENCRYPTION,
                        title=f"SSL certificate EXPIRED ({abs(days)} days ago)",
                        description="The SSL certificate has expired. Browsers will show security warnings and connections may fail.",
                        evidence=info,
                        remediation="Renew the SSL certificate immediately.",
                    ))
                elif days < 30:
                    findings.append(VulnFinding(
                        scanner=self.name, target=target.host,
                        severity=VulnSeverity.MEDIUM,
                        category=VulnCategory.WEAK_ENCRYPTION,
                        title=f"SSL certificate expiring soon ({days} days)",
                        description=f"The SSL certificate expires in {days} days.",
                        evidence=info,
                        remediation="Renew the SSL certificate before expiry.",
                    ))

            # Check protocol version
            if info.get("protocol") and "TLSv1.0" in info["protocol"]:
                findings.append(VulnFinding(
                    scanner=self.name, target=target.host,
                    severity=VulnSeverity.MEDIUM,
                    category=VulnCategory.WEAK_ENCRYPTION,
                    title="Outdated TLS version (TLSv1.0)",
                    description="TLS 1.0 has known vulnerabilities. Modern systems should use TLS 1.2 or 1.3.",
                    evidence=info,
                    remediation="Disable TLS 1.0 and 1.1. Configure the server to use TLS 1.2+ only.",
                ))

            # Self-signed check
            if info.get("self_signed"):
                findings.append(VulnFinding(
                    scanner=self.name, target=target.host,
                    severity=VulnSeverity.LOW,
                    category=VulnCategory.WEAK_ENCRYPTION,
                    title="Self-signed SSL certificate",
                    description="The certificate is self-signed, which means browsers won't trust it by default.",
                    evidence=info,
                    remediation="Use a certificate from a trusted CA (Let's Encrypt is free).",
                ))

        return findings

    def _check_ssl(self, host: str, port: int) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    info = {
                        "host": host,
                        "port": port,
                        "protocol": version,
                        "cipher": cipher[0] if cipher else None,
                        "bits": cipher[2] if cipher else None,
                    }

                    if cert:
                        not_after = cert.get("notAfter", "")
                        if not_after:
                            try:
                                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                days = (exp - datetime.now()).days
                                info["expires"] = not_after
                                info["days_until_expiry"] = days
                            except Exception:
                                pass

                        # Check if self-signed (issuer == subject)
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        subject = dict(x[0] for x in cert.get("subject", ()))
                        info["self_signed"] = issuer == subject
                        info["issuer"] = issuer.get("organizationName", "unknown")
                        info["subject"] = subject.get("commonName", "unknown")
                    else:
                        # Binary cert — limited info
                        info["self_signed"] = None
                        info["days_until_expiry"] = None

                    return info
        except Exception as e:
            logger.debug("SSL check failed for %s:%d — %s", host, port, e)
            return None


# ── SMB Checker ───────────────────────────────────────────────────────

class SMBChecker(ScannerPlugin):
    """Checks for SMB signing, version, and common misconfigs."""

    name = "smb_checker"
    description = "SMB configuration and signing checks"
    category = "network"

    async def is_applicable(self, target: ScanTarget) -> bool:
        return bool(target.ports) and 445 in target.ports

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []
        info = await asyncio.to_thread(self._check_smb, target.host)

        if info and not info.get("signing_required"):
            findings.append(VulnFinding(
                scanner=self.name,
                target=target.host,
                severity=VulnSeverity.MEDIUM,
                category=VulnCategory.MISCONFIGURATION,
                title="SMB signing not required",
                description="SMB signing is not required, which allows relay attacks (NTLM relay).",
                technical_detail="An attacker on the network can relay authentication to this host.",
                evidence=info,
                remediation="Enable mandatory SMB signing via Group Policy or registry.",
                mitre_id="T1557.001",
            ))

        if info and info.get("smbv1_enabled"):
            findings.append(VulnFinding(
                scanner=self.name,
                target=target.host,
                severity=VulnSeverity.HIGH,
                category=VulnCategory.WEAK_SERVICE,
                title="SMBv1 enabled (EternalBlue vulnerable)",
                description="SMBv1 is enabled. This protocol version is vulnerable to EternalBlue and WannaCry.",
                evidence=info,
                remediation="Disable SMBv1. In PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                mitre_id="T1210",
                cve="CVE-2017-0144",
            ))

        return findings

    def _check_smb(self, host: str) -> dict | None:
        """Basic SMB negotiate to check signing and version."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((host, 445))

            # SMB negotiate request (simplified)
            negotiate = (
                b"\x00\x00\x00\x85"
                b"\xffSMB"
                b"\x72"
                b"\x00\x00\x00\x00"
                b"\x18"
                b"\x53\xc8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00"
                b"\xff\xfe"
                b"\x00\x00"
                b"\x00\x00"
                b"\x00"
                b"\x62\x00"
                b"\x02NT LM 0.12\x00"
                b"\x02SMB 2.002\x00"
                b"\x02SMB 2.???\x00"
            )

            s.send(negotiate)
            resp = s.recv(1024)
            s.close()

            info = {"host": host, "port": 445, "responded": True}

            if len(resp) > 70:
                # Check if SMBv1 response (magic \xffSMB)
                if resp[4:8] == b"\xffSMB":
                    info["smbv1_enabled"] = True
                    # Security mode byte at offset 26
                    if len(resp) > 39:
                        sec_mode = resp[39]
                        info["signing_required"] = bool(sec_mode & 0x08)
                        info["signing_enabled"] = bool(sec_mode & 0x04)
                elif resp[4:8] == b"\xfeSMB":
                    info["smbv1_enabled"] = False
                    # SMB2 security mode at offset 70
                    if len(resp) > 70:
                        sec_mode = struct.unpack("<H", resp[70:72])[0]
                        info["signing_required"] = bool(sec_mode & 0x02)
                        info["signing_enabled"] = bool(sec_mode & 0x01)

            return info
        except Exception as e:
            logger.debug("SMB check failed for %s: %s", host, e)
            return None


# ── Default Credentials Checker ───────────────────────────────────────

class DefaultCredChecker(ScannerPlugin):
    """Checks for default/common credentials on exposed services."""

    name = "default_creds"
    description = "Default and common credential checks"
    category = "authentication"

    # Service → (port, check_function_name)
    CHECKS = {
        "ssh": (22, "_check_ssh_auth"),
        "ftp": (21, "_check_ftp_anon"),
        "http": (80, "_check_http_auth"),
    }

    COMMON_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("root", "root"),
        ("root", "toor"),
    ]

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []

        # FTP anonymous check
        if 21 in target.ports:
            anon = await asyncio.to_thread(self._check_ftp_anon, target.host)
            if anon:
                findings.append(VulnFinding(
                    scanner=self.name,
                    target=target.host,
                    severity=VulnSeverity.HIGH,
                    category=VulnCategory.DEFAULT_CREDS,
                    title="FTP anonymous login enabled",
                    description="Anyone can connect to this FTP server without credentials.",
                    evidence={"host": target.host, "port": 21, "anonymous": True, "banner": anon},
                    remediation="Disable anonymous FTP access. If FTP is needed, require authentication.",
                    mitre_id="T1078",
                ))

        # HTTP basic auth with defaults
        for port in [p for p in target.ports if p in (80, 8080, 443, 8443)]:
            weak = await asyncio.to_thread(self._check_http_default, target.host, port)
            if weak:
                findings.append(VulnFinding(
                    scanner=self.name,
                    target=target.host,
                    severity=VulnSeverity.CRITICAL,
                    category=VulnCategory.DEFAULT_CREDS,
                    title=f"Default credentials on HTTP service (port {port})",
                    description=f"The web service at port {port} accepts default credentials ({weak['user']}/{weak['pass']}).",
                    evidence=weak,
                    remediation="Change the default password immediately.",
                    mitre_id="T1078.001",
                ))

        return findings

    def _check_ftp_anon(self, host: str) -> str | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((host, 21))
            banner = s.recv(256).decode("utf-8", errors="replace")
            s.send(b"USER anonymous\r\n")
            resp1 = s.recv(256).decode("utf-8", errors="replace")
            if "331" in resp1:  # Password required
                s.send(b"PASS anonymous@\r\n")
                resp2 = s.recv(256).decode("utf-8", errors="replace")
                s.close()
                if "230" in resp2:  # Login successful
                    return banner.strip()
            s.close()
            return None
        except Exception:
            return None

    def _check_http_default(self, host: str, port: int) -> dict | None:
        """Check common admin panels for default creds."""
        import base64
        admin_paths = ["/admin", "/login", "/manager", "/"]

        for path in admin_paths:
            for user, pwd in self.COMMON_CREDS:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    s.connect((host, port))

                    creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    request = (
                        f"GET {path} HTTP/1.0\r\n"
                        f"Host: {host}\r\n"
                        f"Authorization: Basic {creds}\r\n"
                        f"\r\n"
                    ).encode()

                    s.send(request)
                    resp = s.recv(512).decode("utf-8", errors="replace")
                    s.close()

                    # If we get 200 with auth (and it previously required 401), it's a hit
                    if "200 OK" in resp and "401" not in resp:
                        # Verify it actually needs auth by trying without
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s2.settimeout(3)
                        s2.connect((host, port))
                        s2.send(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                        no_auth_resp = s2.recv(512).decode("utf-8", errors="replace")
                        s2.close()

                        if "401" in no_auth_resp:
                            return {"host": host, "port": port, "path": path,
                                    "user": user, "pass": pwd}
                except Exception:
                    pass

        return None


# ── Windows Security Config Checker ───────────────────────────────────

class WindowsConfigChecker(ScannerPlugin):
    """Checks local Windows security configuration."""

    name = "windows_config"
    description = "Windows security configuration audit"
    category = "configuration"

    async def is_applicable(self, target: ScanTarget) -> bool:
        import platform
        return platform.system() == "Windows" and target.host in ("127.0.0.1", "localhost", socket.gethostname())

    async def scan(self, target: ScanTarget) -> list[VulnFinding]:
        findings = []

        checks = [
            self._check_firewall,
            self._check_windows_update,
            self._check_antivirus,
            self._check_rdp,
            self._check_guest_account,
            self._check_smb1,
        ]

        for check_fn in checks:
            try:
                result = await asyncio.to_thread(check_fn)
                if result:
                    findings.append(result)
            except Exception as e:
                logger.debug("Windows config check failed: %s", e)

        return findings

    def _check_firewall(self) -> VulnFinding | None:
        try:
            import subprocess
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5
            )
            if "OFF" in result.stdout.upper():
                return VulnFinding(
                    scanner=self.name, target="localhost",
                    severity=VulnSeverity.CRITICAL,
                    category=VulnCategory.MISCONFIGURATION,
                    title="Windows Firewall is disabled",
                    description="One or more firewall profiles are turned off, leaving the system exposed.",
                    evidence={"output": result.stdout[:500]},
                    remediation="Enable Windows Firewall: netsh advfirewall set allprofiles state on",
                    mitre_id="T1562.004",
                )
        except Exception:
            pass
        return None

    def _check_windows_update(self) -> VulnFinding | None:
        try:
            import subprocess
            # Check last update time via PowerShell
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"],
                capture_output=True, text=True, timeout=15
            )
            if result.stdout.strip():
                from datetime import datetime
                last_update = datetime.strptime(result.stdout.strip()[:10], "%m/%d/%Y")
                days_ago = (datetime.now() - last_update).days
                if days_ago > 90:
                    return VulnFinding(
                        scanner=self.name, target="localhost",
                        severity=VulnSeverity.HIGH,
                        category=VulnCategory.MISSING_PATCH,
                        title=f"Windows updates are {days_ago} days old",
                        description=f"The last Windows update was installed {days_ago} days ago. Systems should be updated at least monthly.",
                        evidence={"last_update": result.stdout.strip(), "days_ago": days_ago},
                        remediation="Run Windows Update: Settings → Update & Security → Check for updates",
                    )
        except Exception:
            pass
        return None

    def _check_antivirus(self) -> VulnFinding | None:
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                import json
                status = json.loads(result.stdout)
                if not status.get("RealTimeProtectionEnabled"):
                    return VulnFinding(
                        scanner=self.name, target="localhost",
                        severity=VulnSeverity.HIGH,
                        category=VulnCategory.MISCONFIGURATION,
                        title="Real-time antivirus protection is disabled",
                        description="Windows Defender real-time protection is off.",
                        evidence=status,
                        remediation="Enable real-time protection: Windows Security → Virus & threat protection → Turn on",
                        mitre_id="T1562.001",
                    )
        except Exception:
            pass
        return None

    def _check_rdp(self) -> VulnFinding | None:
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server"
            )
            val, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            winreg.CloseKey(key)
            if val == 0:
                return VulnFinding(
                    scanner=self.name, target="localhost",
                    severity=VulnSeverity.MEDIUM,
                    category=VulnCategory.EXPOSED_SERVICE,
                    title="Remote Desktop (RDP) is enabled",
                    description="RDP is enabled. If exposed to the internet, this is a major attack vector.",
                    evidence={"rdp_enabled": True, "registry_value": val},
                    remediation="Disable RDP if not needed, or restrict access via firewall and use NLA.",
                    mitre_id="T1021.001",
                )
        except Exception:
            pass
        return None

    def _check_guest_account(self) -> VulnFinding | None:
        try:
            import subprocess
            result = subprocess.run(
                ["net", "user", "Guest"],
                capture_output=True, text=True, timeout=5
            )
            if "Account active" in result.stdout and "Yes" in result.stdout:
                return VulnFinding(
                    scanner=self.name, target="localhost",
                    severity=VulnSeverity.MEDIUM,
                    category=VulnCategory.MISCONFIGURATION,
                    title="Guest account is enabled",
                    description="The Guest account is active, allowing unauthenticated access.",
                    evidence={"guest_active": True},
                    remediation="Disable the Guest account: net user Guest /active:no",
                    mitre_id="T1078.001",
                )
        except Exception:
            pass
        return None

    def _check_smb1(self) -> VulnFinding | None:
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-SmbServerConfiguration).EnableSMB1Protocol"],
                capture_output=True, text=True, timeout=10
            )
            if "True" in result.stdout:
                return VulnFinding(
                    scanner=self.name, target="localhost",
                    severity=VulnSeverity.HIGH,
                    category=VulnCategory.WEAK_SERVICE,
                    title="SMBv1 protocol is enabled",
                    description="SMBv1 is vulnerable to EternalBlue (WannaCry ransomware). It should be disabled.",
                    evidence={"smbv1_enabled": True},
                    remediation="Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                    mitre_id="T1210",
                    cve="CVE-2017-0144",
                )
        except Exception:
            pass
        return None
