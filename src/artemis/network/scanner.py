"""Network scanner — ARP discovery and port scanning.

Publishes host discovery and port events to the event bus.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

from artemis.core.events import Event, EventBus, EventType

logger = logging.getLogger("artemis.network")


class NetworkScanner:
    """Lightweight network scanner using ARP and TCP connect."""

    def __init__(self, scan_range: str = "192.168.1.0/24", interval: int = 60) -> None:
        self.scan_range = scan_range
        self.interval = interval
        self._bus: EventBus | None = None
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._known_hosts: dict[str, dict[str, Any]] = {}
        self._common_ports = [22, 80, 443, 445, 3389, 8080, 8443]

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._running = True
        self._task = asyncio.create_task(self._scan_loop(), name="net-scanner")
        logger.info("Network scanner started — range: %s, interval: %ds",
                     self.scan_range, self.interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _scan_loop(self) -> None:
        while self._running:
            try:
                hosts = await asyncio.to_thread(self._arp_scan)
                current_ips = set()

                for host in hosts:
                    ip = host["ip"]
                    current_ips.add(ip)

                    if ip not in self._known_hosts:
                        # New host discovered
                        ports = await asyncio.to_thread(self._port_scan, ip)
                        host["open_ports"] = ports
                        self._known_hosts[ip] = host

                        if self._bus:
                            await self._bus.publish(Event(
                                type=EventType.HOST_DISCOVERED,
                                data=host,
                                source="network_scanner",
                                severity=1,
                            ))
                            for port in ports:
                                await self._bus.publish(Event(
                                    type=EventType.PORT_OPEN,
                                    data={"ip": ip, "port": port},
                                    source="network_scanner",
                                    severity=0,
                                ))

                # Check for hosts that disappeared
                lost = set(self._known_hosts.keys()) - current_ips
                for ip in lost:
                    if self._bus:
                        await self._bus.publish(Event(
                            type=EventType.HOST_LOST,
                            data={"ip": ip, **self._known_hosts[ip]},
                            source="network_scanner",
                            severity=1,
                        ))
                    del self._known_hosts[ip]

            except Exception:
                logger.exception("Network scan error")

            await asyncio.sleep(self.interval)

    def _arp_scan(self) -> list[dict[str, Any]]:
        """ARP scan the network range. Uses scapy if available, falls back to arp -a."""
        try:
            from scapy.all import ARP, Ether, srp
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.scan_range),
                timeout=5, verbose=0,
            )
            return [{"ip": r[1].psrc, "mac": r[1].hwsrc} for r in ans]
        except ImportError:
            return self._arp_fallback()

    def _arp_fallback(self) -> list[dict[str, Any]]:
        """Parse 'arp -a' output as fallback."""
        import subprocess
        try:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            hosts = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1].count(".") == 3:
                    hosts.append({"ip": parts[0], "mac": parts[1]})
                elif len(parts) >= 2 and parts[0].count(".") == 3:
                    mac = parts[1] if len(parts) > 1 else "unknown"
                    hosts.append({"ip": parts[0], "mac": mac})
            return hosts
        except Exception:
            return []

    def _port_scan(self, ip: str) -> list[int]:
        """Quick TCP connect scan on common ports."""
        open_ports = []
        for port in self._common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except OSError:
                pass
        return open_ports
