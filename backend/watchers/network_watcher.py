"""Network watcher with real connection monitoring"""

import asyncio
import socket
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Set
from collections import defaultdict
import psutil


class PortScanDetector:
    """Detects port scanning behavior from netstat data"""

    def __init__(self, window_seconds=5, threshold=20):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.scans: Dict[str, List[tuple]] = {}  # ip -> [(timestamp, port), ...]

    def check(self, ip: str, port: int, timestamp: datetime) -> bool:
        if ip not in self.scans:
            self.scans[ip] = []

        self.scans[ip].append((timestamp, port))
        window_start = timestamp - timedelta(seconds=self.window_seconds)
        self.scans[ip] = [(t, p) for t, p in self.scans[ip] if t > window_start]
        unique_ports = len(set(p for _, p in self.scans[ip]))
        return unique_ports >= self.threshold

    def get_unique_ports(self, ip: str) -> int:
        if ip not in self.scans:
            return 0
        return len(set(p for _, p in self.scans[ip]))


class NetworkWatcher:
    """Watches network connections for anomalies"""

    def __init__(self, interface: str = "eth0", callback: Callable = None):
        self.interface = interface
        self.callback = callback
        self.port_scan_detector = PortScanDetector()
        self.running = False
        self.task = None
        self.last_connections: Set[tuple] = set()

    async def start(self):
        """Start network monitoring"""
        self.running = True
        self.task = asyncio.create_task(self._monitor_connections())
        print(f"[NETWORK] Started connection monitoring on {self.interface}")

    async def _monitor_connections(self):
        """Monitor real network connections using psutil"""
        while self.running:
            try:
                # Get all current connections
                current_connections = set()
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'ESTABLISHED' or conn.status == 'SYN_SENT':
                        if conn.raddr:
                            ip = conn.raddr.ip
                            if ip in ('127.0.0.1', '::1', 'localhost'):
                                continue
                            port = conn.raddr.port
                            current_connections.add((ip, port))
                            
                            # Check for port scan patterns
                            await self._check_port_scan(ip, port)

                self.last_connections = current_connections
                
                # Check for suspicious connection counts
                await self._check_connection_flood()
                
            except Exception as e:
                print(f"[NETWORK] Monitoring error: {e}")

            await asyncio.sleep(2)

    async def _check_port_scan(self, ip: str, port: int):
        """Check if IP is scanning multiple ports"""
        timestamp = datetime.now()
        
        if self.port_scan_detector.check(ip, port, timestamp):
            unique_ports = self.port_scan_detector.get_unique_ports(ip)
            await self.callback({
                "source": "NETWORK",
                "type": "PORT_SCAN",
                "severity": 7,
                "source_ip": ip,
                "raw_log": f"Port scan detected: {unique_ports} unique ports in 5s from {ip}",
                "timestamp": timestamp.isoformat(),
                "message": f"Port scan detected from {ip}: {unique_ports} ports probed"
            })

    async def _check_connection_flood(self):
        """Detect connection flooding / DoS"""
        # Count connections per IP
        ip_counts = {}
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:
                ip = conn.raddr.ip
                if ip in ('127.0.0.1', '::1', 'localhost'):
                    continue
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # Alert on high connection counts
        for ip, count in ip_counts.items():
            if count > 50:
                await self.callback({
                    "source": "NETWORK",
                    "type": "DOS_ATTACK",
                    "severity": 9,
                    "source_ip": ip,
                    "raw_log": f"Connection flood: {count} connections from {ip}",
                    "timestamp": datetime.now().isoformat(),
                    "message": f"DoS attack detected: {count} connections from {ip}"
                })

    async def stop(self):
        """Stop network monitoring"""
        self.running = False
        if self.task:
            self.task.cancel()
        print("[NETWORK] Stopped network watcher")