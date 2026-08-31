"""Network watcher with socket connection monitoring and port scan / burst detection"""

import asyncio
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Set, Tuple, Optional
import psutil


def normalize_attacker_ip(ip: str) -> str:
    """Normalize loopback and Docker/WSL bridge IPs to single consistent attacker identity"""
    if ip in ('127.0.0.1', '::1', 'localhost') or ip.startswith('172.28.') or ip.startswith('192.168.65.'):
        return "127.0.0.1"
    return ip


class PortScanDetector:
    """Detects port scanning behavior from connection data"""

    def __init__(self, window_seconds: float = 5.0, threshold: int = 2):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.scans: Dict[str, List[Tuple[datetime, int]]] = {}  # ip -> [(timestamp, port), ...]
        self.last_alert: Dict[str, datetime] = {}

    def check(self, ip: str, port: int, timestamp: datetime) -> bool:
        norm_ip = normalize_attacker_ip(ip)
        if norm_ip not in self.scans:
            self.scans[norm_ip] = []

        self.scans[norm_ip].append((timestamp, port))
        window_start = timestamp - timedelta(seconds=self.window_seconds)
        self.scans[norm_ip] = [(t, p) for t, p in self.scans[norm_ip] if t > window_start]
        unique_ports = len(set(p for _, p in self.scans[norm_ip]))

        last = self.last_alert.get(norm_ip)
        if unique_ports >= self.threshold:
            if not last or (timestamp - last).total_seconds() > 8:
                self.last_alert[norm_ip] = timestamp
                return True
        return False

    def get_unique_ports(self, ip: str) -> int:
        norm_ip = normalize_attacker_ip(ip)
        if norm_ip not in self.scans:
            return 0
        return len(set(p for _, p in self.scans[norm_ip]))


class ConnectionBurstDetector:
    """Detects high-frequency connection bursts / brute-force on single ports"""

    def __init__(self, window_seconds: float = 5.0, threshold: int = 5):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.bursts: Dict[str, List[Tuple[datetime, int, int]]] = {}  # ip -> [(timestamp, target_port, src_port), ...]
        self.last_alert: Dict[str, datetime] = {}

    def check(self, ip: str, target_port: int, src_port: int, timestamp: datetime) -> bool:
        norm_ip = normalize_attacker_ip(ip)
        if norm_ip not in self.bursts:
            self.bursts[norm_ip] = []

        self.bursts[norm_ip].append((timestamp, target_port, src_port))
        window_start = timestamp - timedelta(seconds=self.window_seconds)
        self.bursts[norm_ip] = [(t, tp, sp) for t, tp, sp in self.bursts[norm_ip] if t > window_start]

        port_counts: Dict[int, int] = {}
        for _, tp, _ in self.bursts[norm_ip]:
            port_counts[tp] = port_counts.get(tp, 0) + 1

        for tp, count in port_counts.items():
            if count >= self.threshold:
                key = f"{norm_ip}:{tp}"
                last = self.last_alert.get(key)
                if not last or (timestamp - last).total_seconds() > 8:
                    self.last_alert[key] = timestamp
                    return True
        return False

    def get_burst_count(self, ip: str, target_port: int) -> int:
        norm_ip = normalize_attacker_ip(ip)
        if norm_ip not in self.bursts:
            return 0
        return sum(1 for _, tp, _ in self.bursts[norm_ip] if tp == target_port)


class NetworkWatcher:
    """Watches real network interface connections and detects scan/burst patterns"""

    EXCLUDED_PORTS = {8000, 5173, 8085}
    ACTIVE_STATUSES = {
        'ESTABLISHED',
        'SYN_SENT',
        'TIME_WAIT',
        'CLOSE_WAIT',
        'FIN_WAIT1',
        'FIN_WAIT2',
    }

    def __init__(self, interface: Optional[str] = "eth0", callback: Callable = None, loop=None):
        self.interface = interface or "eth0"
        self.callback = callback
        self.loop = loop
        self.port_scan_detector = PortScanDetector(window_seconds=5.0, threshold=2)
        self.burst_detector = ConnectionBurstDetector(window_seconds=5.0, threshold=5)
        self.running = False
        self.task = None
        self.seen_connections: Set[Tuple[str, int, str, int, str]] = set()

    async def start(self):
        """Start connection monitoring"""
        self.running = True
        # Snapshot pre-existing connections so baseline OS sockets are not treated as a new scan
        self.seen_connections = self._snapshot_connections()
        self.task = asyncio.create_task(self._monitor_connections())
        print(f"[NETWORK] Started connection monitoring on {self.interface}")

    def _snapshot_connections(self) -> Set[Tuple[str, int, str, int, str]]:
        snapshot: Set[Tuple[str, int, str, int, str]] = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status in self.ACTIVE_STATUSES:
                    l_ip = conn.laddr.ip if conn.laddr else ""
                    l_port = conn.laddr.port if conn.laddr else 0
                    r_ip = conn.raddr.ip if conn.raddr else ""
                    r_port = conn.raddr.port if conn.raddr else 0
                    snapshot.add((l_ip, l_port, r_ip, r_port, conn.status))
        except Exception:
            pass
        return snapshot

    def _is_self_traffic(self, conn) -> bool:
        """Check if connection is PhantomAgent's own service traffic"""
        l_ip = conn.laddr.ip if conn.laddr else ""
        l_port = conn.laddr.port if conn.laddr else 0
        r_ip = conn.raddr.ip if conn.raddr else ""
        r_port = conn.raddr.port if conn.raddr else 0

        is_loopback = (
            l_ip in ('127.0.0.1', '::1', 'localhost')
            or r_ip in ('127.0.0.1', '::1', 'localhost')
        )
        if is_loopback:
            if l_port in self.EXCLUDED_PORTS or r_port in self.EXCLUDED_PORTS:
                return True
        return False

    async def _monitor_connections(self):
        """Monitor real network connections using psutil"""
        while self.running:
            try:
                current_conns: Set[Tuple[str, int, str, int, str]] = set()
                timestamp = datetime.now()

                for conn in psutil.net_connections(kind='inet'):
                    if conn.status not in self.ACTIVE_STATUSES:
                        continue

                    # Skip PhantomAgent self traffic on 8000, 5173, 8085
                    if self._is_self_traffic(conn):
                        continue

                    if conn.raddr and conn.laddr:
                        r_ip = conn.raddr.ip
                        r_port = conn.raddr.port
                        l_ip = conn.laddr.ip
                        l_port = conn.laddr.port

                        conn_sig = (l_ip, l_port, r_ip, r_port, conn.status)
                        current_conns.add(conn_sig)

                        if conn_sig not in self.seen_connections:
                            # Identify target service port vs ephemeral client port
                            if l_ip in ('127.0.0.1', '::1', 'localhost') and r_ip in ('127.0.0.1', '::1', 'localhost'):
                                if l_port < 32768:
                                    target_port = l_port
                                    src_port = r_port
                                else:
                                    target_port = r_port
                                    src_port = l_port
                                source_ip = "127.0.0.1"
                            elif conn.raddr:
                                source_ip = r_ip
                                target_port = l_port if l_port and l_port < 32768 else r_port
                                src_port = r_port if target_port == l_port else l_port
                            else:
                                continue

                            norm_ip = normalize_attacker_ip(source_ip)

                            # Check for port scan patterns
                            if self.port_scan_detector.check(norm_ip, target_port, timestamp):
                                unique_ports = self.port_scan_detector.get_unique_ports(norm_ip)
                                await self.callback({
                                    "source": "NETWORK",
                                    "type": "PORT_SCAN",
                                    "severity": 7,
                                    "source_ip": norm_ip,
                                    "raw_log": f"Port scan detected: {unique_ports} unique ports probed in 5s from {norm_ip}",
                                    "timestamp": timestamp.isoformat(),
                                    "message": f"Port scan detected from {norm_ip}: {unique_ports} ports probed"
                                })

                            # Check for rapid connection bursts / brute force / DoS on single port
                            is_outbound_web = (target_port in (80, 443) and norm_ip != "127.0.0.1")
                            if not is_outbound_web and self.burst_detector.check(norm_ip, target_port, src_port, timestamp):
                                count = self.burst_detector.get_burst_count(norm_ip, target_port)
                                if count >= 18:
                                    await self.callback({
                                        "source": "NETWORK",
                                        "type": "DOS_ATTACK",
                                        "severity": 9,
                                        "source_ip": norm_ip,
                                        "raw_log": f"High-entropy anomaly / DoS flood: {count} rapid requests on port {target_port} from {norm_ip}",
                                        "timestamp": timestamp.isoformat(),
                                        "message": f"DoS attack / high-entropy anomaly detected on port {target_port} from {norm_ip}: {count} rapid packets"
                                    })
                                else:
                                    await self.callback({
                                        "source": "NETWORK",
                                        "type": "BRUTE_FORCE",
                                        "severity": 9,
                                        "source_ip": norm_ip,
                                        "raw_log": f"Rapid connection burst / brute force: {count} attempts on port {target_port} from {norm_ip}",
                                        "timestamp": timestamp.isoformat(),
                                        "message": f"Brute force detected on port {target_port} from {norm_ip}: {count} rapid connections"
                                    })

                    elif conn.raddr and not conn.laddr:
                        r_ip = conn.raddr.ip
                        r_port = conn.raddr.port
                        if not (r_ip in ('127.0.0.1', '::1', 'localhost') and r_port in self.EXCLUDED_PORTS):
                            conn_sig = ("", 0, r_ip, r_port, conn.status)
                            current_conns.add(conn_sig)
                            if conn_sig not in self.seen_connections:
                                norm_ip = normalize_attacker_ip(r_ip)
                                if self.port_scan_detector.check(norm_ip, r_port, timestamp):
                                    unique_ports = self.port_scan_detector.get_unique_ports(norm_ip)
                                    await self.callback({
                                        "source": "NETWORK",
                                        "type": "PORT_SCAN",
                                        "severity": 7,
                                        "source_ip": norm_ip,
                                        "raw_log": f"Port scan detected: {unique_ports} unique ports probed in 5s from {norm_ip}",
                                        "timestamp": timestamp.isoformat(),
                                        "message": f"Port scan detected from {norm_ip}: {unique_ports} ports probed"
                                    })

                self.seen_connections = current_conns

            except Exception as e:
                print(f"[NETWORK] Monitoring error: {e}")

            await asyncio.sleep(0.3)

    async def stop(self):
        """Stop network watcher"""
        self.running = False
        if self.task and not self.task.done():
            self.task.cancel()
        print("[NETWORK] Stopped network watcher")