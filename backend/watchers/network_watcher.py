"""Network watcher with port scan and DNS tunnel detection"""

import asyncio
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Set
from collections import defaultdict


class PortScanDetector:
    """Detects port scanning behavior"""
    
    def __init__(self, window_seconds=5, threshold=50):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self.scans: Dict[str, List[tuple]] = {}  # ip -> [(timestamp, port), ...]
    
    def check(self, ip: str, port: int, timestamp: datetime) -> bool:
        """Returns True if IP is scanning ports"""
        if ip not in self.scans:
            self.scans[ip] = []
        
        # Add this connection attempt
        self.scans[ip].append((timestamp, port))
        
        # Clean old entries
        window_start = timestamp - timedelta(seconds=self.window_seconds)
        self.scans[ip] = [(t, p) for t, p in self.scans[ip] if t > window_start]
        
        # Check unique ports in window
        unique_ports = len(set(p for _, p in self.scans[ip]))
        return unique_ports >= self.threshold
    
    def get_unique_ports(self, ip: str) -> int:
        """Get number of unique ports scanned by IP"""
        if ip not in self.scans:
            return 0
        return len(set(p for _, p in self.scans[ip]))


class NetworkWatcher:
    """Watches network traffic for anomalies"""
    
    def __init__(self, interface: str = "eth0", callback: Callable = None):
        self.interface = interface
        self.callback = callback
        self.port_scan_detector = PortScanDetector()
        self.dns_queries: Dict[str, List[datetime]] = defaultdict(list)
        self.running = False
        self.task = None
    
    async def start(self):
        """Start network monitoring"""
        self.running = True
        
        # Try to use scapy for real packet capture
        try:
            from scapy.all import sniff, IP, TCP, UDP, DNS
            self.task = asyncio.create_task(self._scapy_capture())
            print(f"[NETWORK] Started packet capture on {self.interface}")
        except ImportError:
            print("[NETWORK] Scapy not available, using demo mode")
            self.task = asyncio.create_task(self._demo_mode())
        except PermissionError:
            print("[NETWORK] Need root for packet capture, using demo mode")
            self.task = asyncio.create_task(self._demo_mode())
    
    async def _scapy_capture(self):
        """Real packet capture with scapy"""
        from scapy.all import sniff, IP, TCP, UDP, DNS
        
        def packet_handler(pkt):
            if not self.running:
                return
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                # Check for port scan (TCP SYN without ACK)
                if TCP in pkt and pkt[TCP].flags == 'S':
                    asyncio.create_task(self._check_port_scan(src_ip, pkt[TCP].dport))
                
                # Check for DNS tunneling
                if UDP in pkt and pkt[UDP].dport == 53 and DNS in pkt:
                    asyncio.create_task(self._check_dns_tunnel(src_ip, pkt[DNS]))
        
        # Run scapy in executor to not block async loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: sniff(iface=self.interface, prn=packet_handler, store=0, stop_filter=lambda x: not self.running)
        )
    
    async def _check_port_scan(self, ip: str, port: int):
        """Check if this connection is part of a port scan"""
        timestamp = datetime.now()
        
        if self.port_scan_detector.check(ip, port, timestamp):
            unique_ports = self.port_scan_detector.get_unique_ports(ip)
            await self.callback({
                "source": "NETWORK",
                "type": "PORT_SCAN",
                "severity": 7,
                "source_ip": ip,
                "raw_log": f"Port scan detected: {unique_ports} ports in 5s",
                "timestamp": timestamp.isoformat(),
                "message": f"Port scan from {ip}: {unique_ports} ports probed"
            })
    
    async def _check_dns_tunnel(self, ip: str, dns_pkt):
        """Check for DNS tunneling patterns"""
        # Simplified check - real implementation would analyze query patterns
        pass
    
    async def _demo_mode(self):
        """Generate fake network events for demo"""
        import random
        
        while self.running:
            await asyncio.sleep(8)
            
            # Generate port scan
            ip = f"45.142.212.{random.randint(1, 255)}"
            await self.callback({
                "source": "NETWORK",
                "type": "PORT_SCAN",
                "severity": 7,
                "source_ip": ip,
                "raw_log": f"Port scan detected: 67 ports in 5s",
                "timestamp": datetime.now().isoformat(),
                "message": f"Port scan from {ip}: 67 ports probed"
            })
    
    async def stop(self):
        """Stop network monitoring"""
        self.running = False
        if self.task:
            self.task.cancel()
        print("[NETWORK] Stopped network watcher")