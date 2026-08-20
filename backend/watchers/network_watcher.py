"""Network watcher with real Scapy packet sniffing"""

import asyncio
import time
from datetime import datetime
from typing import Callable, Dict, Optional
from scapy.all import AsyncSniffer, IP, TCP, UDP, Raw
from backend.pipeline.feature_extractor import FeatureExtractor


class NetworkWatcher:
    """Watches real network interface traffic using Scapy AsyncSniffer"""

    def __init__(self, interface: Optional[str] = None, callback: Optional[Callable] = None, loop=None):
        self.interface = interface or self._find_docker_interface()
        self.callback = callback
        self.loop = loop
        self.feature_extractor = FeatureExtractor(window_seconds=5.0)
        self.sniffer: Optional[AsyncSniffer] = None
        self.running = False
        self.last_alert_time: Dict[str, datetime] = {}
        # Whitelist localhost and local host IP ranges
        self.whitelist = {
            "127.0.0.1", "::1", "localhost",
            "10.0.2.15",       # WSL host
            "172.28.0.1",      # Docker bridge gateway
            "172.28.0.5",      # Juice Shop target — victim, not attacker
        }

    def _find_docker_interface(self) -> str:
        """Dynamically locate docker lab bridge interface or fall back to any active interface"""
        import psutil
        stats = psutil.net_if_stats()
        # Prioritize active docker lab bridge interfaces (br-*)
        for iface in stats:
            if iface.startswith("br-") and stats[iface].isup:
                return iface
        for iface in stats:
            if iface.startswith("docker") and stats[iface].isup:
                return iface
        return "any"

    def _can_alert(self, alert_key: str, cooldown_seconds: int = 30) -> bool:
        """Check if enough time has passed since the last alert for this key.
        Default cooldown raised to 30s so a Hydra/curl flood doesn't spam identical alerts."""
        now = datetime.now()
        if alert_key in self.last_alert_time:
            elapsed = (now - self.last_alert_time[alert_key]).total_seconds()
            if elapsed < cooldown_seconds:
                return False
        self.last_alert_time[alert_key] = now
        return True

    def _packet_handler(self, packet):
        """Callback for Scapy AsyncSniffer per packet"""
        if not packet.haslayer(IP):
            return

        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Ignore local host or internal gateway whitelist
        if src_ip in self.whitelist:
            return

        pkt_info = {
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': None,
            'dst_port': None,
            'protocol': 'OTHER',
            'tcp_flags': '',
            'payload_bytes': len(packet),
            'http_payload': ''
        }

        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            pkt_info['src_port'] = tcp_layer.sport
            pkt_info['dst_port'] = tcp_layer.dport
            pkt_info['protocol'] = 'TCP'
            pkt_info['tcp_flags'] = str(tcp_layer.flags)

            if packet.haslayer(Raw):
                try:
                    payload = packet.getlayer(Raw).load.decode('utf-8', errors='ignore')
                    pkt_info['http_payload'] = payload
                except Exception:
                    pass

        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            pkt_info['src_port'] = udp_layer.sport
            pkt_info['dst_port'] = udp_layer.dport
            pkt_info['protocol'] = 'UDP'

        self.feature_extractor.process_packet(pkt_info)

        # Trigger feature check if callback is configured
        if self.callback and self.loop:
            features = self.feature_extractor.get_features(src_ip)
            
            # Attack Signatures:
            # 1. PORT_SCAN: Multiple destination ports probed (unique_dst_ports >= 3)
            is_scan = features['unique_dst_ports'] >= 3

            # 2. DOS_ATTACK: High volume packet flood targeting 1-2 ports ONLY
            is_dos = (features['connection_frequency'] >= 25.0 or features['packet_count'] >= 80) and features['unique_dst_ports'] <= 2

            # 3. BRUTE_FORCE: Failed authentication or request burst on a single service port
            is_bruteforce = features['failed_auth_count'] >= 1 or (features['packet_count'] >= 15 and features['unique_dst_ports'] <= 2)

            # 4. UNKNOWN_ZERO_DAY: High anomaly packet burst
            is_zeroday = features['packet_count'] >= 20 and features['syn_count'] >= 15 and features['unique_dst_ports'] == 2

            # Priority Order: PORT_SCAN (Multi-port recon) takes precedence when unique_dst_ports >= 3
            if is_scan and self._can_alert(f"scan_{src_ip}"):
                self._dispatch_alert("PORT_SCAN", 6, src_ip, features, "Real Port scan detected")
            elif is_dos and self._can_alert(f"dos_{src_ip}"):
                self._dispatch_alert("DOS_ATTACK", 8, src_ip, features, "Real DoS connection flood detected")
            elif is_zeroday and self._can_alert(f"zeroday_{src_ip}"):
                self._dispatch_alert("UNKNOWN_ZERO_DAY", 8, src_ip, features, "Un-labeled Zero-Day Structural Anomaly detected")
            elif is_bruteforce and self._can_alert(f"brute_{src_ip}"):
                self._dispatch_alert("BRUTE_FORCE", 7, src_ip, features, "Real Brute Force / Credential Spraying detected")

    def _dispatch_alert(self, threat_type: str, severity: int, src_ip: str, features: Dict, msg: str):
        # The communication graph observed in this window. The GNN scores every host
        # using its neighbourhood, which is what separates a scanner from a benign
        # monitoring agent -- their own feature vectors are indistinguishable.
        try:
            graph = self.feature_extractor.get_graph_snapshot()
        except Exception as e:
            print(f"[NETWORK] Could not build graph snapshot: {e}")
            graph = None

        alert_payload = {
            "source": "NETWORK",
            "type": threat_type,
            "severity": severity,
            "source_ip": src_ip,
            "features": features,
            "graph": graph,
            "raw_log": f"Real packet capture threat: {threat_type} from {src_ip} ({features['packet_count']} pkts, {features['unique_dst_ports']} ports)",
            "timestamp": datetime.now().isoformat(),
            "message": f"{msg} from {src_ip}: {features['packet_count']} pkts processed"
        }
        asyncio.run_coroutine_threadsafe(self.callback(alert_payload), self.loop)

    async def start(self):
        """Start Scapy AsyncSniffer background packet capture"""
        self.running = True
        if not self.loop:
            self.loop = asyncio.get_running_loop()

        print(f"[NETWORK] Starting Scapy packet capture on interface '{self.interface}'...")
        
        try:
            self.sniffer = AsyncSniffer(
                iface=self.interface if self.interface != "any" else None,
                prn=self._packet_handler,
                store=False,
                filter="ip"
            )
            self.sniffer.start()
            print(f"[NETWORK] Scapy sniffer active on '{self.interface}'")
        except Exception as e:
            print(f"[NETWORK] Failed to start Scapy sniffer on {self.interface}: {e}")

    async def stop(self):
        """Stop Scapy sniffer"""
        self.running = False
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()
        print("[NETWORK] Stopped Scapy network watcher")