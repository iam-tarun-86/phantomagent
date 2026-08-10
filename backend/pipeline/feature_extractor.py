"""Feature Extractor for raw packet capture sliding window metrics"""

import time
from collections import defaultdict, deque
from typing import Dict, Any, List

class FeatureExtractor:
    """Aggregates raw IP packet data into statistical features over a sliding time window."""

    def __init__(self, window_seconds: float = 5.0):
        self.window_seconds = window_seconds
        # Store packet dicts per source IP: deque of (timestamp, packet_info)
        self.ip_windows: Dict[str, deque] = defaultdict(deque)

    def process_packet(self, packet_info: Dict[str, Any]):
        """
        Process a single packet info dictionary:
        packet_info = {
            'timestamp': float,
            'src_ip': str,
            'dst_ip': str,
            'src_port': int,
            'dst_port': int,
            'protocol': str,
            'tcp_flags': str (e.g., 'S', 'A', 'R', 'SA'),
            'payload_bytes': int,
            'http_payload': str (optional)
        }
        """
        src_ip = packet_info.get('src_ip')
        if not src_ip:
            return

        now = packet_info.get('timestamp', time.time())
        window = self.ip_windows[src_ip]
        window.append((now, packet_info))

        # Evict old packets outside window
        cutoff = now - self.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()

    def get_features(self, src_ip: str) -> Dict[str, Any]:
        """Compute aggregate statistical features for a given source IP."""
        window = self.ip_windows.get(src_ip, deque())
        if not window:
            return {
                "src_ip": src_ip,
                "packet_count": 0,
                "syn_count": 0,
                "ack_count": 0,
                "rst_count": 0,
                "unique_dst_ports": 0,
                "bytes_sent": 0,
                "connection_frequency": 0.0,
                "failed_auth_count": 0
            }

        now = time.time()
        cutoff = now - self.window_seconds
        valid_packets = [pkt for t, pkt in window if t >= cutoff]

        if not valid_packets:
            return {
                "src_ip": src_ip,
                "packet_count": 0,
                "syn_count": 0,
                "ack_count": 0,
                "rst_count": 0,
                "unique_dst_ports": 0,
                "bytes_sent": 0,
                "connection_frequency": 0.0,
                "failed_auth_count": 0
            }

        syn_count = 0
        ack_count = 0
        rst_count = 0
        unique_dst_ports = set()
        bytes_sent = 0
        failed_auth_count = 0

        for pkt in valid_packets:
            flags = pkt.get('tcp_flags', '')
            if 'S' in flags and 'A' not in flags:
                syn_count += 1
            if 'A' in flags:
                ack_count += 1
            if 'R' in flags:
                rst_count += 1

            dst_port = pkt.get('dst_port')
            if dst_port is not None:
                unique_dst_ports.add(dst_port)

            bytes_sent += pkt.get('payload_bytes', 0)

            # Check HTTP failed auth signatures (401/403 or failed login payloads)
            http_payload = pkt.get('http_payload', '')
            if http_payload:
                if '401 Unauthorized' in http_payload or '403 Forbidden' in http_payload or 'Invalid credentials' in http_payload:
                    failed_auth_count += 1

        duration = max(self.window_seconds, 1.0)
        freq = len(valid_packets) / duration

        return {
            "src_ip": src_ip,
            "packet_count": len(valid_packets),
            "syn_count": syn_count,
            "ack_count": ack_count,
            "rst_count": rst_count,
            "unique_dst_ports": len(unique_dst_ports),
            "bytes_sent": bytes_sent,
            "connection_frequency": round(freq, 2),
            "failed_auth_count": failed_auth_count
        }

    def clear(self):
        """Clear window buffers."""
        self.ip_windows.clear()
