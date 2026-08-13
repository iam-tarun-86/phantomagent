"""Per-IP Behavioral Fingerprint Engine (Online Z-Score Profiling)

AI/ML Explanation:
In machine learning outlier detection:
Z = (X - mean) / std_dev

Instead of fixed global thresholds, this module maintains a rolling 24-hour baseline
(mean mu and variance sigma^2) per source IP address across key metrics:
- Packet count per 5s window
- Unique destination ports targeted
- Connection frequency (pkts/sec)

If a host (like an internal backup server) regularly sends high volumes, its mu is high,
so its Z-score remains low (<= 2.0 sigma) -> NO FALSE POSITIVES.
If an unknown IP suddenly bursts, its historical mu is 0, resulting in Z > 30.0 sigma -> THREAT.
"""

import math
import time
from collections import defaultdict, deque
from typing import Dict, Any, Tuple


class BehavioralFingerprinter:
    """Tracks per-IP statistical baselines (mean, std_dev) and computes online Z-scores."""

    def __init__(self, window_hours: float = 24.0, min_samples: int = 5):
        self.window_seconds = window_hours * 3600
        self.min_samples = min_samples
        # IP -> metric_name -> deque of (timestamp, value)
        self.history: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(deque))

    def update_and_score(self, src_ip: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Record new window features for src_ip, prune old data, and calculate Z-scores.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        metrics = {
            "packet_count": float(features.get("packet_count", 0)),
            "unique_ports": float(features.get("unique_dst_ports", 0)),
            "conn_freq": float(features.get("connection_frequency", 0.0)),
            "syn_count": float(features.get("syn_count", 0))
        }

        z_scores = {}
        max_z_score = 0.0

        for metric_name, val in metrics.items():
            hist = self.history[src_ip][metric_name]

            # Prune old samples
            while hist and hist[0][0] < cutoff:
                hist.popleft()

            # Calculate baseline statistics (mean, std_dev) BEFORE adding current sample
            if len(hist) >= self.min_samples:
                values = [v for _, v in hist]
                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / len(values)
                std_dev = math.sqrt(variance)

                # Avoid division by zero
                denom = max(std_dev, 1.0)
                z = (val - mean) / denom
            else:
                # Not enough history (e.g. brand new external IP) -> high default outlier weighting
                mean = 0.0
                std_dev = 1.0
                z = val if val > 0 else 0.0

            z_scores[f"z_{metric_name}"] = round(z, 2)
            if z > max_z_score:
                max_z_score = z

            # Append current observation to history
            hist.append((now, val))

        is_anomaly = max_z_score >= 3.0  # 3-sigma standard anomaly threshold

        return {
            "max_z_score": round(max_z_score, 2),
            "z_scores": z_scores,
            "is_anomaly": is_anomaly,
            "history_depth": len(self.history[src_ip]["packet_count"])
        }
