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

Cold start
----------
A brand-new IP has no self-baseline. Treating "no history" as "maximally anomalous" —
which an earlier version did, by using the raw metric value as the Z-score — makes this
signal fire for essentially every unseen host, including one sending four benign packets.
That is fatal for a corroborating signal: it is always YES for exactly the population it
is meant to discriminate within, so it silently rubber-stamps whatever the GNN decides.

Instead, an unseen IP is scored against a BENIGN POPULATION PRIOR: the mean and standard
deviation of each metric across known-benign traffic, computed at training time and
written to models/benign_baseline.json. "Unusual compared with known-benign traffic" is
a real, independent statement. With no prior available the signal abstains (votes NO)
rather than asserting an anomaly it cannot evidence.
"""

import json
import math
import os
import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional

from backend.config import BASE_DIR

BASELINE_PATH = BASE_DIR / "models" / "benign_baseline.json"

# Fingerprinter metric -> feature key it is derived from.
METRIC_SOURCES = {
    "packet_count": "packet_count",
    "unique_ports": "unique_dst_ports",
    "conn_freq": "connection_frequency",
    "syn_count": "syn_count",
}


class BehavioralFingerprinter:
    """Tracks per-IP statistical baselines (mean, std_dev) and computes online Z-scores."""

    def __init__(self, window_hours: float = 24.0, min_samples: int = 5, baseline_path=None):
        self.window_seconds = window_hours * 3600
        self.min_samples = min_samples
        # IP -> metric_name -> deque of (timestamp, value)
        self.history: Dict[str, Dict[str, deque]] = defaultdict(lambda: defaultdict(deque))

        self.baseline_path = baseline_path or BASELINE_PATH
        self.prior: Dict[str, Dict[str, float]] = {}
        self.prior_source = "none"
        self._load_prior()

    def _load_prior(self):
        """Load the benign population prior produced by train_gnn.py."""
        try:
            if os.path.exists(self.baseline_path):
                with open(self.baseline_path) as f:
                    data = json.load(f)
                metrics = data.get("metrics", {})
                if metrics:
                    self.prior = {k: dict(v) for k, v in metrics.items()}
                    self.prior_source = str(self.baseline_path)
                    return
        except Exception as e:
            print(f"[BEHAVIOR] Failed to load benign baseline: {e}")

        print(
            "[BEHAVIOR] WARNING: no benign population baseline available "
            f"({self.baseline_path}). Unseen IPs will abstain from the behavioural vote "
            "until they build their own history. Run backend/scripts/train_gnn.py."
        )

    def _cold_start_z(self, metric_name: str, val: float) -> Optional[float]:
        """Z-score against the benign population, or None if we cannot evidence one."""
        stats = self.prior.get(metric_name)
        if not stats:
            return None
        mean = float(stats.get("mean", 0.0))
        std = float(stats.get("std", 0.0))
        # Same floor as the self-baseline path. Benign traffic can be perfectly uniform
        # in a metric (e.g. always exactly 1 destination port), and dividing by a near-
        # zero sigma turns a 1-unit deviation into a 6-sigma "anomaly".
        return (val - mean) / max(std, 1.0)

    def update_and_score(self, src_ip: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """Record new window features for src_ip, prune old data, and calculate Z-scores."""
        now = time.time()
        cutoff = now - self.window_seconds

        metrics = {
            name: float(features.get(source, 0))
            for name, source in METRIC_SOURCES.items()
        }

        z_scores: Dict[str, float] = {}
        max_z_score = 0.0
        used_prior = False
        abstained = False

        for metric_name, val in metrics.items():
            hist = self.history[src_ip][metric_name]

            # Prune old samples
            while hist and hist[0][0] < cutoff:
                hist.popleft()

            if len(hist) >= self.min_samples:
                # Enough self-history: score against this IP's own baseline.
                values = [v for _, v in hist]
                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / len(values)
                std_dev = math.sqrt(variance)
                z = (val - mean) / max(std_dev, 1.0)
            else:
                # Cold start: score against the benign population, or abstain.
                prior_z = self._cold_start_z(metric_name, val)
                if prior_z is None:
                    abstained = True
                    z = 0.0
                else:
                    used_prior = True
                    z = prior_z

            z_scores[f"z_{metric_name}"] = round(z, 2)
            if z > max_z_score:
                max_z_score = z

            hist.append((now, val))

        is_anomaly = max_z_score >= 3.0  # 3-sigma standard anomaly threshold

        return {
            "max_z_score": round(max_z_score, 2),
            "z_scores": z_scores,
            "is_anomaly": is_anomaly,
            "history_depth": len(self.history[src_ip]["packet_count"]),
            "baseline": "population-prior" if used_prior else ("self" if not abstained else "abstained"),
        }
