"""MITRE ATT&CK Temporal Kill-Chain Correlator

AI/ML Explanation:
In Markov Chains / State Machine Modeling:
A single isolated event (e.g., 1 port scan) might be noise.
However, if a single source IP progresses through multiple distinct kill-chain stages:
Stage 1: Reconnaissance (Port Scan)
Stage 2: Initial Access / Credential Spraying (Brute Force)
Stage 3: Execution / Anomaly Burst (DoS / Zero-Day)
Stage 4: Exfiltration / C2 Channel (High Entropy Payload)

The correlator tracks the transition matrix per IP over a 1-hour rolling timeline.
Advancing through >= 2 stages indicates a coordinated APT campaign.
"""

import time
from collections import defaultdict
from typing import Dict, Any, Set, List, Tuple


STAGE_MAPPING = {
    "PORT_SCAN": 1,         # Reconnaissance
    "BRUTE_FORCE": 2,       # Credential Access
    "DOS_ATTACK": 3,        # Execution / Service Disruption
    "FILE_ANOMALY": 3,      # Persistence / Payload Drop
    "UNKNOWN_ZERO_DAY": 3,  # Anomaly Burst
    "SUSPICIOUS_LOGIN": 2,  # Privilege Escalation
}


class KillChainCorrelator:
    """Tracks multi-step attack campaign progression per source IP over time."""

    def __init__(self, campaign_window_seconds: float = 3600.0):
        self.window_seconds = campaign_window_seconds
        # IP -> list of (timestamp, threat_type, stage_number)
        self.history: Dict[str, List[Tuple[float, str, int]]] = defaultdict(list)

    def record_and_evaluate(self, src_ip: str, threat_type: str) -> Dict[str, Any]:
        """
        Record event for src_ip and evaluate multi-stage campaign score.
        """
        now = time.time()
        cutoff = now - self.window_seconds

        # Prune old events outside window
        self.history[src_ip] = [item for item in self.history[src_ip] if item[0] >= cutoff]

        # Only append actual threat events (ignore BENIGN / UNKNOWN noise)
        threat_upper = threat_type.upper()
        if threat_upper in STAGE_MAPPING and threat_upper not in ('BENIGN', 'UNKNOWN', 'NOISE'):
            stage = STAGE_MAPPING[threat_upper]
            self.history[src_ip].append((now, threat_type, stage))

        # Extract unique stages observed in window
        observed_stages: Set[int] = {item[2] for item in self.history[src_ip]}
        observed_threats: Set[str] = {item[1] for item in self.history[src_ip]}

        campaign_stage_count = len(observed_stages)
        event_count = len(self.history[src_ip])

        is_campaign = campaign_stage_count >= 2

        return {
            "campaign_stage_count": campaign_stage_count,
            "max_stage_reached": max(observed_stages) if observed_stages else 0,
            "observed_threats": list(observed_threats),
            "event_count": event_count,
            "is_campaign": is_campaign
        }
