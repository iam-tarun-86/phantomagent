"""Shannon Entropy Analyzer for Raw Packet & Payload Data

AI/ML Explanation:
Information Entropy (H) measures randomness in byte sequences:
H(X) = - sum(P(x) * log2(P(x)))

- Range: [0.0, 8.0] bits per byte (since 1 byte = 8 bits).
- Low Entropy (< 2.0): NOP sleds (\x90), buffer overflow pads, SQL injection strings.
- Medium Entropy (3.0 - 5.5): Plaintext HTTP, HTML, normal API traffic.
- High Entropy (> 7.2): Encrypted C2 communications, ransomware headers, base64 data exfiltration.
"""

import math
from collections import Counter
from typing import Dict, Any, Union


class PayloadEntropyAnalyzer:
    """Computes Shannon entropy on raw bytes or payload strings."""

    @staticmethod
    def calculate_entropy(payload: Union[bytes, str]) -> float:
        """
        Calculate Shannon entropy in bits per byte [0.0 - 8.0].
        """
        if not payload:
            return 0.0

        if isinstance(payload, str):
            payload = payload.encode('utf-8', errors='ignore')

        if len(payload) == 0:
            return 0.0

        total_bytes = len(payload)
        counts = Counter(payload)

        entropy = 0.0
        for count in counts.values():
            p = count / total_bytes
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    def analyze_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze payload entropy for an event.
        Returns entropy score and qualitative signal (HIGH_ENTROPY, LOW_ENTROPY, NORMAL).
        """
        raw_log = event_data.get('raw_log', '')
        features = event_data.get('features', {})
        http_payload = features.get('http_payload', '')

        # Combine payload sources
        target_data = http_payload if http_payload else raw_log

        entropy = self.calculate_entropy(target_data)

        signal = "NORMAL"
        is_anomaly = False

        if entropy >= 7.2:
            signal = "HIGH_ENTROPY_ENCRYPTED_C2"
            is_anomaly = True
        elif 0.0 < entropy <= 2.0 and len(target_data) > 20:
            signal = "LOW_ENTROPY_EXPLOIT_PAD"
            is_anomaly = True

        return {
            "entropy": entropy,
            "signal": signal,
            "is_anomaly": is_anomaly,
            "payload_length": len(target_data)
        }
