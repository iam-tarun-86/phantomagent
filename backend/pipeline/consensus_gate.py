"""5-Signal Evidence Consensus Gate (Multi-Model Ensemble Decision Rule)

AI/ML Explanation:
In Ensemble Voting & Multi-Head Decision Systems:
To achieve Near-Zero False Positives, NO SINGLE MODEL is allowed to trigger a critical alert.

Instead, 5 independent signal detectors evaluate every event:
1. GNN Model Score (> 0.40)                [Graph ML Signal]
2. Conformal P-Value (< 0.05)             [Statistical Certainty Signal]
3. Per-IP Behavioral Z-Score (> 3.0 sigma) [Outlier Baseline Signal]
4. Payload Shannon Entropy (High / Low)   [Information Theory Signal]
5. ATT&CK Kill-Chain Progress (>= 2 stages)[Temporal Campaign Signal]

Consensus Rule:
- Require >= 3 out of 5 positive votes -> THREAT CONFIRMED (Passes Consensus Gate)
- < 3 out of 5 votes -> SUPPRESS ALERT / LOG SILENTLY (Prevents Noise & Alert Fatigue)
"""

from typing import Dict, Any
from backend.pipeline.entropy_analyzer import PayloadEntropyAnalyzer
from backend.pipeline.behavioral_fingerprint import BehavioralFingerprinter
from backend.pipeline.killchain_correlator import KillChainCorrelator
from backend.pipeline.conformal_predictor import ConformalPredictor


class ConsensusGate:
    """Ensemble decision gate requiring N-of-5 signal consensus to validate threats."""

    def __init__(self, required_consensus_votes: int = 3):
        self.required_votes = required_consensus_votes
        self.entropy_analyzer = PayloadEntropyAnalyzer()
        self.behavioral_fingerprinter = BehavioralFingerprinter()
        self.killchain_correlator = KillChainCorrelator()
        self.conformal_predictor = ConformalPredictor(alpha=0.05)

    def evaluate(self, event_data: Dict[str, Any], gnn_score: float) -> Dict[str, Any]:
        """
        Evaluate all 5 signals and determine consensus vote.
        """
        src_ip = event_data.get('source_ip', 'unknown')
        threat_type = event_data.get('type', 'UNKNOWN')

        # 1. GNN Signal
        gnn_vote = gnn_score >= 0.40

        # 2. Conformal Prediction Signal
        conformal_res = self.conformal_predictor.predict_p_value(gnn_score)
        conformal_vote = conformal_res['is_statistically_significant']

        # 3. Behavioral Z-Score Signal
        features = event_data.get('features', {})
        behavior_res = self.behavioral_fingerprinter.update_and_score(src_ip, features)
        zscore_vote = behavior_res['is_anomaly']

        # 4. Payload Shannon Entropy Signal
        entropy_res = self.entropy_analyzer.analyze_event(event_data)
        entropy_vote = entropy_res['is_anomaly']

        # 5. MITRE ATT&CK Kill-Chain Signal
        killchain_res = self.killchain_correlator.record_and_evaluate(src_ip, threat_type)
        killchain_vote = killchain_res['is_campaign']

        # Count positive consensus votes
        votes = {
            "gnn_structural": gnn_vote,
            "conformal_pvalue": conformal_vote,
            "behavioral_zscore": zscore_vote,
            "payload_entropy": entropy_vote,
            "killchain_campaign": killchain_vote
        }

        total_positive_votes = sum(1 for v in votes.values() if v)
        has_consensus = total_positive_votes >= self.required_votes

        return {
            "has_consensus": has_consensus,
            "total_votes": total_positive_votes,
            "required_votes": self.required_votes,
            "vote_breakdown": votes,
            "gnn_score": gnn_score,
            "conformal": conformal_res,
            "behavioral": behavior_res,
            "entropy": entropy_res,
            "killchain": killchain_res
        }
