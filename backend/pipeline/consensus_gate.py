"""5-Signal Evidence Consensus Gate (Multi-Model Ensemble Decision Rule)

Goal: near-zero false positives by requiring corroboration — NO SINGLE EVIDENCE SOURCE
may confirm a critical threat on its own.

Five detectors evaluate every event:
  1. GNN Model Score (>= 0.40)                [Graph ML]
  2. Conformal P-Value (< 0.05)               [Statistical calibration of signal 1]
  3. Per-IP Behavioural Z-Score (>= 3.0 sigma) [Outlier baseline]
  4. Payload Shannon Entropy (high / low)      [Information theory]
  5. ATT&CK Kill-Chain Progress (>= 2 stages)  [Temporal campaign]

Why this is not a flat 3-of-5 vote
----------------------------------
Signals 1 and 2 are not independent. The conformal p-value is a monotonically decreasing
function of the GNN score, so a high score necessarily produces a small p-value — signal
2 restates signal 1 in different units. Counting them as two votes double-counts one
piece of evidence, which is incoherent regardless of where the threshold sits.

What the change to evidence sources did and did not do (measured over all 32 vote
combinations; see backend/scripts/ablation.py):

  - It did NOT newly prevent a GNN-only verdict. Under the old flat 3-of-5 rule,
    gnn + conformal was 2 votes and already failed. Both rules reject it.
  - It did NOT raise the amount of corroboration required. One independent signal
    sufficed before and still suffices.
  - It IS more permissive overall: 25 of 32 combinations pass, against 16 under the
    flat rule. Every two-signal combination now passes, where flat required three.

So this is a correctness fix (stop double-counting correlated evidence), not a
false-positive reduction. Raising required_evidence_sources to 3 would tighten it to 13
combinations, but a single-window port scan produces only structural + behavioural
evidence, so a threshold of 3 suppresses real detections. 2 is the deliberate choice.

So votes are grouped into independent EVIDENCE SOURCES:

    structural  = signal 1 OR signal 2   (one source, however loudly it fires)
    behavioural = signal 3
    entropy     = signal 4
    killchain   = signal 5

Consensus requires `required_evidence_sources` (default 2) distinct sources to agree,
AND at least one of them to be non-structural. In practice: the GNN plus one real
corroborating signal, or two corroborating signals without the GNN. A saturated GNN
score on its own can never reach consensus.

The raw 5-signal breakdown is still reported for the dashboard and the LLM prompt.
"""

from typing import Any, Dict

from backend.pipeline.behavioral_fingerprint import BehavioralFingerprinter
from backend.pipeline.conformal_predictor import ConformalPredictor
from backend.pipeline.entropy_analyzer import PayloadEntropyAnalyzer
from backend.pipeline.killchain_correlator import KillChainCorrelator

# Signals derived from the GNN score. These collapse into a single evidence source.
STRUCTURAL_SIGNALS = ("gnn_structural", "conformal_pvalue")
INDEPENDENT_SIGNALS = ("behavioral_zscore", "payload_entropy", "killchain_campaign")


class ConsensusGate:
    """Ensemble decision gate requiring corroboration across independent evidence sources."""

    def __init__(self, required_consensus_votes: int = 3, required_evidence_sources: int = 2):
        # Retained for reporting/back-compat: the raw N-of-5 tally shown in the UI.
        self.required_votes = required_consensus_votes
        # The threshold that actually gates consensus.
        self.required_evidence_sources = required_evidence_sources

        self.entropy_analyzer = PayloadEntropyAnalyzer()
        self.behavioral_fingerprinter = BehavioralFingerprinter()
        self.killchain_correlator = KillChainCorrelator()
        self.conformal_predictor = ConformalPredictor(alpha=0.05)

    def evaluate(self, event_data: Dict[str, Any], gnn_score: float) -> Dict[str, Any]:
        """Evaluate all 5 signals and determine whether consensus is reached."""
        src_ip = event_data.get('source_ip', 'unknown')
        threat_type = event_data.get('type', 'UNKNOWN')

        # 1. GNN Signal
        gnn_vote = gnn_score >= 0.40

        # 2. Conformal Prediction Signal (calibration of signal 1 — not independent)
        conformal_res = self.conformal_predictor.predict_p_value(gnn_score)
        conformal_vote = conformal_res['is_statistically_significant']

        # 3. Behavioural Z-Score Signal
        features = event_data.get('features', {})
        behavior_res = self.behavioral_fingerprinter.update_and_score(src_ip, features)
        zscore_vote = behavior_res['is_anomaly']

        # 4. Payload Shannon Entropy Signal
        entropy_res = self.entropy_analyzer.analyze_event(event_data)
        entropy_vote = entropy_res['is_anomaly']

        # 5. MITRE ATT&CK Kill-Chain Signal
        killchain_res = self.killchain_correlator.record_and_evaluate(src_ip, threat_type)
        killchain_vote = killchain_res['is_campaign']

        votes = {
            "gnn_structural": gnn_vote,
            "conformal_pvalue": conformal_vote,
            "behavioral_zscore": zscore_vote,
            "payload_entropy": entropy_vote,
            "killchain_campaign": killchain_vote,
        }

        total_positive_votes = sum(1 for v in votes.values() if v)

        # Collapse the two GNN-derived signals into one evidence source.
        structural_source = any(votes[s] for s in STRUCTURAL_SIGNALS)
        independent_sources = [s for s in INDEPENDENT_SIGNALS if votes[s]]

        evidence_sources = len(independent_sources) + (1 if structural_source else 0)

        has_consensus = (
            evidence_sources >= self.required_evidence_sources
            and len(independent_sources) >= 1
        )

        return {
            "has_consensus": has_consensus,
            "total_votes": total_positive_votes,
            "required_votes": self.required_votes,
            "vote_breakdown": votes,
            "evidence_sources": evidence_sources,
            "required_evidence_sources": self.required_evidence_sources,
            "structural_source": structural_source,
            "independent_sources": independent_sources,
            "gnn_score": gnn_score,
            "conformal": conformal_res,
            "behavioral": behavior_res,
            "entropy": entropy_res,
            "killchain": killchain_res,
        }
