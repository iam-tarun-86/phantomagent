"""Decision engine: routes threats by severity and integrates GNN + Gemma reasoning"""

from typing import Dict, Any
from backend.config import SEVERITY_THRESHOLDS
from backend.pipeline.gnn_model import GNNPredictor
from backend.pipeline.gemma_engine import GemmaEngine
from backend.pipeline.consensus_gate import ConsensusGate
from backend.utils.event_logger import EventLogger


class DecisionEngine:
    """Routes threats and integrates GNN ('Eyes') + Gemma ('Brain') reasoning + Consensus Gate"""

    def __init__(self):
        self.gnn = GNNPredictor()
        self.gemma = GemmaEngine()
        self.consensus_gate = ConsensusGate(required_consensus_votes=3)
        self.logger = EventLogger()
        self.stats = {
            'logged': 0,
            'alerted': 0,
            'auto_contained': 0,
            'pending': 0,
            'approved': 0,
            'rejected': 0
        }

    async def analyze_and_route(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full Pipeline Processing:
        Raw event -> GNN Anomaly Score -> Consensus Gate (5 Signals) -> Gemma Verdict -> Decision -> Log
        """
        features = event_data.get('features', {})
        src_ip = event_data.get('source_ip', 'unknown')
        rule_threat_type = event_data.get('type', 'UNKNOWN')   # Watcher's rule-based label
        rule_severity = event_data.get('severity', 5)          # Watcher's assigned severity

        # 1. GNN 'Eyes': Predict structural anomaly score [0.0 - 1.0]
        gnn_score = self.gnn.predict_anomaly_score(features)
        event_data['gnn_score'] = gnn_score

        # 2. Consensus Gate (5-Signal Evidence Evaluation)
        consensus_res = self.consensus_gate.evaluate(event_data, gnn_score)
        event_data['consensus'] = consensus_res

        # 3. Gemma 'Brain': Generate structured JSON analysis
        analysis = await self.gemma.analyze(event_data)
        analysis['gnn_score'] = gnn_score
        analysis['consensus_votes'] = consensus_res['total_votes']
        analysis['has_consensus'] = consensus_res['has_consensus']

        # 4. FUSION & CONSENSUS FILTER:
        # If 3-of-5 signals agree OR watcher confirmed signature + GNN >= 0.2, escalate.
        # If consensus fails (< 3 votes) and no strong rule match, downgrade severity to prevent False Positives.
        gemma_label = analysis.get('threat_type', 'UNKNOWN')

        if consensus_res['has_consensus']:
            if rule_threat_type not in ('UNKNOWN', 'BENIGN'):
                analysis['threat_type'] = rule_threat_type
                analysis['severity'] = max(analysis.get('severity', 5), rule_severity)
            analysis['explanation'] = (
                f"Consensus Passed ({consensus_res['total_votes']}/5 signals agreed). "
                f"Confirmed {analysis['threat_type']} (GNN: {gnn_score:.4f})."
            )
        else:
            # Consensus failed (<3 votes) -> Downgrade severity to avoid alert noise / false positive
            if rule_threat_type not in ('UNKNOWN', 'BENIGN') and gnn_score >= 0.2:
                analysis['threat_type'] = rule_threat_type
                analysis['severity'] = min(6, rule_severity)  # Cap at moderate severity
                analysis['explanation'] = (
                    f"Rule signature match ({rule_threat_type}) but Consensus Gate returned "
                    f"{consensus_res['total_votes']}/5 votes. Moderate threat classification."
                )
            else:
                analysis['severity'] = min(analysis.get('severity', 2), 3)  # Downgrade to LOG level
                analysis['action'] = 'LOG'
                analysis['explanation'] = (
                    f"Consensus Gate failed ({consensus_res['total_votes']}/5 signals). "
                    f"Suppressed potential false positive."
                )

        # 5. Route decision by fused severity
        decision = self.decide(analysis)

        # 6. Log event
        self.logger.log_event(
            source_ip=src_ip,
            features=features,
            gnn_score=gnn_score,
            verdict=analysis,
            action_taken=decision['action']
        )

        return {
            'analysis': analysis,
            'decision': decision,
            'gnn_score': gnn_score,
            'consensus': consensus_res
        }

    
    def decide(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make decision based on Gemma analysis & GNN score.
        Returns: {action, requires_approval, auto_execute, reason}
        """
        severity = analysis.get('severity', 5)
        action = analysis.get('action', 'ALERT')
        
        # Route by severity
        if SEVERITY_THRESHOLDS['AUTO_CONTAIN'][0] <= severity <= SEVERITY_THRESHOLDS['AUTO_CONTAIN'][1]:
            self.stats['auto_contained'] += 1
            return {
                'action': 'CONTAIN',
                'requires_approval': False,
                'auto_execute': True,
                'reason': f'Severity {severity}: Auto-contain threat'
            }
        
        elif SEVERITY_THRESHOLDS['PENDING_APPROVAL'][0] <= severity <= SEVERITY_THRESHOLDS['PENDING_APPROVAL'][1]:
            self.stats['pending'] += 1
            return {
                'action': 'LOCKDOWN',
                'requires_approval': True,
                'auto_execute': False,
                'reason': f'Severity {severity}: Human approval required'
            }

        # CRITICAL: Severity 10+ always requires immediate lockdown
        elif severity >= 10:
            self.stats['pending'] += 1
            return {
                'action': 'LOCKDOWN',
                'requires_approval': True,
                'auto_execute': False,
                'reason': f'Severity {severity}: CRITICAL — Immediate lockdown required'
            }

        return {
            'action': 'ALERT',
            'requires_approval': False,
            'auto_execute': False,
            'reason': f'Severity {severity}: Default to alert'
        }
    
    def approve(self, threat_id: str) -> Dict[str, Any]:
        """Approve a pending threat"""
        self.stats['approved'] += 1
        return {
            'action': 'CONTAIN',
            'executed': True,
            'reason': f'Threat {threat_id} approved by operator'
        }
    
    def reject(self, threat_id: str) -> Dict[str, Any]:
        """Reject a pending threat"""
        self.stats['rejected'] += 1
        return {
            'action': 'LOG',
            'executed': False,
            'reason': f'Threat {threat_id} rejected by operator'
        }
    
    def get_stats(self) -> Dict[str, int]:
        """Get decision statistics"""
        return self.stats.copy()