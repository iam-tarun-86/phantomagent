"""Decision engine: routes threats by severity and integrates GNN + Gemma reasoning"""

from typing import Dict, Any
from backend.config import SEVERITY_THRESHOLDS
from backend.pipeline.gnn_model import GNNPredictor
from backend.pipeline.gemma_engine import GemmaEngine


class DecisionEngine:
    """Routes threats and integrates GNN ('Eyes') + Gemma ('Brain') reasoning"""
    
    def __init__(self):
        self.gnn = GNNPredictor()
        self.gemma = GemmaEngine()
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
        Full Phase 5 Pipeline Processing:
        Raw event features -> GNN Anomaly Score -> Gemma Verdict -> Decision Routing
        """
        features = event_data.get('features', {})
        
        # 1. GNN 'Eyes': Predict structural anomaly score [0.0 - 1.0]
        gnn_score = self.gnn.predict_anomaly_score(features)
        event_data['gnn_score'] = gnn_score

        # 2. Gemma 'Brain': Generate structured JSON analysis
        analysis = await self.gemma.analyze(event_data)
        analysis['gnn_score'] = gnn_score

        # 3. Route decision by severity
        decision = self.decide(analysis)
        
        return {
            'analysis': analysis,
            'decision': decision,
            'gnn_score': gnn_score
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