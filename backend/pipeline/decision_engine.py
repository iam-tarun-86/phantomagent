"""Decision engine: routes threats by severity"""

from typing import Dict, Any
from backend.config import SEVERITY_THRESHOLDS


class DecisionEngine:
    """Routes threats to appropriate action based on severity"""
    
    def __init__(self):
        self.stats = {
            'logged': 0,
            'alerted': 0,
            'auto_contained': 0,
            'pending': 0,
            'approved': 0,
            'rejected': 0
        }
    
    def decide(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make decision based on Qwen analysis.
        Returns: {action, requires_approval, auto_execute, reason}
        """
        severity = analysis.get('severity', 5)
        action = analysis.get('action', 'ALERT')
        
        # Route by severity
        if SEVERITY_THRESHOLDS['LOG'][0] <= severity <= SEVERITY_THRESHOLDS['LOG'][1]:
            self.stats['logged'] += 1
            return {
                'action': 'LOG',
                'requires_approval': False,
                'auto_execute': False,
                'reason': f'Severity {severity}: Log for review'
            }
        
        elif SEVERITY_THRESHOLDS['ALERT'][0] <= severity <= SEVERITY_THRESHOLDS['ALERT'][1]:
            self.stats['alerted'] += 1
            return {
                'action': 'ALERT',
                'requires_approval': False,
                'auto_execute': False,
                'reason': f'Severity {severity}: Alert operators'
            }
        
        elif SEVERITY_THRESHOLDS['AUTO_CONTAIN'][0] <= severity <= SEVERITY_THRESHOLDS['AUTO_CONTAIN'][1]:
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