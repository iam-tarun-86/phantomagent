"""Pre-filter engine: kills 99% noise before LLM"""

import re
from typing import Dict, Any, Optional


class PreFilter:
    """Rule-based pre-filter for threat detection"""
    
    # Known safe patterns (whitelist)
    SAFE_PATTERNS = [
        r'CRON',
        r'systemd',
        r'ansible',
        r'puppet',
    ]
    
    # Known bad patterns (blacklist)
    BAD_PATTERNS = {
        'BRUTE_FORCE': {
            'pattern': r'Failed password',
            'min_severity': 4,
            'max_severity': 10,
        },
        'PORT_SCAN': {
            'pattern': r'port scan|nmap|masscan',
            'min_severity': 5,
            'max_severity': 8,
        },
        'MALWARE': {
            'pattern': r'backdoor|rootkit|trojan',
            'min_severity': 8,
            'max_severity': 10,
        },
    }
    
    def __init__(self):
        self.blocked_count = 0
        self.passed_count = 0
    
    def filter(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Filter an event. Returns None if noise, returns enriched event if real threat.
        """
        raw_log = event.get('raw_log', '')
        
        # Check whitelist first
        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, raw_log, re.IGNORECASE):
                self.blocked_count += 1
                return None  # Safe, ignore
        
        # Check blacklist
        for threat_type, config in self.BAD_PATTERNS.items():
            if re.search(config['pattern'], raw_log, re.IGNORECASE):
                self.passed_count += 1
                # Enrich event
                event['prefilter_type'] = threat_type
                event['prefilter_confidence'] = 'HIGH'
                event['prefilter_severity'] = config['min_severity']
                return event
        
        # Unknown pattern - let through with low confidence
        self.passed_count += 1
        event['prefilter_type'] = 'UNKNOWN'
        event['prefilter_confidence'] = 'LOW'
        event['prefilter_severity'] = 3
        return event
    
    def get_stats(self) -> Dict[str, int]:
        """Get filter statistics"""
        return {
            'blocked': self.blocked_count,
            'passed': self.passed_count,
            'efficiency': f"{(self.blocked_count / max(self.blocked_count + self.passed_count, 1)) * 100:.1f}%"
        }