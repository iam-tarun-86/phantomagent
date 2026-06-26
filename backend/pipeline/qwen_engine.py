"""Qwen 3.5 local LLM integration"""

import json
import aiohttp
from typing import Dict, Any
from backend.config import QWEN_API_URL, QWEN_MODEL, QWEN_TIMEOUT


class QwenEngine:
    """Local Qwen 3.5 analysis engine"""
    
    SYSTEM_PROMPT = """You are an elite cybersecurity analyst. Analyze this security event and respond ONLY in valid JSON format with these exact fields:
{
    "threat_type": "Brute Force|Port Scan|File Anomaly|DNS Tunneling|Suspicious Login|Malware|Unknown",
    "severity": 1-10,
    "attack_pattern": "brief description of attack technique",
    "action": "LOG|ALERT|CONTAIN|LOCKDOWN",
    "explanation": "one sentence explaining why this is a threat"
}

Rules:
- severity 1-3: minor concern, LOG
- severity 4-6: moderate threat, ALERT
- severity 7-8: serious threat, CONTAIN
- severity 9-10: critical threat, LOCKDOWN
- Be concise. Respond ONLY with JSON. No markdown, no explanations."""
    
    def __init__(self):
        self.session = None
        self.is_available = False
    
    async def initialize(self):
        """Check if Qwen is available"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("http://localhost:8085/api/tags", timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        models = [m['name'] for m in data.get('models', [])]
                        if any('qwen' in m for m in models):
                            self.is_available = True
                            print(f"[QWEN] Connected to Ollama. Models: {models}")
                        else:
                            print("[QWEN] Qwen model not found. Run: ollama pull qwen3:8b")
                    else:
                        print("[QWEN] Ollama not responding. Using fallback analysis.")
        except Exception as e:
            print(f"[QWEN] Cannot connect to Ollama: {e}")
            print("[QWEN] Using rule-based fallback analysis.")
    
    async def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a security event with Qwen or fallback.
        """
        if not self.is_available:
            return self._fallback_analysis(event)
        
        try:
            prompt = self._build_prompt(event)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    QWEN_API_URL,
                    json={
                        "model": QWEN_MODEL,
                        "prompt": prompt,
                        "system": self.SYSTEM_PROMPT,
                        "stream": False,
                        "format": "json"
                    },
                    timeout=aiohttp.ClientTimeout(total=QWEN_TIMEOUT)
                ) as resp:
                    
                    if resp.status == 200:
                        data = await resp.json()
                        response_text = data.get('response', '{}')
                        
                        # Parse JSON response
                        try:
                            analysis = json.loads(response_text)
                            return {
                                "threat_type": analysis.get('threat_type', 'Unknown'),
                                "severity": int(analysis.get('severity', 5)),
                                "attack_pattern": analysis.get('attack_pattern', 'Unknown pattern'),
                                "action": analysis.get('action', 'ALERT'),
                                "explanation": analysis.get('explanation', 'No explanation provided'),
                                "source": "QWEN",
                                "confidence": "HIGH"
                            }
                        except json.JSONDecodeError:
                            print(f"[QWEN] Invalid JSON response: {response_text}")
                            return self._fallback_analysis(event)
                    else:
                        print(f"[QWEN] API error: {resp.status}")
                        return self._fallback_analysis(event)
                        
        except Exception as e:
            print(f"[QWEN] Analysis error: {e}")
            return self._fallback_analysis(event)
    
    def _build_prompt(self, event: Dict[str, Any]) -> str:
        """Build analysis prompt from event"""
        return f"""Analyze this security event:

Source: {event.get('source', 'Unknown')}
Type: {event.get('type', 'Unknown')}
Raw Log: {event.get('raw_log', 'No log data')}
Source IP: {event.get('source_ip', 'Unknown')}
Pre-filter Severity: {event.get('prefilter_severity', 'Unknown')}

Respond with JSON only."""
    
    def _fallback_analysis(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based fallback when Qwen is unavailable"""
        event_type = event.get('type', 'UNKNOWN')
        prefilter_sev = event.get('prefilter_severity', 5)
        
        fallbacks = {
            'BRUTE_FORCE': {
                'threat_type': 'Brute Force',
                'severity': 9,
                'attack_pattern': 'Repeated failed authentication attempts',
                'action': 'LOCKDOWN',
                'explanation': 'Multiple failed login attempts indicate brute force attack'
            },
            'PORT_SCAN': {
                'threat_type': 'Port Scan',
                'severity': 7,
                'attack_pattern': 'Reconnaissance probing multiple ports',
                'action': 'CONTAIN',
                'explanation': 'Systematic port scanning indicates reconnaissance activity'
            },
            'FILE_ANOMALY': {
                'threat_type': 'File Anomaly',
                'severity': 6,
                'attack_pattern': 'Suspicious executable in temporary directory',
                'action': 'ALERT',
                'explanation': 'Executable file created in temporary location'
            },
            'DNS_TUNNELING': {
                'threat_type': 'DNS Tunneling',
                'severity': 8,
                'attack_pattern': 'Data exfiltration via DNS queries',
                'action': 'CONTAIN',
                'explanation': 'Abnormal DNS query patterns suggest data tunneling'
            },
            'SUSPICIOUS_LOGIN': {
                'threat_type': 'Suspicious Login',
                'severity': 5,
                'attack_pattern': 'Unusual authentication attempt',
                'action': 'ALERT',
                'explanation': 'Login attempt from unexpected source or with unusual pattern'
            },
        }
        
        result = fallbacks.get(event_type, {
            'threat_type': 'Unknown',
            'severity': prefilter_sev,
            'attack_pattern': 'Unrecognized activity pattern',
            'action': 'ALERT',
            'explanation': 'Unable to classify threat pattern'
        })
        
        result['source'] = 'FALLBACK'
        result['confidence'] = 'MEDIUM'
        
        return result