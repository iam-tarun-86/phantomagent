"""AI Brain: Local LLM threat narrative & reasoning engine (Gemma 4 E2B via llama.cpp / Ollama)"""

import json
import re
import aiohttp
from typing import Dict, Any
from backend.config import AI_SERVER_URL, MODEL_NAME, AI_TIMEOUT


class BrainEngine:
    """Local AI Brain analysis engine (llama.cpp / Ollama)"""
    
    SYSTEM_PROMPT = """You are an elite cybersecurity analyst enriching security incident reports.
The detection system has already deterministically evaluated the event, assigned its severity score, and determined the containment action.
Your role is to produce a high-fidelity narrative explanation, attack pattern description, and technical indicators strictly matching the assigned severity level. Do not attempt to re-evaluate or suggest a different severity score.

Strict Tone and Urgency Guidelines:
- Severity 1-3 (LOG tier): Describe as low-risk, routine activity, or informational event.
- Severity 4-6 (ALERT tier): Describe as suspicious/moderate risk warranting security review.
- Severity 7-8 (AUTO_CONTAIN tier): Describe as high-risk active threat requiring automated containment.
- Severity 9-10 (PENDING_APPROVAL tier): Describe as critical, severe active intrusion requiring immediate lockdown. Never use downplaying words like "minor", "low-risk", "benign", or "routine".

Response Format:
Respond ONLY in valid JSON format with these exact fields:
{
    "threat_type": "Brute Force|Port Scan|File Anomaly|DNS Tunneling|Suspicious Login|Malware|Unknown",
    "attack_pattern": "precise description of attack technique observed",
    "explanation": "one sentence explaining why this is a threat, strictly matching the assigned severity urgency",
    "reason": "detailed technical explanation including specific numbers, ports, and indicators",
    "confidence": 95,
    "indicators": ["indicator 1", "indicator 2", "indicator 3"]
}"""
    
    def __init__(self):
        self.session = None
        self.is_available = False
        self.engine_type = "fallback"  # 'llama.cpp', 'ollama', or 'fallback'
    
    @staticmethod
    def _get_tier_info(severity: int) -> tuple:
        if severity <= 3:
            return "LOG", "Low-Risk / Routine"
        elif severity <= 6:
            return "ALERT", "Moderate / Suspicious"
        elif severity <= 8:
            return "AUTO_CONTAIN", "High-Risk / Serious"
        else:
            return "PENDING_APPROVAL", "Critical / Severe Active Intrusion"
    
    async def initialize(self):
        """Check if local llama.cpp / Ollama is running with Gemma"""
        try:
            async with aiohttp.ClientSession() as session:
                # Check llama.cpp server health / props
                try:
                    async with session.get(f"{AI_SERVER_URL}/health", timeout=3) as resp:
                        if resp.status == 200:
                            self.is_available = True
                            self.engine_type = "llama.cpp"
                            print(f"[BRAIN] Connected to llama.cpp server at {AI_SERVER_URL} (Model: {MODEL_NAME})")
                            return
                except Exception:
                    pass

                # Check Ollama tags
                try:
                    async with session.get(f"{AI_SERVER_URL}/api/tags", timeout=3) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            models = [m.get('name', '') for m in data.get('models', [])]
                            self.is_available = True
                            self.engine_type = "ollama"
                            print(f"[BRAIN] Connected to Ollama at {AI_SERVER_URL}. Available models: {models}")
                            return
                except Exception:
                    pass

                print(f"[BRAIN] Local LLM server not detected on {AI_SERVER_URL}. Using rule-based fallback analysis.")
        except Exception as e:
            print(f"[BRAIN] Cannot connect to local LLM: {e}")
            print("[BRAIN] Using rule-based fallback analysis.")
    
    async def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a security event with Gemma 4 E2B or fallback.
        """
        if not self.is_available:
            return self._fallback_analysis(event)
        
        try:
            prompt = self._build_prompt(event)
            timeout = aiohttp.ClientTimeout(total=AI_TIMEOUT)

            async with aiohttp.ClientSession() as session:
                response_text = ""
                
                # If running via llama.cpp (llama-server)
                if self.engine_type == "llama.cpp":
                    # Try OpenAI-compatible chat completions first
                    chat_payload = {
                        "messages": [
                            {"role": "system", "content": self.SYSTEM_PROMPT},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.1,
                        "response_format": {"type": "json_object"}
                    }
                    async with session.post(f"{AI_SERVER_URL}/v1/chat/completions", json=chat_payload, timeout=timeout) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            response_text = data.get('choices', [{}])[0].get('message', {}).get('content', '{}')
                        else:
                            # Fallback to /completion
                            comp_payload = {
                                "prompt": f"<start_of_turn>user\n{self.SYSTEM_PROMPT}\n\n{prompt}<end_of_turn>\n<start_of_turn>model\n",
                                "temperature": 0.1,
                                "n_predict": 512
                            }
                            async with session.post(f"{AI_SERVER_URL}/completion", json=comp_payload, timeout=timeout) as c_resp:
                                if c_resp.status == 200:
                                    c_data = await c_resp.json()
                                    response_text = c_data.get('content', '{}')

                # If running via Ollama
                elif self.engine_type == "ollama":
                    ollama_payload = {
                        "model": MODEL_NAME,
                        "prompt": prompt,
                        "system": self.SYSTEM_PROMPT,
                        "stream": False,
                        "format": "json"
                    }
                    async with session.post(f"{AI_SERVER_URL}/api/generate", json=ollama_payload, timeout=timeout) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            response_text = data.get('response', '{}')

                # Parse extracted JSON
                if response_text:
                    try:
                        clean_json = re.search(r'\{.*\}', response_text, re.DOTALL)
                        json_str = clean_json.group(0) if clean_json else response_text.strip()
                        analysis = json.loads(json_str)

                        # Extract integer severity (handles 9, "9", or "Critical (9)")
                        raw_sev = analysis.get('severity', 5)
                        if isinstance(raw_sev, (int, float)):
                            sev = int(raw_sev)
                        else:
                            sev_digits = re.findall(r'\d+', str(raw_sev))
                            sev = int(sev_digits[0]) if sev_digits else 5

                        # Extract float confidence (handles 0.95 or 95.0)
                        raw_conf = analysis.get('confidence', 90.0)
                        if isinstance(raw_conf, (int, float)):
                            conf = float(raw_conf) * 100 if raw_conf <= 1.0 else float(raw_conf)
                        else:
                            conf = 90.0

                        return {
                            "threat_type": analysis.get('threat_type', event.get('type', 'Unknown')),
                            "severity": sev,
                            "attack_pattern": analysis.get('attack_pattern', 'Unknown pattern'),
                            "action": analysis.get('action', 'ALERT'),
                            "explanation": analysis.get('explanation', 'No explanation provided'),
                            "reason": analysis.get('reason', 'AI analysis completed'),
                            "confidence": conf,
                            "indicators": analysis.get('indicators', ['Pattern match detected']),
                            "source": "BRAIN",
                            "ai_confidence": "HIGH"
                        }
                    except Exception as parse_err:
                        print(f"[BRAIN] JSON parse error: {parse_err}. Raw: {response_text}")
                        return self._fallback_analysis(event)
                else:
                    return self._fallback_analysis(event)

        except Exception as e:
            print(f"[BRAIN] Analysis error: {e}")
            return self._fallback_analysis(event)
    
    def _build_prompt(self, event: Dict[str, Any]) -> str:
        """Build analysis prompt with deterministic severity context"""
        severity = event.get('severity', event.get('prefilter_severity', 5))
        tier, desc = self._get_tier_info(severity)
        
        return f"""This security incident has been evaluated by the detection system as Severity {severity} ({tier} tier: {desc}).
Write an analyst-style explanation and attack pattern description strictly consistent with this assigned severity level. Do not suggest a different severity.

Source: {event.get('source', 'Unknown')}
Detected Attack Type: {event.get('type', 'Unknown')}
Raw Log: {event.get('raw_log', 'No log data')}
Attacker Source IP: {event.get('source_ip', 'Unknown')}
Assigned Severity: {severity} ({tier} - {desc})

Respond with JSON only containing: threat_type, attack_pattern, explanation, reason, confidence, indicators."""
    
    def _fallback_analysis(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based fallback when Brain AI is unavailable"""
        event_type = event.get('type', 'UNKNOWN')
        prefilter_sev = event.get('prefilter_severity', 5)
        source_ip = event.get('source_ip', 'Unknown')
        raw_log = event.get('raw_log', 'No log data')
        
        fallbacks = {
            'BRUTE_FORCE': {
                'threat_type': 'Brute Force',
                'severity': 9,
                'attack_pattern': 'Repeated failed authentication attempts',
                'action': 'LOCKDOWN',
                'explanation': 'Multiple failed login attempts indicate brute force attack',
                'reason': f'Multiple failed SSH login attempts detected from {source_ip}. Pattern matches Hydra/Medusa brute-force tool signature. High-frequency attempts with common credential lists.',
                'confidence': 92.5,
                'indicators': [
                    f'Repeated failed auth from {source_ip}',
                    'Common username: root/admin',
                    'Password spraying pattern',
                    'No successful authentication',
                    'High frequency attempts'
                ]
            },
            'PORT_SCAN': {
                'threat_type': 'Port Scan',
                'severity': 7,
                'attack_pattern': 'Reconnaissance probing multiple ports',
                'action': 'CONTAIN',
                'explanation': 'Systematic port scanning indicates reconnaissance activity',
                'reason': f'Sequential SYN packets detected across multiple ports from {source_ip}. No legitimate handshake completion. Pattern matches Nmap -sS stealth scan.',
                'confidence': 88.3,
                'indicators': [
                    f'Multiple ports probed from {source_ip}',
                    'SYN packets without ACK',
                    'Sequential port targeting',
                    'No established connections',
                    'Reconnaissance behavior'
                ]
            },
            'FILE_ANOMALY': {
                'threat_type': 'File Anomaly',
                'severity': 6,
                'attack_pattern': 'Suspicious executable in temporary directory',
                'action': 'ALERT',
                'explanation': 'Executable file created in temporary location',
                'reason': f'Suspicious file activity detected. {raw_log}. File location and behavior match known malware patterns.',
                'confidence': 78.0,
                'indicators': [
                    'Executable in temp directory',
                    'Unexpected file creation',
                    'Suspicious file signature',
                    'No legitimate process association'
                ]
            },
            'DNS_TUNNELING': {
                'threat_type': 'DNS Tunneling',
                'severity': 8,
                'attack_pattern': 'Data exfiltration via DNS queries',
                'action': 'CONTAIN',
                'explanation': 'Abnormal DNS query patterns suggest data tunneling',
                'reason': f'Abnormal DNS query volume and patterns from {source_ip}. Queries to unusual domains with high entropy. Possible data exfiltration via DNS protocol.',
                'confidence': 85.7,
                'indicators': [
                    'High DNS query volume',
                    'Unusual domain names',
                    'High entropy subdomains',
                    'Large query payload sizes',
                    'Off-hours activity'
                ]
            },
            'SUSPICIOUS_LOGIN': {
                'threat_type': 'Suspicious Login',
                'severity': 5,
                'attack_pattern': 'Unusual authentication attempt',
                'action': 'ALERT',
                'explanation': 'Login attempt from unexpected source or with unusual pattern',
                'reason': f'Login attempt from {source_ip} with unusual characteristics. Geographic anomaly or timing pattern detected.',
                'confidence': 72.0,
                'indicators': [
                    f'Login from {source_ip}',
                    'Unusual time of access',
                    'Geographic anomaly',
                    'Failed MFA attempt'
                ]
            },
            'DOS_ATTACK': {
                'threat_type': 'Unknown',
                'severity': 9,
                'attack_pattern': 'High-frequency packet flood / zero-day structural anomaly',
                'action': 'LOCKDOWN',
                'explanation': 'Abnormal traffic volume and structural packet anomalies indicate DoS or zero-day exploit attempt',
                'reason': f'High-frequency TCP flood / zero-day structural anomaly detected from {source_ip}. Packet entropy and connection rate exceed normal thresholds.',
                'confidence': 94.0,
                'indicators': [
                    f'High connection rate from {source_ip}',
                    'SYN flood / packet storm pattern',
                    'Zero-day structural anomaly signature',
                    'Anomalous traffic burst'
                ]
            },
        }
        
        result = fallbacks.get(event_type, {
            'threat_type': 'Unknown',
            'severity': prefilter_sev,
            'attack_pattern': 'Unrecognized activity pattern',
            'action': 'ALERT',
            'explanation': 'Unable to classify threat pattern',
            'reason': f'Unrecognized activity pattern from {source_ip}. {raw_log}. Requires manual review.',
            'confidence': 45.0,
            'indicators': [
                f'Unknown pattern from {source_ip}',
                'Unclassified activity',
                'Manual review required'
            ]
        })
        
        result['source'] = 'FALLBACK'
        result['ai_confidence'] = 'MEDIUM'
        
        return result


# Aliases for backward compatibility
Brain = BrainEngine
QwenEngine = BrainEngine
AIBrain = BrainEngine
