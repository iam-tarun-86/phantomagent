"""Gemma local LLM integration targeting gemma4:e4b via Ollama API"""

import json
import aiohttp
from typing import Dict, Any
from backend.config import GEMMA_API_URL, GEMMA_MODEL, GEMMA_TIMEOUT


class GemmaEngine:
    """Gemma 4 E4B LLM threat reasoning engine powered by Ollama API"""
    
    SYSTEM_PROMPT = """You are PhantomAgent's Cyber Threat Analysis Engine ("The Brain").
Analyze the network traffic statistical features and GNN structural anomaly score to render a definitive cybersecurity verdict.

Respond ONLY in strict JSON format with these exact fields:
{
    "threat_type": "PORT_SCAN|DOS_ATTACK|BRUTE_FORCE|SUSPICIOUS_LOGIN|FILE_ANOMALY|UNKNOWN_ZERO_DAY|BENIGN",
    "confidence": 0.0-1.0,
    "severity": 1-10,
    "attack_pattern": "brief technical description of attack pattern",
    "action": "LOG|ALERT|CONTAIN|LOCKDOWN",
    "explanation": "one clear sentence executive summary",
    "reason": "detailed technical reasoning citing specific feature numbers and GNN anomaly score",
    "indicators": ["indicator 1", "indicator 2"],
    "mitigation": "suggested active mitigation command or firewall rule"
}

Rules:
- severity 1-3: minor concern, action LOG
- severity 4-6: moderate threat, action ALERT
- severity 7-8: serious threat (e.g. PORT_SCAN), action CONTAIN
- severity 9-10: critical threat (e.g. DOS_ATTACK, BRUTE_FORCE), action LOCKDOWN
- If GNN anomaly score > 0.75 but features don't match known patterns, classify as UNKNOWN_ZERO_DAY with severity >= 8.
- Respond ONLY with JSON. No markdown wrappers, no conversational filler."""

    def __init__(self, ollama_url: str = "http://localhost:11434", model_name: str = "gemma4:e4b"):
        self.ollama_url = ollama_url.rstrip("/")
        self.model_name = model_name
        self.is_available = False

    async def initialize(self):
        """Check if Ollama server and gemma4:e4b model are available"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.ollama_url}/api/tags"
                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        models = [m.get('name') for m in data.get('models', [])]
                        self.is_available = True
                        print(f"[GEMMA-OLLAMA] Connected to Ollama server. Installed models: {models}")
                    else:
                        print(f"[GEMMA-OLLAMA] Ollama server returned HTTP {resp.status}. Using fallback.")
        except Exception as e:
            print(f"[GEMMA-OLLAMA] Could not connect to Ollama ({e}). Using rule-based LLM fallback.")

    async def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze network event containing feature stats and GNN anomaly score
        """
        if not self.is_available:
            return self._fallback_analysis(event)

        try:
            prompt = self._build_prompt(event)
            url = f"{self.ollama_url}/api/generate"
            
            payload = {
                "model": self.model_name,
                "prompt": f"{self.SYSTEM_PROMPT}\n\n{prompt}",
                "format": "json",
                "stream": False,
                "options": {
                    "temperature": 0.1
                }
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=GEMMA_TIMEOUT)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        response_text = data.get('response', '{}')
                        
                        try:
                            analysis = json.loads(response_text)
                            return {
                                "threat_type": analysis.get('threat_type', 'UNKNOWN'),
                                "confidence": float(analysis.get('confidence', 0.85)),
                                "severity": int(analysis.get('severity', 5)),
                                "attack_pattern": analysis.get('attack_pattern', 'Detected network anomaly'),
                                "action": analysis.get('action', 'ALERT'),
                                "explanation": analysis.get('explanation', 'Network anomaly detected'),
                                "reason": analysis.get('reason', f"GNN Anomaly score {event.get('gnn_score', 0.0)} flagged suspicious features."),
                                "indicators": analysis.get('indicators', [f"Source IP {event.get('source_ip', 'unknown')}"]),
                                "mitigation": analysis.get('mitigation', f"iptables -A INPUT -s {event.get('source_ip', 'unknown')} -j DROP"),
                                "source": "GEMMA_4_E4B",
                                "ai_confidence": "HIGH"
                            }
                        except json.JSONDecodeError:
                            print(f"[GEMMA-OLLAMA] JSON decoding error from output: {response_text}")
                            return self._fallback_analysis(event)
                    else:
                        print(f"[GEMMA-OLLAMA] Ollama API error: {resp.status}")
                        return self._fallback_analysis(event)

        except Exception as e:
            print(f"[GEMMA-OLLAMA] Inference exception: {e}")
            return self._fallback_analysis(event)

    def _build_prompt(self, event: Dict[str, Any]) -> str:
        """Construct structured prompt from features and GNN score"""
        features = event.get('features', {})
        gnn_score = event.get('gnn_score', 0.0)
        src_ip = event.get('source_ip', 'Unknown')

        return f"""Analyze Network Event:
Source IP: {src_ip}
GNN Structural Anomaly Score: {gnn_score:.4f} (Scale 0.0=Benign to 1.0=Critical Anomaly)

Extracted Live Features:
- Packets in Window: {features.get('packet_count', 0)}
- SYN Packets: {features.get('syn_count', 0)}
- ACK Packets: {features.get('ack_count', 0)}
- RST Packets: {features.get('rst_count', 0)}
- Unique Destination Ports Targeted: {features.get('unique_dst_ports', 0)}
- Total Bytes Sent: {features.get('bytes_sent', 0)}
- Connection Frequency: {features.get('connection_frequency', 0.0)} pkts/sec
- Failed Authentication Attempts: {features.get('failed_auth_count', 0)}

Render final verdict in JSON format."""

    def _fallback_analysis(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based fallback when Ollama API is unavailable"""
        features = event.get('features', {})
        gnn_score = event.get('gnn_score', event.get('prefilter_severity', 5) / 10.0)
        src_ip = event.get('source_ip', 'Unknown')

        syn_count = features.get('syn_count', 0)
        dst_ports = features.get('unique_dst_ports', 0)
        failed_auth = features.get('failed_auth_count', 0)
        conn_freq = features.get('connection_frequency', 0.0)

        if dst_ports >= 10 or syn_count >= 15:
            threat_type = "PORT_SCAN"
            severity = 7
            action = "CONTAIN"
            explanation = f"Sequential port probe detected from {src_ip} targeting {dst_ports} ports."
            reason = f"GNN score {gnn_score:.2f} + SYN count {syn_count} across {dst_ports} ports indicates Nmap stealth scan."
            mitigation = f"iptables -A INPUT -s {src_ip} -p tcp --dport 1:65535 -j DROP"
        elif conn_freq > 50.0:
            threat_type = "DOS_ATTACK"
            severity = 9
            action = "LOCKDOWN"
            explanation = f"Connection flooding attack detected from {src_ip} at {conn_freq} pkts/sec."
            reason = f"High frequency connection flood ({conn_freq} pkts/s) with GNN anomaly score {gnn_score:.2f}."
            mitigation = f"iptables -A INPUT -s {src_ip} -m limit --limit 10/s -j ACCEPT"
        elif failed_auth > 5:
            threat_type = "BRUTE_FORCE"
            severity = 8
            action = "CONTAIN"
            explanation = f"Authentication brute-force detected from {src_ip} with {failed_auth} failed logins."
            reason = f"Multiple failed login attempts ({failed_auth}) from {src_ip}. GNN anomaly score {gnn_score:.2f}."
            mitigation = f"fail2ban-client set sshd banip {src_ip}"
        elif gnn_score > 0.75:
            threat_type = "UNKNOWN_ZERO_DAY"
            severity = 8
            action = "CONTAIN"
            explanation = f"Zero-day structural anomaly detected from {src_ip} by GNN model."
            reason = f"GNN structural anomaly score {gnn_score:.4f} exceeded threshold 0.75 without matching known attack signatures."
            mitigation = f"iptables -A INPUT -s {src_ip} -j DROP"
        else:
            threat_type = "BENIGN"
            severity = 2
            action = "LOG"
            explanation = f"Normal network traffic pattern from {src_ip}."
            reason = f"Features and GNN anomaly score ({gnn_score:.2f}) are within benign operational bounds."
            mitigation = "NONE"

        return {
            "threat_type": threat_type,
            "confidence": 0.90 if gnn_score > 0.5 else 0.95,
            "severity": severity,
            "attack_pattern": f"{threat_type} pattern match",
            "action": action,
            "explanation": explanation,
            "reason": reason,
            "indicators": [f"Source IP: {src_ip}", f"GNN Score: {gnn_score:.4f}", f"Unique Ports: {dst_ports}"],
            "mitigation": mitigation,
            "source": "GEMMA_FALLBACK",
            "ai_confidence": "HIGH"
        }