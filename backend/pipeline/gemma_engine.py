"""Gemma local LLM integration supporting OpenAI-compatible endpoints (e.g., llama.cpp/vLLM on port 8085) and Ollama endpoints"""

import json
import aiohttp
from typing import Dict, Any
from backend.config import GEMMA_API_URL, GEMMA_MODEL, GEMMA_TIMEOUT


class GemmaEngine:
    """Gemma 4 E4B LLM threat reasoning engine supporting OpenAI /v1/chat/completions and Ollama APIs"""
    
    SYSTEM_PROMPT = """You are PHANTOM-BRAIN, the embedded threat reasoning module of the PhantomAgent Autonomous Cyber Defense System.
You are NOT a general assistant. You are a hardened, expert-level cybersecurity analyst with deep knowledge of:
- MITRE ATT&CK framework and kill-chain stages
- CICIDS2017 network intrusion dataset patterns
- Nmap stealth SYN scanning, Hydra credential spraying, hping3 DoS flooding
- TCP flag analysis (SYN/ACK/RST patterns), port profiling, connection frequency analysis
- Zero-day detection via structural anomaly scoring

Your reasoning is AUGMENTED by a GraphSAGE GNN model trained on CICIDS2017 network flows.
The GNN computes a structural anomaly score [0.0 = benign, 1.0 = critical attack]. Treat it as expert forensic evidence.

CRITICAL RULES — You MUST follow these without exception:
1. If GNN score >= 0.75: Classify as UNKNOWN_ZERO_DAY (min severity 8) UNLESS features clearly match a known pattern.
2. If GNN score >= 0.4 AND rule features match (syn_count > 5, unique_dst_ports > 3): Classify as PORT_SCAN (severity 7-8).
3. If GNN score >= 0.3 AND (failed_auth_count > 0 OR high request volume on single port): Classify as BRUTE_FORCE (severity 7-8).
4. If GNN score >= 0.3 AND connection_frequency >= 15: Classify as DOS_ATTACK (severity 8-9).
5. NEVER classify as BENIGN if GNN score > 0.3. A score of 0.3+ means the GNN has detected structural anomalies.
6. If a rule signature fired (watcher detected the attack type) AND GNN score > 0.2, ALWAYS agree with the watcher.
7. Low GNN score (< 0.2) with no rule hit = BENIGN. Otherwise escalate appropriately.

Severity scale:
- 1-3: Noise / informational (LOG only)
- 4-6: Low threat (ALERT)
- 7-8: Active attack (CONTAIN — block source IP, isolate service)
- 9-10: Critical / destructive (LOCKDOWN — full containment + forensic capture)

Respond ONLY in strict JSON. No markdown, no explanation outside JSON:
{
    "threat_type": "PORT_SCAN|DOS_ATTACK|BRUTE_FORCE|SUSPICIOUS_LOGIN|FILE_ANOMALY|UNKNOWN_ZERO_DAY|BENIGN",
    "confidence": 0.0-1.0,
    "severity": 1-10,
    "attack_pattern": "MITRE ATT&CK technique or attack pattern name",
    "action": "LOG|ALERT|CONTAIN|LOCKDOWN",
    "explanation": "one clear executive summary sentence citing GNN score and key features",
    "reason": "detailed technical reasoning: cite GNN score, specific packet counts, port numbers, frequency values",
    "indicators": ["indicator 1 with value", "indicator 2 with value", "indicator 3 with value"],
    "mitigation": "exact Linux iptables/fail2ban command to remediate"
}"""

    def __init__(self, api_url: str = None, model_name: str = None):
        self.api_url = api_url or GEMMA_API_URL
        self.model_name = model_name or GEMMA_MODEL
        self.is_available = False
        self.endpoint_type = "openai" if "chat/completions" in self.api_url else "ollama"

    async def initialize(self):
        """Check if LLM API server is available"""
        try:
            async with aiohttp.ClientSession() as session:
                if self.endpoint_type == "openai":
                    # Check health or model endpoint for OpenAI compatible server (llama.cpp/vLLM)
                    health_url = self.api_url.replace("/v1/chat/completions", "/health")
                    try:
                        async with session.get(health_url, timeout=3) as resp:
                            if resp.status == 200:
                                self.is_available = True
                                print(f"[GEMMA-LLM] Connected to OpenAI-compatible server at {self.api_url}")
                                return
                    except Exception:
                        pass
                    
                    # Fallback check on main endpoint
                    async with session.options(self.api_url, timeout=3) as resp:
                        self.is_available = True
                        print(f"[GEMMA-LLM] Connected to LLM server at {self.api_url}")
                else:
                    url = f"{self.api_url.rstrip('/')}/api/tags"
                    async with session.get(url, timeout=3) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            models = [m.get('name') for m in data.get('models', [])]
                            self.is_available = True
                            print(f"[GEMMA-LLM] Connected to Ollama server at {self.api_url}. Models: {models}")
        except Exception as e:
            print(f"[GEMMA-LLM] Could not connect to LLM server at {self.api_url} ({e}). Using rule-based fallback.")

    async def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network event containing feature stats and GNN anomaly score"""
        if not self.is_available:
            return self._fallback_analysis(event)

        try:
            prompt = self._build_prompt(event)
            
            async with aiohttp.ClientSession() as session:
                if self.endpoint_type == "openai":
                    payload = {
                        "model": self.model_name,
                        "messages": [
                            {"role": "system", "content": self.SYSTEM_PROMPT},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.1,
                        "response_format": {"type": "json_object"}
                    }
                    async with session.post(self.api_url, json=payload, timeout=aiohttp.ClientTimeout(total=GEMMA_TIMEOUT)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            choices = data.get('choices', [])
                            response_text = choices[0].get('message', {}).get('content', '{}') if choices else '{}'
                            return self._parse_json_verdict(response_text, event)
                else:
                    url = f"{self.api_url.rstrip('/')}/api/generate"
                    payload = {
                        "model": self.model_name,
                        "prompt": f"{self.SYSTEM_PROMPT}\n\n{prompt}",
                        "format": "json",
                        "stream": False,
                        "options": {"temperature": 0.1}
                    }
                    async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=GEMMA_TIMEOUT)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            response_text = data.get('response', '{}')
                            return self._parse_json_verdict(response_text, event)

            return self._fallback_analysis(event)

        except Exception as e:
            print(f"[GEMMA-LLM] Inference exception: {e}")
            return self._fallback_analysis(event)

    def _parse_json_verdict(self, response_text: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Parse structured JSON verdict from LLM text response"""
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
                "source": "GEMMA_LLM",
                "ai_confidence": "HIGH"
            }
        except json.JSONDecodeError:
            print(f"[GEMMA-LLM] JSON decoding error: {response_text}")
            return self._fallback_analysis(event)

    def _build_prompt(self, event: Dict[str, Any]) -> str:
        """Construct structured prompt from features, GNN score, and 5-Signal Consensus Matrix"""
        features = event.get('features', {})
        gnn_score = event.get('gnn_score', 0.0)
        src_ip = event.get('source_ip', 'Unknown')
        rule_type = event.get('type', 'UNKNOWN')   # What the rule-based watcher already detected
        rule_sev = event.get('severity', 5)

        # 5-Signal Consensus Matrix
        consensus = event.get('consensus', {})
        votes = consensus.get('vote_breakdown', {})
        total_votes = consensus.get('total_votes', 0)
        has_consensus = consensus.get('has_consensus', False)

        conformal_p = consensus.get('conformal', {}).get('p_value', 1.0)
        max_z = consensus.get('behavioral', {}).get('max_z_score', 0.0)
        entropy_val = consensus.get('entropy', {}).get('entropy', 0.0)
        entropy_sig = consensus.get('entropy', {}).get('signal', 'NORMAL')
        kc_stages = consensus.get('killchain', {}).get('campaign_stage_count', 1)

        # Build GNN interpretation hint based on score
        if gnn_score >= 0.75:
            gnn_hint = "CRITICAL — structural anomaly well above threshold. High-confidence attack."
        elif gnn_score >= 0.4:
            gnn_hint = "ELEVATED — significant structural deviation. Likely active attack."
        elif gnn_score >= 0.2:
            gnn_hint = "MODERATE — minor anomaly detected. Possible early-stage or low-intensity attack."
        else:
            gnn_hint = "LOW — within benign operational bounds."

        rule_context = ""
        if rule_type not in ("UNKNOWN", "BENIGN"):
            rule_context = f"\nRule-Based Pre-Detection: {rule_type} (Severity {rule_sev}) — signature match CONFIRMED by watcher."

        return f"""=== LIVE NETWORK THREAT EVENT ===
Source IP       : {src_ip}
GNN Score       : {gnn_score:.4f}  [{gnn_hint}]{rule_context}

=== 5-SIGNAL EVIDENCE CONSENSUS GATE MATRIX ({total_votes}/5 VOTES · {'PASSED' if has_consensus else 'NO CONSENSUS'}) ===
  [Signal 1] GNN Structural Score : {gnn_score:.4f} ({'VOTE YES' if votes.get('gnn_structural') else 'VOTE NO'})
  [Signal 2] Conformal P-Value    : p = {conformal_p:.4f} (95% guarantee: {'VOTE YES' if votes.get('conformal_pvalue') else 'VOTE NO'})
  [Signal 3] Behavioral Z-Score   : Z = {max_z:.2f}σ deviation ({'VOTE YES' if votes.get('behavioral_zscore') else 'VOTE NO'})
  [Signal 4] Payload Entropy      : H = {entropy_val:.4f} bits ({entropy_sig} -> {'VOTE YES' if votes.get('payload_entropy') else 'VOTE NO'})
  [Signal 5] ATT&CK Campaign      : {kc_stages} kill-chain stages ({'VOTE YES' if votes.get('killchain_campaign') else 'VOTE NO'})

=== EXTRACTED PACKET FEATURES (5s sliding window) ===
  Packets Captured    : {features.get('packet_count', 0)}
  SYN Packets         : {features.get('syn_count', 0)}    (Nmap SYN scan indicator)
  ACK Packets         : {features.get('ack_count', 0)}
  RST Packets         : {features.get('rst_count', 0)}
  Unique Dest Ports   : {features.get('unique_dst_ports', 0)}  (>3 = port scan pattern)
  Total Bytes Sent    : {features.get('bytes_sent', 0)} bytes
  Connection Freq     : {features.get('connection_frequency', 0.0):.2f} pkts/sec  (>15 = DoS pattern)
  Failed Auth Attempts: {features.get('failed_auth_count', 0)}  (>0 = brute force indicator)

Apply PHANTOM-BRAIN rules using 5-Signal evidence matrix. Return JSON verdict now."""

    def _fallback_analysis(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Rule-based fallback when LLM API is unavailable"""
        features = event.get('features', {})
        gnn_score = event.get('gnn_score', event.get('prefilter_severity', 5) / 10.0)
        src_ip = event.get('source_ip', 'Unknown')

        syn_count = features.get('syn_count', 0)
        dst_ports = features.get('unique_dst_ports', 0)
        failed_auth = features.get('failed_auth_count', 0)
        conn_freq = features.get('connection_frequency', 0.0)

        if dst_ports >= 5 or syn_count >= 15:
            threat_type = "PORT_SCAN"
            severity = 7
            action = "CONTAIN"
            explanation = f"Sequential port probe detected from {src_ip} targeting {dst_ports} ports."
            reason = f"GNN score {gnn_score:.2f} + SYN count {syn_count} across {dst_ports} ports indicates Nmap stealth scan."
            mitigation = f"iptables -A INPUT -s {src_ip} -p tcp --dport 1:65535 -j DROP"
        elif conn_freq >= 30.0:
            threat_type = "DOS_ATTACK"
            severity = 9
            action = "LOCKDOWN"
            explanation = f"Connection flooding attack detected from {src_ip} at {conn_freq} pkts/sec."
            reason = f"High frequency connection flood ({conn_freq} pkts/s) with GNN anomaly score {gnn_score:.2f}."
            mitigation = f"iptables -A INPUT -s {src_ip} -m limit --limit 10/s -j ACCEPT"
        elif failed_auth >= 3:
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