"""Gemma local LLM integration supporting OpenAI-compatible endpoints (e.g., llama.cpp/vLLM on port 8085) and Ollama endpoints"""

import json
import aiohttp
from typing import Dict, Any
from backend.config import GEMMA_API_URL, GEMMA_MODEL, GEMMA_TIMEOUT


class GemmaEngine:
    """Gemma 4 E4B LLM threat reasoning engine supporting OpenAI /v1/chat/completions and Ollama APIs"""
    
    SYSTEM_PROMPT = """You are PHANTOM-BRAIN, the embedded threat reasoning module of the PhantomAgent Autonomous Cyber Defense System.
You are a hardened cybersecurity forensic engine. Your reasoning is AUGMENTED by a GraphSAGE GNN model trained on CICIDS2017 network flows.

You will receive an extracted telemetry payload containing GNN structural anomaly scores, 5-signal consensus matrix metrics, and packet flow statistics.

CRITICAL INSTRUCTIONS:
1. Always output ONLY valid raw JSON conforming strictly to the schema below. Do NOT output markdown or explanations outside JSON.
2. Determine if an attack or anomaly is occurring based on GNN score (>0.3 is elevated) and network indicators.
3. Map the attack to the precise MITRE ATT&CK technique (e.g., "T1046 - Network Service Discovery", "T1110 - Brute Force", "T1498 - Network Denial of Service", "T1078 - Valid Accounts").
4. Provide the Kill Chain stage ("Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Lateral Movement", "Impact").
5. Provide a crisp, factual justification citing GNN score and observed flow metrics.
6. Select ONE remediation intent from the fixed vocabulary below. You do NOT write shell
   commands — the response engine builds them. Your only free field is the target IP.
     - "BLOCK_IP" : drop all traffic from the source IP at the firewall
     - "BAN_SSH"  : ban the source IP from SSH via fail2ban (credential attacks)
     - "NONE"     : no active response warranted (benign traffic)

Required JSON Schema:
{
  "anomaly_detected": true,
  "confidence": 0.94,
  "mitre_technique": "T1046 - Network Service Discovery",
  "kill_chain_stage": "Reconnaissance",
  "justification": "GNN anomaly score (0.874) combined with elevated SYN-to-ACK ratio and high port entropy confirms a stealth horizontal port scan across subnet 172.28.0.0/24.",
  "defense_action": {
    "action": "BLOCK_IP",
    "target_ip": "172.28.0.10"
  }
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
                    # Check /v1/models endpoint for OpenAI-compatible server (llama.cpp/vLLM/Ollama)
                    models_url = self.api_url.replace("/v1/chat/completions", "/v1/models")
                    try:
                        async with session.get(models_url, timeout=5) as resp:
                            if resp.status == 200:
                                self.is_available = True
                                print(f"[GEMMA-LLM] Connected to OpenAI-compatible LLM server at {models_url}")
                                return
                    except Exception:
                        pass
                    
                    # Fallback check on main endpoint
                    try:
                        async with session.options(self.api_url, timeout=3) as resp:
                            self.is_available = True
                            print(f"[GEMMA-LLM] Connected to LLM server at {self.api_url}")
                    except Exception:
                        self.is_available = False
                else:
                    url = f"{self.api_url.rstrip('/')}/api/tags"
                    async with session.get(url, timeout=5) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            models = [m.get('name') for m in data.get('models', [])]
                            self.is_available = True
                            print(f"[GEMMA-LLM] Connected to Ollama server at {self.api_url}. Models: {models}")
        except Exception as e:
            self.is_available = False
            print(f"[GEMMA-LLM] Could not connect to LLM server at {self.api_url} ({e}). Will retry on inference.")

    async def analyze(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network event containing feature stats and GNN anomaly score"""
        if not self.is_available:
            await self.initialize()

        if not self.is_available:
            return self._fallback_analysis(event)

        try:
            prompt = self._build_prompt(event)
            
            async with aiohttp.ClientSession() as session:
                if self.endpoint_type == "openai":
                    schema_def = {
                        "type": "object",
                        "properties": {
                            "anomaly_detected": {"type": "boolean"},
                            "confidence": {"type": "number"},
                            "mitre_technique": {"type": "string"},
                            "kill_chain_stage": {"type": "string"},
                            "justification": {"type": "string"},
                            "defense_action": {
                                "type": "object",
                                "properties": {
                                    "action": {
                                        "type": "string",
                                        "enum": ["BLOCK_IP", "BAN_SSH", "NONE"]
                                    },
                                    "target_ip": {"type": "string"}
                                },
                                "required": ["action", "target_ip"]
                            }
                        },
                        "required": [
                            "anomaly_detected",
                            "confidence",
                            "mitre_technique",
                            "kill_chain_stage",
                            "justification",
                            "defense_action"
                        ]
                    }
                    payload = {
                        "model": self.model_name,
                        "messages": [
                            {"role": "system", "content": self.SYSTEM_PROMPT},
                            {"role": "user", "content": prompt}
                        ],
                        "temperature": 0.0,
                        "top_p": 1.0,
                        "max_tokens": 2048,
                        "response_format": {
                            "type": "json_schema",
                            "json_schema": {
                                "name": "threat_analysis",
                                "strict": True,
                                "schema": schema_def
                            },
                            "schema": schema_def
                        }
                    }
                    async with session.post(self.api_url, json=payload, timeout=aiohttp.ClientTimeout(total=GEMMA_TIMEOUT)) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            choices = data.get('choices', [])
                            response_text = choices[0].get('message', {}).get('content', '{}') if choices else '{}'
                            return self._parse_json_verdict(response_text, event)
                        else:
                            # If server rejects json_schema wrapper, retry with json_object
                            if resp.status == 400:
                                payload["response_format"] = {"type": "json_object"}
                                async with session.post(self.api_url, json=payload, timeout=aiohttp.ClientTimeout(total=GEMMA_TIMEOUT)) as retry_resp:
                                    if retry_resp.status == 200:
                                        data = await retry_resp.json()
                                        choices = data.get('choices', [])
                                        response_text = choices[0].get('message', {}).get('content', '{}') if choices else '{}'
                                        return self._parse_json_verdict(response_text, event)
                            print(f"[GEMMA-LLM] HTTP {resp.status} response from LLM server")
                else:
                    url = f"{self.api_url.rstrip('/')}/api/generate"
                    payload = {
                        "model": self.model_name,
                        "prompt": f"{self.SYSTEM_PROMPT}\n\n{prompt}",
                        "format": "json",
                        "stream": False,
                        "options": {"temperature": 0.0, "top_p": 1.0, "num_predict": 2048}
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
        """Parse structured JSON verdict with robust multi-layer exception handling & fallback"""
        src_ip = event.get('source_ip', 'unknown')
        try:
            clean_text = response_text.strip()
            # Extract content between markdown code blocks if present
            if "```" in clean_text:
                parts = clean_text.split("```")
                for part in parts:
                    part_str = part.strip()
                    if part_str.startswith("json"):
                        part_str = part_str[4:].strip()
                    if part_str.startswith("{") and part_str.endswith("}"):
                        clean_text = part_str
                        break

            # Substring extraction for first { to last } or auto-close bracket if truncated
            start_idx = clean_text.find("{")
            if start_idx != -1:
                end_idx = clean_text.rfind("}")
                if end_idx != -1 and end_idx > start_idx:
                    clean_text = clean_text[start_idx:end_idx + 1]
                else:
                    # Truncated JSON recovery
                    clean_text = clean_text[start_idx:].rstrip()
                    if not clean_text.endswith("}"):
                        clean_text = clean_text + ('"}' if clean_text.endswith('"') else '}')

            data = json.loads(clean_text)

            anomaly_detected = data.get('anomaly_detected', True)
            raw_conf = data.get('confidence', 0.90)
            try:
                confidence = float(raw_conf)
                if confidence > 1.0:
                    confidence /= 100.0
            except:
                confidence = 0.90

            mitre_technique = data.get('mitre_technique', data.get('attack_pattern', 'T1046 - Network Service Discovery'))
            kill_chain_stage = data.get('kill_chain_stage', 'Reconnaissance')
            justification = data.get('justification') or data.get('reason') or data.get('explanation') or f"GNN score {event.get('gnn_score', 0.0):.4f} flagged telemetry anomaly."

            defense_action = self._parse_defense_action(data, src_ip)

            # Map MITRE technique to canonical threat_type for dashboard & downstream rules
            tech_lower = mitre_technique.lower()
            if 't1046' in tech_lower or 'discovery' in tech_lower or 'scan' in tech_lower or 'port' in tech_lower:
                threat_type = 'PORT_SCAN'
                severity = 7
            elif 't1110' in tech_lower or 'brute' in tech_lower or 'credential' in tech_lower:
                threat_type = 'BRUTE_FORCE'
                severity = 8
            elif 't1498' in tech_lower or 't1499' in tech_lower or 'dos' in tech_lower or 'denial' in tech_lower or 'flood' in tech_lower:
                threat_type = 'DOS_ATTACK'
                severity = 9
            elif 't1078' in tech_lower or 'login' in tech_lower or 'account' in tech_lower:
                threat_type = 'SUSPICIOUS_LOGIN'
                severity = 7
            elif not anomaly_detected:
                threat_type = 'BENIGN'
                severity = 2
            else:
                threat_type = event.get('type') if event.get('type') not in ('UNKNOWN', 'BENIGN') else 'UNKNOWN_ZERO_DAY'
                severity = 8

            return {
                "threat_type": threat_type,
                "confidence": round(confidence, 2),
                "severity": severity,
                "anomaly_detected": anomaly_detected,
                "mitre_technique": mitre_technique,
                "kill_chain_stage": kill_chain_stage,
                "justification": justification,
                "defense_action": defense_action,
                "attack_pattern": mitre_technique,
                "action": "CONTAIN" if severity >= 6 else ("LOCKDOWN" if severity >= 9 else "LOG"),
                "explanation": justification,
                "reason": justification,
                "indicators": [f"Source IP: {src_ip}", f"MITRE: {mitre_technique}", f"Stage: {kill_chain_stage}"],
                "mitigation": self._describe_action(defense_action),
                "source": "GEMMA_LLM",
                "ai_confidence": "HIGH"
            }
        except Exception as e:
            print(f"[GEMMA-LLM] JSON decoding exception ({e}): raw text = {response_text[:100]}...")
            return self._fallback_analysis(event)

    VALID_ACTIONS = ("BLOCK_IP", "BAN_SSH", "NONE")

    def _parse_defense_action(self, data: Dict[str, Any], src_ip: str) -> Dict[str, str]:
        """
        Extract the structured remediation intent from a model verdict.

        The model may only choose from a fixed action vocabulary; anything unrecognised
        degrades to BLOCK_IP against the observed source IP rather than being executed
        as written. Free-text commands are never accepted — the responder builds argv.
        """
        raw = data.get('defense_action')
        action = None
        target_ip = src_ip

        if isinstance(raw, dict):
            candidate = str(raw.get('action', '')).strip().upper()
            if candidate in self.VALID_ACTIONS:
                action = candidate
            candidate_ip = str(raw.get('target_ip', '')).strip()
            if candidate_ip:
                target_ip = candidate_ip
        elif isinstance(raw, str) and raw.strip().upper() in self.VALID_ACTIONS:
            action = raw.strip().upper()

        if action is None:
            # Includes the legacy `active_defense_actions` shape, which we deliberately
            # do not parse: a model emitting command strings gets the default response.
            action = 'NONE' if data.get('anomaly_detected') is False else 'BLOCK_IP'

        return {"action": action, "target_ip": target_ip}

    @staticmethod
    def _describe_action(defense_action: Dict[str, str]) -> str:
        """Human-readable rendering of the intent, for dashboard display only.

        This string is never executed — see Responder.build_structured_action.
        """
        action = defense_action.get('action', 'NONE')
        ip = defense_action.get('target_ip', 'unknown')
        if action == 'BLOCK_IP':
            return f"iptables -A PHANTOM -s {ip} -j DROP"
        if action == 'BAN_SSH':
            return f"fail2ban-client set sshd banip {ip}"
        return "NONE"

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
            defense = "BLOCK_IP"
        elif conn_freq >= 30.0:
            threat_type = "DOS_ATTACK"
            severity = 9
            action = "LOCKDOWN"
            explanation = f"Connection flooding attack detected from {src_ip} at {conn_freq} pkts/sec."
            reason = f"High frequency connection flood ({conn_freq} pkts/s) with GNN anomaly score {gnn_score:.2f}."
            defense = "BLOCK_IP"
        elif failed_auth >= 3:
            threat_type = "BRUTE_FORCE"
            severity = 8
            action = "CONTAIN"
            explanation = f"Authentication brute-force detected from {src_ip} with {failed_auth} failed logins."
            reason = f"Multiple failed login attempts ({failed_auth}) from {src_ip}. GNN anomaly score {gnn_score:.2f}."
            defense = "BAN_SSH"
        elif gnn_score > 0.75:
            threat_type = "UNKNOWN_ZERO_DAY"
            severity = 8
            action = "CONTAIN"
            explanation = f"Zero-day structural anomaly detected from {src_ip} by GNN model."
            reason = f"GNN structural anomaly score {gnn_score:.4f} exceeded threshold 0.75 without matching known attack signatures."
            defense = "BLOCK_IP"
        else:
            threat_type = "BENIGN"
            severity = 2
            action = "LOG"
            explanation = f"Normal network traffic pattern from {src_ip}."
            reason = f"Features and GNN anomaly score ({gnn_score:.2f}) are within benign operational bounds."
            defense = "NONE"

        # The fallback picks an intent from the same fixed vocabulary the LLM uses; the
        # responder builds the actual command from it.
        defense_action = {
            "action": defense,
            "target_ip": src_ip if defense != "NONE" else "",
        }

        return {
            "threat_type": threat_type,
            "confidence": 0.90 if gnn_score > 0.5 else 0.95,
            "severity": severity,
            "attack_pattern": f"{threat_type} pattern match",
            "action": action,
            "explanation": explanation,
            "reason": reason,
            "indicators": [f"Source IP: {src_ip}", f"GNN Score: {gnn_score:.4f}", f"Unique Ports: {dst_ports}"],
            "defense_action": defense_action,
            "mitigation": self._describe_action(defense_action),
            "source": "GEMMA_FALLBACK",
            "ai_confidence": "HIGH"
        }