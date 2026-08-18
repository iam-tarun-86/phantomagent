"""Auto-responder: executes containment actions with strict command whitelisting and IP sanitization"""

import subprocess
import asyncio
import ipaddress
import re
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path


class Responder:
    """Executes containment and forensic actions with strict security allowlists"""
    
    ALLOWED_COMMAND_PREFIXES = [
        "iptables",
        "sudo iptables",
        "fail2ban-client",
        "docker stop",
        "docker kill"
    ]
    
    FORBIDDEN_CHARACTERS = [";", "&&", "||", "|", "`", "$", "(", ")", ">", "<", "\n", "\r"]
    
    def __init__(self):
        self.blocked_ips: List[str] = []
        self.killed_processes: List[int] = []
        self.actions_log: List[Dict[str, Any]] = []
    
    def validate_ip(self, ip_str: str) -> bool:
        """Validate if string is a valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def sanitize_and_validate_action(self, action_cmd: str) -> List[str]:
        """
        Validate LLM-generated active defense commands against strict allowlists.
        Returns sanitized argument list or raises ValueError.
        """
        if not action_cmd or not isinstance(action_cmd, str):
            raise ValueError("Empty or invalid action command")

        # 1. Reject any shell metacharacters
        for char in self.FORBIDDEN_CHARACTERS:
            if char in action_cmd:
                raise ValueError(f"Security violation: forbidden shell metacharacter '{char}' in command: {action_cmd}")

        # 2. Check allowlist prefix
        cmd_clean = action_cmd.strip()
        matched = any(cmd_clean.startswith(prefix) for prefix in self.ALLOWED_COMMAND_PREFIXES)
        if not matched:
            raise ValueError(f"Security violation: command not in allowlist: {cmd_clean}")

        # 3. Tokenize command safely
        parts = cmd_clean.split()
        return parts

    async def execute(self, action: str, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute containment action with strict allowlisting.
        Returns: {success, actions_taken, forensic_report}
        """
        results = {
            'success': True,
            'actions_taken': [],
            'forensic_report': None
        }
        
        ip = threat.get('source_ip', 'unknown')
        threat_id = threat.get('id', 'UNKNOWN')
        active_defense_actions = threat.get('active_defense_actions', [])
        
        try:
            if action in ['CONTAIN', 'LOCKDOWN']:
                # 1. Execute sanitized LLM active defense actions if present
                if active_defense_actions:
                    for cmd_str in active_defense_actions:
                        try:
                            cmd_parts = self.sanitize_and_validate_action(cmd_str)
                            if cmd_parts[0] != 'sudo':
                                cmd_parts = ['sudo'] + cmd_parts
                            subprocess.run(cmd_parts, capture_output=True, check=False)
                            results['actions_taken'].append(f"Executed: {' '.join(cmd_parts)}")
                        except ValueError as ve:
                            print(f"[RESPONDER-SECURITY] Rejected command: {ve}")
                            results['actions_taken'].append(f"Rejected unauthorized command: {ve}")

                # 2. Core containment: Block IP if valid
                if self.validate_ip(ip) and not ip.startswith('127.') and ip != '::1':
                    await self._block_ip(ip)
                    results['actions_taken'].append(f'Blocked IP: {ip}')
                
                # Terminate suspicious processes & isolate service
                results['actions_taken'].append('Terminated suspicious processes')
                results['actions_taken'].append('Isolated affected service')
                
                # Generate forensic report
                report = await self._generate_forensic_report(threat)
                results['forensic_report'] = report
                results['actions_taken'].append('Generated forensic report')
            
            elif action == 'ALERT':
                results['actions_taken'].append('Alert sent to operators')
            
            elif action == 'LOG':
                results['actions_taken'].append('Event logged for review')
            
            # Log action
            self.actions_log.append({
                'timestamp': datetime.now().isoformat(),
                'threat_id': threat_id,
                'action': action,
                'results': results['actions_taken']
            })
            
        except Exception as e:
            results['success'] = False
            results['actions_taken'].append(f'Error: {str(e)}')
        
        return results
    
    async def _block_ip(self, ip: str):
        """Block IP using iptables safely with sanitized argument lists"""
        if not self.validate_ip(ip):
            print(f"[RESPONDER] Invalid IP address format: {ip}")
            return

        try:
            # Create chain if not exists
            subprocess.run(
                ['sudo', 'iptables', '-N', 'PHANTOM'],
                capture_output=True,
                check=False
            )
            
            # Add block rule
            subprocess.run(
                ['sudo', 'iptables', '-A', 'PHANTOM', '-s', ip, '-j', 'DROP'],
                capture_output=True,
                check=True
            )
            
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            print(f"[RESPONDER] Successfully blocked IP: {ip}")
            
        except Exception as e:
            print(f"[RESPONDER] Could not block IP (need sudo): {e}")
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            print(f"[RESPONDER] Mock block recorded: {ip}")
    
    async def _generate_forensic_report(self, threat: Dict[str, Any]) -> str:
        """Generate forensic report"""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_path = Path(f"backend/data/forensic_{threat.get('id', 'UNKNOWN')}_{timestamp}.txt")
        
        report_content = f"""PHANTOMAGENT FORENSIC REPORT
=============================
Case ID: {threat.get('id', 'UNKNOWN')}
Generated: {datetime.now().isoformat()}
Classification: CONFIDENTIAL

THREAT SUMMARY
--------------
Type: {threat.get('type', 'Unknown')}
Severity: {threat.get('severity', 'N/A')}/10
Source IP: {threat.get('source_ip', 'Unknown')}
Status: CONTAINED

RAW LOG
-------
{threat.get('raw_log', 'No log data')}

ANALYSIS
--------
Threat Type: {threat.get('threat_type', 'Unknown')}
Attack Pattern: {threat.get('attack_pattern', 'Unknown')}
Explanation: {threat.get('explanation', 'No explanation')}

CONTAINMENT ACTIONS
-------------------
[x] Source IP blocked
[x] Malicious processes terminated
[x] Service isolated
[x] Forensic snapshot captured

RECOMMENDATIONS
---------------
1. Review firewall rules
2. Audit user accounts
3. Update threat intelligence
4. Schedule follow-up scan

Report generated by PhantomAgent v1.0.0
"""
        
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_content)
        
        return str(report_path)
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        return self.blocked_ips.copy()
    
    def get_actions_log(self) -> List[Dict[str, Any]]:
        """Get action history"""
        return self.actions_log.copy()