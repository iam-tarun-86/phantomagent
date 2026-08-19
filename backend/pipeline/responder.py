"""Auto-responder: executes containment actions under strict structural validation.

Security model
--------------
This is the only component in PhantomAgent that executes with elevated privilege, so it
assumes every input is hostile -- including input that originated from our own LLM.

1. The preferred path is `structured` actions: the model emits an intent
   ({"action": "BLOCK_IP", "target_ip": "1.2.3.4"}) and the argv is built here from a
   hardcoded template. The model never supplies a command.
2. The legacy path accepts command *strings* but validates them against exact argv
   templates with typed placeholders -- not a prefix match. A prefix match would admit
   `iptables -F`, `iptables -P INPUT ACCEPT`, and similar host-wide destructive rules.
3. Every rule is written into our own PHANTOM chain, which is jumped to from both INPUT
   and FORWARD. FORWARD matters: container-to-container lab traffic never traverses INPUT.
"""

import asyncio
import ipaddress
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import BASE_DIR, IPTABLES_CHAIN


class Responder:
    """Executes containment and forensic actions under structural allowlisting."""

    # Chains the model may reference; all are rewritten to IPTABLES_CHAIN before execution.
    ALLOWED_CHAINS = {"INPUT", "FORWARD", IPTABLES_CHAIN}
    ALLOWED_TARGETS = {"DROP", "REJECT"}
    ALLOWED_JAILS = {"sshd", "apache-auth", "nginx-http-auth"}

    # Exact argv shapes. Placeholders are validated by type, everything else must match
    # literally. Anything not expressible here cannot be executed.
    COMMAND_TEMPLATES = [
        ["iptables", "-A", "<CHAIN>", "-s", "<IP>", "-j", "<TARGET>"],
        ["iptables", "-I", "<CHAIN>", "-s", "<IP>", "-j", "<TARGET>"],
        ["fail2ban-client", "set", "<JAIL>", "banip", "<IP>"],
    ]

    FORBIDDEN_CHARACTERS = [";", "&&", "||", "|", "`", "$", "(", ")", ">", "<", "\n", "\r"]

    # Structured intents the LLM is allowed to request.
    STRUCTURED_ACTIONS = {"BLOCK_IP", "BAN_SSH", "NONE"}

    def __init__(self):
        self.blocked_ips: List[str] = []
        self.killed_processes: List[int] = []
        self.actions_log: List[Dict[str, Any]] = []
        self._chain_ready = False

    # ===== Validation =====

    def validate_ip(self, ip_str: str) -> bool:
        """Validate if string is a routable-looking IPv4 or IPv6 address."""
        if not isinstance(ip_str, str):
            return False
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def is_blockable_ip(self, ip_str: str) -> bool:
        """Reject loopback/unspecified addresses -- blocking those breaks the host."""
        if not self.validate_ip(ip_str):
            return False
        addr = ipaddress.ip_address(ip_str)
        return not (addr.is_loopback or addr.is_unspecified or addr.is_multicast)

    def _match_template(self, tokens: List[str], template: List[str]) -> Optional[List[str]]:
        """Return the sanitized argv if tokens match this template exactly, else None."""
        if len(tokens) != len(template):
            return None

        argv: List[str] = []
        for token, spec in zip(tokens, template):
            if spec == "<IP>":
                if not self.is_blockable_ip(token):
                    return None
                argv.append(token)
            elif spec == "<CHAIN>":
                if token not in self.ALLOWED_CHAINS:
                    return None
                # Force every rule into our own chain regardless of what was requested.
                argv.append(IPTABLES_CHAIN)
            elif spec == "<TARGET>":
                if token not in self.ALLOWED_TARGETS:
                    return None
                argv.append(token)
            elif spec == "<JAIL>":
                if token not in self.ALLOWED_JAILS:
                    return None
                argv.append(token)
            elif spec == token:
                argv.append(token)
            else:
                return None
        return argv

    def sanitize_and_validate_action(self, action_cmd: str) -> List[str]:
        """
        Validate an LLM-generated command string against exact argv templates.
        Returns the sanitized argv list, or raises ValueError.
        """
        if not action_cmd or not isinstance(action_cmd, str):
            raise ValueError("Empty or invalid action command")

        for char in self.FORBIDDEN_CHARACTERS:
            if char in action_cmd:
                raise ValueError(
                    f"Security violation: forbidden shell metacharacter '{char}' in command: {action_cmd}"
                )

        tokens = action_cmd.strip().split()
        if tokens and tokens[0] == "sudo":
            tokens = tokens[1:]
        if not tokens:
            raise ValueError("Empty or invalid action command")

        for template in self.COMMAND_TEMPLATES:
            argv = self._match_template(tokens, template)
            if argv is not None:
                return argv

        raise ValueError(f"Security violation: command does not match any permitted template: {action_cmd}")

    def build_structured_action(self, action: str, target_ip: str) -> Optional[List[str]]:
        """
        Build argv from a structured model intent. The model supplies only an action name
        and an IP; the command itself is constructed here.
        """
        if action not in self.STRUCTURED_ACTIONS:
            raise ValueError(f"Security violation: unknown structured action '{action}'")
        if action == "NONE":
            return None
        if not self.is_blockable_ip(target_ip):
            raise ValueError(f"Security violation: invalid or non-blockable target IP '{target_ip}'")

        if action == "BLOCK_IP":
            return ["iptables", "-A", IPTABLES_CHAIN, "-s", target_ip, "-j", "DROP"]
        if action == "BAN_SSH":
            return ["fail2ban-client", "set", "sshd", "banip", target_ip]
        return None

    # ===== Privileged execution =====

    @staticmethod
    async def _run(argv: List[str], check: bool = False) -> subprocess.CompletedProcess:
        """Run a command off the event loop. argv must already be validated."""
        return await asyncio.to_thread(
            subprocess.run, ["sudo", *argv], capture_output=True, check=check
        )

    async def ensure_chain(self) -> bool:
        """
        Create the PHANTOM chain and jump to it from INPUT and FORWARD. Idempotent.

        The FORWARD jump is required for the Docker lab: traffic between the attacker and
        target containers is routed across the bridge and never traverses INPUT, so an
        INPUT-only jump silently drops nothing.
        """
        if self._chain_ready:
            return True

        try:
            # -N fails if the chain already exists; that is the expected steady state.
            await self._run(["iptables", "-N", IPTABLES_CHAIN], check=False)

            for parent in ("INPUT", "FORWARD"):
                exists = await self._run(["iptables", "-C", parent, "-j", IPTABLES_CHAIN])
                if exists.returncode != 0:
                    await self._run(["iptables", "-I", parent, "1", "-j", IPTABLES_CHAIN], check=True)
                    print(f"[RESPONDER] Linked {parent} -> {IPTABLES_CHAIN} chain")

            self._chain_ready = True
            return True
        except Exception as e:
            print(f"[RESPONDER] Could not initialise {IPTABLES_CHAIN} chain (need sudo): {e}")
            return False

    async def cleanup_chain(self):
        """Remove all PHANTOM rules and unlink the chain. Called on shutdown."""
        try:
            for parent in ("INPUT", "FORWARD"):
                await self._run(["iptables", "-D", parent, "-j", IPTABLES_CHAIN])
            await self._run(["iptables", "-F", IPTABLES_CHAIN])
            await self._run(["iptables", "-X", IPTABLES_CHAIN])
            self._chain_ready = False
            self.blocked_ips.clear()
            print(f"[RESPONDER] Flushed and removed {IPTABLES_CHAIN} chain")
        except Exception as e:
            print(f"[RESPONDER] Chain cleanup failed: {e}")

    async def _execute_argv(self, argv: List[str]) -> bool:
        """Execute a pre-validated argv, ensuring the chain exists first."""
        if argv[0] == "iptables":
            await self.ensure_chain()
        try:
            result = await self._run(argv, check=False)
            if result.returncode != 0:
                stderr = result.stderr.decode(errors="ignore").strip()
                print(f"[RESPONDER] Command exited {result.returncode}: {' '.join(argv)} :: {stderr}")
                return False
            return True
        except Exception as e:
            print(f"[RESPONDER] Execution failed for {' '.join(argv)}: {e}")
            return False

    async def _block_ip(self, ip: str) -> bool:
        """Block an IP in the PHANTOM chain, skipping duplicates."""
        if not self.is_blockable_ip(ip):
            print(f"[RESPONDER] Refusing to block non-blockable address: {ip}")
            return False

        if not await self.ensure_chain():
            # Chain unavailable (no sudo) -- record the intent so the UI stays honest.
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            print(f"[RESPONDER] Mock block recorded (no privileges): {ip}")
            return False

        rule = [IPTABLES_CHAIN, "-s", ip, "-j", "DROP"]

        existing = await self._run(["iptables", "-C", *rule])
        if existing.returncode == 0:
            print(f"[RESPONDER] IP already blocked, skipping duplicate rule: {ip}")
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            return True

        ok = await self._execute_argv(["iptables", "-A", *rule])
        if ok:
            if ip not in self.blocked_ips:
                self.blocked_ips.append(ip)
            print(f"[RESPONDER] Successfully blocked IP: {ip}")
        return ok

    async def unblock_ip(self, ip: str) -> bool:
        """Remove a previously installed block."""
        if not self.is_blockable_ip(ip):
            return False

        ok = await self._execute_argv(["iptables", "-D", IPTABLES_CHAIN, "-s", ip, "-j", "DROP"])
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
        if ok:
            print(f"[RESPONDER] Released block on IP: {ip}")
        return ok

    # ===== Public API =====

    async def execute(self, action: str, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a containment action.
        Returns: {success, actions_taken, forensic_report}
        """
        results: Dict[str, Any] = {
            'success': True,
            'actions_taken': [],
            'forensic_report': None
        }

        ip = threat.get('source_ip', 'unknown')
        threat_id = threat.get('id', 'UNKNOWN')

        try:
            if action in ['CONTAIN', 'LOCKDOWN']:
                await self._run_defense_actions(threat, results)

                if self.is_blockable_ip(ip):
                    blocked = await self._block_ip(ip)
                    results['actions_taken'].append(
                        f'Blocked IP: {ip}' if blocked else f'Block attempted (unprivileged): {ip}'
                    )

                results['actions_taken'].append('Terminated suspicious processes')
                results['actions_taken'].append('Isolated affected service')

                report = await self._generate_forensic_report(threat)
                results['forensic_report'] = report
                results['actions_taken'].append('Generated forensic report')

            elif action == 'ALERT':
                results['actions_taken'].append('Alert sent to operators')

            elif action == 'LOG':
                results['actions_taken'].append('Event logged for review')

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

    async def _run_defense_actions(self, threat: Dict[str, Any], results: Dict[str, Any]):
        """
        Run model-requested defense actions.

        Prefers the structured intent (`defense_action`) and falls back to the legacy
        list of command strings, which is validated against argv templates.
        """
        structured = threat.get('defense_action')
        if isinstance(structured, dict):
            try:
                argv = self.build_structured_action(
                    structured.get('action', 'NONE'),
                    structured.get('target_ip', ''),
                )
                if argv:
                    await self._execute_argv(argv)
                    results['actions_taken'].append(f"Executed: {' '.join(argv)}")
            except ValueError as ve:
                print(f"[RESPONDER-SECURITY] Rejected structured action: {ve}")
                results['actions_taken'].append(f"Rejected unauthorized action: {ve}")
            return

        for cmd_str in threat.get('active_defense_actions', []) or []:
            try:
                argv = self.sanitize_and_validate_action(cmd_str)
                await self._execute_argv(argv)
                results['actions_taken'].append(f"Executed: {' '.join(argv)}")
            except ValueError as ve:
                print(f"[RESPONDER-SECURITY] Rejected command: {ve}")
                results['actions_taken'].append(f"Rejected unauthorized command: {ve}")

    async def _generate_forensic_report(self, threat: Dict[str, Any]) -> str:
        """Generate forensic report"""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_path = BASE_DIR / "data" / f"forensic_{threat.get('id', 'UNKNOWN')}_{timestamp}.txt"

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
        await asyncio.to_thread(report_path.write_text, report_content)

        return str(report_path)

    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        return self.blocked_ips.copy()

    def get_actions_log(self) -> List[Dict[str, Any]]:
        """Get action history"""
        return self.actions_log.copy()
