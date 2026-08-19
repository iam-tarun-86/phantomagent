"""5-Signal Consensus Gate voting behaviour.

The gate's reason for existing is that no single evidence source may confirm a threat.
Signals 1 (GNN score) and 2 (conformal p-value) are the same evidence source — the
p-value is a monotonic function of the score — so they collapse into one. These tests
pin that property.

Fresh gate instances per test: the behavioural fingerprinter and kill-chain correlator
carry per-IP state across calls.
"""

import pytest

from backend.pipeline.consensus_gate import ConsensusGate


BENIGN_FEATURES = {
    "packet_count": 2,
    "syn_count": 1,
    "ack_count": 1,
    "rst_count": 0,
    "unique_dst_ports": 1,
    "bytes_sent": 240,
    "connection_frequency": 0.4,
    "failed_auth_count": 0,
}

PORT_SCAN_FEATURES = {
    "packet_count": 220,
    "syn_count": 200,
    "ack_count": 2,
    "rst_count": 60,
    "unique_dst_ports": 45,
    "bytes_sent": 13200,
    "connection_frequency": 44.0,
    "failed_auth_count": 0,
}


@pytest.fixture
def gate():
    return ConsensusGate()


def event(ip="10.0.0.20", threat_type="UNKNOWN", features=None, raw_log="GET /index.html HTTP/1.1 200 OK"):
    return {
        "source_ip": ip,
        "type": threat_type,
        "raw_log": raw_log,
        "features": features if features is not None else BENIGN_FEATURES,
    }


# ===== Core behaviour =====

def test_benign_traffic_does_not_reach_consensus(gate):
    result = gate.evaluate(event(), gnn_score=0.05)
    assert result["has_consensus"] is False


def test_port_scan_from_new_ip_reaches_consensus(gate):
    """Structural evidence plus a behavioural outlier is genuine corroboration."""
    result = gate.evaluate(
        event(ip="172.28.0.10", threat_type="PORT_SCAN", features=PORT_SCAN_FEATURES),
        gnn_score=0.91,
    )
    assert result["has_consensus"] is True
    assert result["vote_breakdown"]["behavioral_zscore"] is True


# ===== The property the gate exists to provide =====

def test_gnn_alone_cannot_reach_consensus(gate):
    """
    A saturated GNN score fires both structural signals. Under the old flat 3-of-5 rule
    that was 2 of the 3 required votes; now they count once and consensus is denied.
    """
    result = gate.evaluate(event(ip="10.0.0.77"), gnn_score=0.99)

    assert result["vote_breakdown"]["gnn_structural"] is True
    assert result["vote_breakdown"]["conformal_pvalue"] is True
    assert result["independent_sources"] == []
    assert result["evidence_sources"] == 1
    assert result["has_consensus"] is False


def test_structural_signals_collapse_to_one_evidence_source(gate):
    result = gate.evaluate(event(ip="10.0.0.78"), gnn_score=0.99)
    # Two raw votes...
    assert result["total_votes"] >= 2
    # ...but a single source of evidence.
    assert result["structural_source"] is True
    assert result["evidence_sources"] == 1


def test_one_independent_signal_is_required(gate):
    """Even at the source threshold, consensus needs non-structural corroboration."""
    result = gate.evaluate(event(ip="10.0.0.79"), gnn_score=0.99)
    assert result["has_consensus"] is False

    corroborated = gate.evaluate(
        event(ip="10.0.0.80", features=PORT_SCAN_FEATURES),
        gnn_score=0.99,
    )
    assert corroborated["independent_sources"]
    assert corroborated["has_consensus"] is True


def test_conformal_is_monotonic_in_gnn_score(gate):
    """
    Documents why signals 1 and 2 are one source: the p-value can only fall as the score
    rises, so it never carries information the score does not.
    """
    previous = 1.0
    for score in [0.0, 0.1, 0.3, 0.5, 0.7, 0.9, 1.0]:
        p = gate.evaluate(event(ip="10.0.0.81"), gnn_score=score)["conformal"]["p_value"]
        assert p <= previous, f"p-value rose at score {score}"
        previous = p


# ===== Signal mechanics =====

def test_vote_breakdown_exposes_all_five_signals(gate):
    votes = gate.evaluate(event(ip="10.0.0.30"), gnn_score=0.5)["vote_breakdown"]

    assert set(votes) == {
        "gnn_structural",
        "conformal_pvalue",
        "behavioral_zscore",
        "payload_entropy",
        "killchain_campaign",
    }
    assert all(isinstance(v, bool) for v in votes.values())


def test_gnn_signal_threshold_at_040(gate):
    assert gate.evaluate(event(ip="10.0.0.40"), gnn_score=0.39)["vote_breakdown"]["gnn_structural"] is False
    assert gate.evaluate(event(ip="10.0.0.41"), gnn_score=0.40)["vote_breakdown"]["gnn_structural"] is True


def test_killchain_flags_multi_stage_campaign(gate):
    """One IP progressing recon -> credential access is a campaign; a single stage is not."""
    ip = "172.28.0.99"

    first = gate.evaluate(event(ip=ip, threat_type="PORT_SCAN"), 0.5)
    assert first["killchain"]["is_campaign"] is False

    second = gate.evaluate(event(ip=ip, threat_type="BRUTE_FORCE"), 0.5)
    assert second["killchain"]["is_campaign"] is True
    assert second["vote_breakdown"]["killchain_campaign"] is True


def test_two_independent_signals_reach_consensus_without_the_gnn(gate):
    """A quiet GNN must not veto corroborated evidence from other detectors."""
    ip = "172.28.0.55"
    high_entropy = "".join(chr((i * 7 + 13) % 256) for i in range(400))

    gate.evaluate(event(ip=ip, threat_type="PORT_SCAN", features=PORT_SCAN_FEATURES), 0.0)
    result = gate.evaluate(
        event(ip=ip, threat_type="BRUTE_FORCE", features=PORT_SCAN_FEATURES, raw_log=high_entropy),
        gnn_score=0.0,
    )

    assert result["vote_breakdown"]["gnn_structural"] is False
    assert len(result["independent_sources"]) >= 2
    assert result["has_consensus"] is True
