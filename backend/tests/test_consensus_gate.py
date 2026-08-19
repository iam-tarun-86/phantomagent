"""5-Signal Consensus Gate voting behaviour.

These pin the gate's contract: benign traffic must not reach consensus, and a genuine
multi-signal attack must. Fresh gate instances per test — the behavioural fingerprinter
and kill-chain correlator carry per-IP state across calls.
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
    return ConsensusGate(required_consensus_votes=3)


def test_benign_traffic_does_not_reach_consensus(gate):
    event = {
        "source_ip": "10.0.0.20",
        "type": "UNKNOWN",
        "raw_log": "GET /index.html HTTP/1.1 200 OK",
        "features": BENIGN_FEATURES,
    }
    result = gate.evaluate(event, gnn_score=0.05)

    assert result["has_consensus"] is False
    assert result["total_votes"] < 3


def test_port_scan_reaches_consensus(gate):
    event = {
        "source_ip": "172.28.0.10",
        "type": "PORT_SCAN",
        "raw_log": "Real packet capture threat: PORT_SCAN from 172.28.0.10",
        "features": PORT_SCAN_FEATURES,
    }
    result = gate.evaluate(event, gnn_score=0.91)

    assert result["has_consensus"] is True
    assert result["total_votes"] >= 3


def test_vote_breakdown_exposes_all_five_signals(gate):
    event = {"source_ip": "10.0.0.30", "type": "UNKNOWN", "raw_log": "x", "features": BENIGN_FEATURES}
    votes = gate.evaluate(event, gnn_score=0.5)["vote_breakdown"]

    assert set(votes) == {
        "gnn_structural",
        "conformal_pvalue",
        "behavioral_zscore",
        "payload_entropy",
        "killchain_campaign",
    }
    assert all(isinstance(v, bool) for v in votes.values())


def test_gnn_signal_threshold_at_040(gate):
    event = {"source_ip": "10.0.0.40", "type": "UNKNOWN", "raw_log": "x", "features": BENIGN_FEATURES}

    assert gate.evaluate(event, gnn_score=0.39)["vote_breakdown"]["gnn_structural"] is False
    assert gate.evaluate(event, gnn_score=0.40)["vote_breakdown"]["gnn_structural"] is True


def test_killchain_flags_multi_stage_campaign(gate):
    """One IP progressing recon -> credential access is a campaign; a single stage is not."""
    ip = "172.28.0.99"
    features = dict(BENIGN_FEATURES)

    first = gate.evaluate({"source_ip": ip, "type": "PORT_SCAN", "raw_log": "x", "features": features}, 0.5)
    assert first["killchain"]["is_campaign"] is False

    second = gate.evaluate({"source_ip": ip, "type": "BRUTE_FORCE", "raw_log": "x", "features": features}, 0.5)
    assert second["killchain"]["is_campaign"] is True
    assert second["vote_breakdown"]["killchain_campaign"] is True


def test_conformal_vote_is_coupled_to_gnn_score(gate):
    """KNOWN LIMITATION (see Phase 2 remediation).

    The conformal calibration set is a fixed 21-value list capped at 0.35, so the
    p-value signal fires whenever gnn_score > 0.35 -- i.e. it is not independent of
    signal 1. This test documents the coupling so Phase 2 has a baseline to change.
    """
    event = {"source_ip": "10.0.0.50", "type": "UNKNOWN", "raw_log": "x", "features": BENIGN_FEATURES}

    low = gate.evaluate(event, gnn_score=0.30)["vote_breakdown"]
    high = gate.evaluate(event, gnn_score=0.80)["vote_breakdown"]

    assert low["conformal_pvalue"] is False
    assert high["conformal_pvalue"] is True
    # Both GNN-derived signals move together on the same input.
    assert high["gnn_structural"] is True
