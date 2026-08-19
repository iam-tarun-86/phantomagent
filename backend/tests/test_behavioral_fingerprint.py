"""Behavioural fingerprint cold-start handling.

The failure this guards against: an earlier version used the raw metric value as the
Z-score for any IP without history, so every unseen host sending more than 3 packets was
"anomalous". As a corroborating signal that is worthless — it is YES for effectively all
external traffic, so it rubber-stamps whatever the GNN already decided.
"""

import json

import pytest

from backend.pipeline.behavioral_fingerprint import BASELINE_PATH, BehavioralFingerprinter


BENIGN = {"packet_count": 4, "unique_dst_ports": 1, "connection_frequency": 0.8, "syn_count": 2}
SCAN = {"packet_count": 220, "unique_dst_ports": 45, "connection_frequency": 44.0, "syn_count": 200}


@pytest.fixture
def prior_path(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"metrics": {
        "unique_ports": {"mean": 1.0, "std": 0.0},
        "conn_freq": {"mean": 1.04, "std": 0.55},
        "syn_count": {"mean": 2.0, "std": 0.82},
    }}))
    return path


@pytest.fixture
def fp(prior_path):
    return BehavioralFingerprinter(baseline_path=prior_path)


# ===== Cold start =====

def test_new_ip_sending_benign_traffic_is_not_anomalous(fp):
    """The core regression: an unseen host doing normal things must not vote YES."""
    result = fp.update_and_score("203.0.113.10", BENIGN)
    assert result["is_anomaly"] is False
    assert result["baseline"] == "population-prior"


def test_new_ip_running_a_scan_is_anomalous(fp):
    result = fp.update_and_score("203.0.113.11", SCAN)
    assert result["is_anomaly"] is True
    assert result["max_z_score"] > 3.0


def test_zero_variance_metric_does_not_explode(fp):
    """Benign unique_dst_ports is always exactly 1 (sigma=0); 2 ports is not a 6-sigma event."""
    result = fp.update_and_score("203.0.113.12", {**BENIGN, "unique_dst_ports": 2})
    assert result["z_scores"]["z_unique_ports"] < 3.0


def test_signal_abstains_without_a_prior(tmp_path, capsys):
    """No baseline available: vote NO rather than assert an anomaly we cannot evidence."""
    fp = BehavioralFingerprinter(baseline_path=tmp_path / "absent.json")
    assert "WARNING" in capsys.readouterr().out

    result = fp.update_and_score("203.0.113.13", SCAN)
    assert result["is_anomaly"] is False
    assert result["baseline"] == "abstained"
    assert result["max_z_score"] == 0.0


@pytest.mark.skipif(not BASELINE_PATH.exists(), reason="model not trained yet")
def test_shipped_baseline_loads():
    fp = BehavioralFingerprinter()
    assert fp.prior_source != "none"
    assert fp.update_and_score("203.0.113.14", BENIGN)["is_anomaly"] is False


# ===== Self-baseline, once history exists =====

def test_established_host_keeps_its_own_baseline(fp):
    """A backup server that always sends a lot must not be flagged for doing so."""
    ip = "10.0.0.50"
    heavy = {"packet_count": 200, "unique_dst_ports": 1, "connection_frequency": 40.0, "syn_count": 100}

    for _ in range(6):
        fp.update_and_score(ip, heavy)

    result = fp.update_and_score(ip, heavy)
    assert result["baseline"] == "self"
    assert result["is_anomaly"] is False


def test_established_host_spiking_is_flagged(fp):
    ip = "10.0.0.51"
    for _ in range(6):
        fp.update_and_score(ip, {"packet_count": 5, "unique_dst_ports": 1,
                                 "connection_frequency": 1.0, "syn_count": 2})

    result = fp.update_and_score(ip, SCAN)
    assert result["baseline"] == "self"
    assert result["is_anomaly"] is True


def test_distinct_ips_have_independent_baselines(fp):
    for _ in range(6):
        fp.update_and_score("10.0.0.60", SCAN)

    # A different IP must not inherit the first one's tolerance.
    assert fp.update_and_score("10.0.0.61", SCAN)["is_anomaly"] is True
