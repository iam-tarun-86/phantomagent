"""GNN checkpoint contract — normalization statistics must travel with the weights.

Background: training previously assigned the computed statistics to
GNNPredictor.MEANS/STDS, an in-memory class-attribute write that was never persisted.
Only state_dict() was saved, so inference silently fell back to hardcoded constants that
did not match the training set. Measured effect on the current dataset: at
unique_dst_ports=10 the score moved 0.7457 -> 0.0144, flipping the consensus vote.
"""

import numpy as np
import pytest
import torch

from backend.pipeline.gnn_model import (
    CHECKPOINT_VERSION,
    DEFAULT_MODEL_PATH,
    GNNPredictor,
    GraphSAGEAnomalyModel,
)


@pytest.fixture
def predictor():
    return GNNPredictor()


# ===== The checkpoint carries its statistics =====

@pytest.mark.skipif(not DEFAULT_MODEL_PATH.exists(), reason="model not trained yet")
def test_trained_checkpoint_supplies_normalization_stats(predictor):
    assert predictor.stats_source.startswith("checkpoint"), (
        "predictor fell back to legacy stats — the checkpoint is missing means/stds"
    )


@pytest.mark.skipif(not DEFAULT_MODEL_PATH.exists(), reason="model not trained yet")
def test_loaded_stats_are_not_the_legacy_constants(predictor):
    """Guards against a silent regression back to hardcoded values."""
    assert not np.allclose(predictor.means, GNNPredictor.LEGACY_MEANS)


@pytest.mark.skipif(not DEFAULT_MODEL_PATH.exists(), reason="model not trained yet")
def test_checkpoint_has_expected_shape():
    ckpt = torch.load(DEFAULT_MODEL_PATH, weights_only=True, map_location="cpu")
    assert ckpt["version"] == CHECKPOINT_VERSION
    assert set(ckpt) >= {"state_dict", "means", "stds", "feature_keys"}
    assert list(ckpt["feature_keys"]) == GNNPredictor.FEATURE_KEYS
    assert len(ckpt["means"]) == len(GNNPredictor.FEATURE_KEYS)


# ===== Legacy and corrupt checkpoints degrade loudly =====

def test_legacy_bare_state_dict_warns_and_falls_back(tmp_path, capsys):
    path = tmp_path / "legacy.pt"
    torch.save(GraphSAGEAnomalyModel().state_dict(), path)

    p = GNNPredictor(model_path=str(path))
    output = capsys.readouterr().out

    assert p.stats_source == "legacy-fallback"
    assert "WARNING" in output and "legacy v1 checkpoint" in output
    assert np.allclose(p.means, GNNPredictor.LEGACY_MEANS)


def test_feature_order_mismatch_is_rejected(tmp_path, capsys):
    """A silently reordered feature column would produce garbage scores forever."""
    path = tmp_path / "reordered.pt"
    scrambled = list(reversed(GNNPredictor.FEATURE_KEYS))
    torch.save(
        {
            "version": CHECKPOINT_VERSION,
            "state_dict": GraphSAGEAnomalyModel().state_dict(),
            "means": [0.0] * 7,
            "stds": [1.0] * 7,
            "feature_keys": scrambled,
        },
        path,
    )

    GNNPredictor(model_path=str(path))
    assert "feature order" in capsys.readouterr().out.lower()


def test_missing_model_file_does_not_crash(tmp_path):
    p = GNNPredictor(model_path=str(tmp_path / "nope.pt"))
    assert 0.0 <= p.predict_anomaly_score({"syn_count": 5}) <= 1.0


# ===== Scoring =====

@pytest.mark.skipif(not DEFAULT_MODEL_PATH.exists(), reason="model not trained yet")
def test_benign_traffic_scores_low(predictor):
    score = predictor.predict_anomaly_score({
        "syn_count": 2, "ack_count": 5, "rst_count": 0, "unique_dst_ports": 1,
        "bytes_sent": 1200, "connection_frequency": 0.8, "failed_auth_count": 0,
    })
    assert score < 0.2, f"benign traffic scored {score}"


@pytest.mark.skipif(not DEFAULT_MODEL_PATH.exists(), reason="model not trained yet")
def test_port_scan_scores_high(predictor):
    score = predictor.predict_anomaly_score({
        "syn_count": 60, "ack_count": 2, "rst_count": 5, "unique_dst_ports": 45,
        "bytes_sent": 1500, "connection_frequency": 30.0, "failed_auth_count": 0,
    })
    assert score > 0.5, f"port scan scored {score}"


@pytest.mark.skipif(not DEFAULT_MODEL_PATH.exists(), reason="model not trained yet")
def test_dos_flood_scores_high(predictor):
    score = predictor.predict_anomaly_score({
        "syn_count": 300, "ack_count": 5, "rst_count": 2, "unique_dst_ports": 2,
        "bytes_sent": 25000, "connection_frequency": 120.0, "failed_auth_count": 0,
    })
    assert score > 0.5, f"DoS flood scored {score}"


def test_missing_features_default_to_zero(predictor):
    """Watchers do not always populate every field; scoring must not raise."""
    assert 0.0 <= predictor.predict_anomaly_score({}) <= 1.0
    assert 0.0 <= predictor.predict_anomaly_score({"syn_count": 5}) <= 1.0


def test_score_is_deterministic(predictor):
    """Dropout must be off at inference — the same input cannot score differently."""
    features = {"syn_count": 30, "unique_dst_ports": 12, "connection_frequency": 8.0}
    scores = {predictor.predict_anomaly_score(features) for _ in range(10)}
    assert len(scores) == 1, f"non-deterministic scoring: {scores}"
