"""Conformal predictor calibration.

The calibration set must come from real benign scores produced by the trained model.
The previous hardcoded 21-value list made the smallest achievable p-value 1/22 = 0.0455,
which is barely under alpha=0.05 — so the "95% statistical guarantee" was really a fixed
threshold at score > 0.35 with no resolution behind it.
"""

import json

import pytest

from backend.pipeline.conformal_predictor import CALIBRATION_PATH, ConformalPredictor


@pytest.fixture
def predictor():
    return ConformalPredictor(alpha=0.05)


# ===== Calibration loading =====

@pytest.mark.skipif(not CALIBRATION_PATH.exists(), reason="model not trained yet")
def test_calibration_is_loaded_from_training_artefact(predictor):
    assert predictor.calibration_source != "fallback"
    assert len(predictor.calibration_scores) >= 100


@pytest.mark.skipif(not CALIBRATION_PATH.exists(), reason="model not trained yet")
def test_calibration_has_resolution_for_alpha(predictor):
    """With n too small, p < alpha is unreachable and the signal can never fire."""
    assert predictor.min_achievable_p_value < predictor.alpha / 2


def test_missing_calibration_file_falls_back_loudly(tmp_path, capsys):
    p = ConformalPredictor(calibration_path=tmp_path / "absent.json")
    assert p.calibration_source == "fallback"
    assert "WARNING" in capsys.readouterr().out


def test_corrupt_calibration_file_falls_back(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert ConformalPredictor(calibration_path=bad).calibration_source == "fallback"


def test_custom_calibration_file_is_used(tmp_path):
    path = tmp_path / "cal.json"
    path.write_text(json.dumps({"scores": [0.01 * i for i in range(200)]}))

    p = ConformalPredictor(calibration_path=path)
    assert len(p.calibration_scores) == 200
    assert p.calibration_source == str(path)


# ===== p-value semantics =====

def test_p_value_is_monotonically_decreasing(predictor):
    previous = 1.0
    for score in [0.0, 0.05, 0.2, 0.4, 0.6, 0.8, 1.0]:
        p = predictor.predict_p_value(score)["p_value"]
        assert p <= previous
        previous = p


def test_p_value_stays_in_unit_interval(predictor):
    for score in [0.0, 0.5, 1.0]:
        assert 0.0 <= predictor.predict_p_value(score)["p_value"] <= 1.0


def test_result_reports_its_calibration_provenance(predictor):
    result = predictor.predict_p_value(0.5)
    assert "calibration_size" in result
    assert "calibration_source" in result


# ===== Operator feedback loop =====

def test_dismissed_scores_join_the_calibration_set(predictor):
    before = len(predictor.calibration_scores)
    predictor.add_calibration_sample(0.42)
    assert len(predictor.calibration_scores) == before + 1
    assert 0.42 in predictor.calibration_scores


@pytest.mark.parametrize("bad", [-0.1, 1.5, 42])
def test_out_of_range_samples_are_ignored(predictor, bad):
    before = len(predictor.calibration_scores)
    predictor.add_calibration_sample(bad)
    assert len(predictor.calibration_scores) == before


def test_calibration_set_is_bounded(tmp_path):
    path = tmp_path / "cal.json"
    path.write_text(json.dumps({"scores": [0.001]}))

    p = ConformalPredictor(calibration_path=path, max_samples=50)
    for i in range(200):
        p.add_calibration_sample(i / 200)

    assert len(p.calibration_scores) == 50


def test_adding_benign_samples_raises_the_bar(tmp_path):
    """Folding in benign observations should make the signal harder to trip, not easier."""
    path = tmp_path / "cal.json"
    path.write_text(json.dumps({"scores": [0.001] * 100}))
    p = ConformalPredictor(calibration_path=path)

    before = p.predict_p_value(0.5)["p_value"]
    for _ in range(100):
        p.add_calibration_sample(0.6)
    after = p.predict_p_value(0.5)["p_value"]

    assert after > before
