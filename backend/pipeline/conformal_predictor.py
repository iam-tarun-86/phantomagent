"""Conformal Predictor for False Positive Rate (FPR) Statistical Bounding

AI/ML Explanation:
Standard neural nets produce uncalibrated probability scores (e.g. 0.65). Conformal
prediction compares a live GNN score against an empirical calibration set of benign
scores to compute a valid p-value:

    p_value = (Count(calibration_score >= live_score) + 1) / (N + 1)

If p_value < alpha (0.05), the observed score is unlikely to have come from benign
traffic, bounding the false positive rate at <= 5%.

IMPORTANT — what this signal is NOT
-----------------------------------
The p-value is a monotonically decreasing function of the GNN score: a higher score
always yields a p-value at least as small. It therefore carries NO information that the
GNN score does not already carry, and cannot serve as independent corroboration of it.
It is a *calibration* of signal 1, not a second opinion.

ConsensusGate accounts for this by counting the GNN score and this p-value as a single
evidence source. See backend/pipeline/consensus_gate.py.

The calibration set is generated at training time (backend/scripts/train_gnn.py) from
benign samples scored by the trained model, and written to
backend/models/calibration_scores.json. Without that file the predictor degrades to a
small hardcoded set and says so.
"""

import json
import os
from typing import Any, Dict, List

from backend.config import BASE_DIR

CALIBRATION_PATH = BASE_DIR / "models" / "calibration_scores.json"

# Fallback only. Too small for a meaningful p-value: with n=21 the smallest achievable
# p-value is 1/22 = 0.0455, so the signal degenerates into a fixed threshold at ~0.35.
FALLBACK_CALIBRATION: List[float] = [
    0.0001, 0.0004, 0.0006, 0.0012, 0.0025, 0.0040, 0.0080,
    0.0120, 0.0180, 0.0250, 0.0350, 0.0450, 0.0600, 0.0800,
    0.1000, 0.1200, 0.1500, 0.1800, 0.2200, 0.2800, 0.3500
]


class ConformalPredictor:
    """Calculates conformal empirical p-values against a benign calibration distribution."""

    def __init__(self, alpha: float = 0.05, calibration_path=None, max_samples: int = 1000):
        self.alpha = alpha
        self.max_samples = max_samples
        self.calibration_path = calibration_path or CALIBRATION_PATH
        self.calibration_scores: List[float] = []
        self.calibration_source = "fallback"

        self._load_calibration()

    def _load_calibration(self):
        """Load benign calibration scores produced during training."""
        try:
            if os.path.exists(self.calibration_path):
                with open(self.calibration_path) as f:
                    data = json.load(f)
                scores = [float(s) for s in data.get("scores", [])]
                if scores:
                    self.calibration_scores = sorted(scores)
                    self.calibration_source = str(self.calibration_path)
                    return
        except Exception as e:
            print(f"[CONFORMAL] Failed to load calibration set: {e}")

        self.calibration_scores = list(FALLBACK_CALIBRATION)
        self.calibration_source = "fallback"
        print(
            "[CONFORMAL] WARNING: using the hardcoded fallback calibration set "
            f"(n={len(self.calibration_scores)}). p-values have almost no resolution. "
            "Run backend/scripts/train_gnn.py to generate a real one."
        )

    @property
    def min_achievable_p_value(self) -> float:
        """1/(n+1). If this is >= alpha, the signal can never fire."""
        return 1.0 / (len(self.calibration_scores) + 1)

    def add_calibration_sample(self, score: float):
        """
        Record a known-benign score into the calibration set.

        Operator dismissals are the natural source: a human saying "not a threat" is a
        free benign label, and folding it in keeps the baseline current as traffic drifts.
        """
        if not 0.0 <= score <= 1.0:
            return
        self.calibration_scores.append(float(score))
        self.calibration_scores.sort()
        while len(self.calibration_scores) > self.max_samples:
            self.calibration_scores.pop(0)

    def predict_p_value(self, gnn_score: float) -> Dict[str, Any]:
        """
        Calculate the empirical p-value for a live score.
        p_value = fraction of benign calibration samples scoring >= the live score.
        """
        n = len(self.calibration_scores)
        if n == 0:
            return {"p_value": 0.0, "is_statistically_significant": True}

        greater_count = sum(1 for s in self.calibration_scores if s >= gnn_score)
        p_value = round((greater_count + 1) / (n + 1), 4)

        return {
            "p_value": p_value,
            "alpha_target": self.alpha,
            "is_statistically_significant": p_value < self.alpha,
            "confidence_guarantee": f"{round((1 - self.alpha) * 100, 1)}%",
            "calibration_size": n,
            "calibration_source": self.calibration_source,
        }
