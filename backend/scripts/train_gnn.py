"""Training script for GraphSAGE GNN model on CICIDS2017 with held-out zero-day category.

Two artefacts are produced, and both matter at inference time:

  models/gnn_cicids2017.pt      weights + the normalization statistics used to fit them
  models/calibration_scores.json  benign score distribution for the conformal predictor
  models/benign_baseline.json     benign per-metric statistics for behavioural cold start

Persisting the statistics is not optional. An earlier version assigned them to
GNNPredictor.MEANS/STDS at training time — an in-memory class-attribute write that was
never saved — so inference silently fell back to hardcoded constants that did not match
the training set.
"""

import json
import os

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

from backend.pipeline.gnn_model import CHECKPOINT_VERSION, GNNPredictor, GraphSAGEAnomalyModel

DATASET_PATH = "backend/data/cicids2017_subset.csv"
MODEL_OUTPUT_PATH = "backend/models/gnn_cicids2017.pt"
CALIBRATION_OUTPUT_PATH = "backend/models/calibration_scores.json"
BASELINE_OUTPUT_PATH = "backend/models/benign_baseline.json"

# Conformal prediction needs enough benign samples for the p-value to have resolution:
# the smallest achievable p-value is 1/(n+1), so n must exceed 1/alpha - 1 (19 at
# alpha=0.05) before the signal can ever fire, and far more before it means anything.
CALIBRATION_SAMPLE_COUNT = 500

# BehavioralFingerprinter metric -> dataset column supplying its benign distribution.
# 'packet_count' has no equivalent in the CSV (it is a live 5s-window count), so that
# metric abstains at cold start instead of being fabricated.
BEHAVIOURAL_METRIC_COLUMNS = {
    "unique_ports": "unique_dst_ports",
    "conn_freq": "connection_frequency",
    "syn_count": "syn_count",
}


def train():
    # Deterministic weight init: without this every retrain produces a different score
    # distribution, so the calibration set and any tuned threshold silently drift.
    torch.manual_seed(42)
    np.random.seed(42)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}. Run generate_dataset.py first.")

    df = pd.read_csv(DATASET_PATH)
    print(f"[TRAIN] Loaded {len(df)} records from {DATASET_PATH}")

    # Step 1: Held-out attack category split (Methodology: Exclude 'Infiltration' for zero-day test)
    HELD_OUT_CATEGORY = 'Infiltration'

    train_val_df = df[df['label'] != HELD_OUT_CATEGORY].copy()
    zero_day_df = df[df['label'] == HELD_OUT_CATEGORY].copy()

    print(f"[METHODOLOGY] Held-out zero-day attack category: '{HELD_OUT_CATEGORY}' ({len(zero_day_df)} samples excluded from training)")

    feature_cols = GNNPredictor.FEATURE_KEYS

    # Binary label: BENIGN = 0.0, ATTACK = 1.0
    train_val_df['target'] = (train_val_df['label'] != 'BENIGN').astype(np.float32)
    zero_day_df['target'] = 1.0

    X = train_val_df[feature_cols].values.astype(np.float32)
    y = train_val_df['target'].values.astype(np.float32)

    # Normalization statistics — computed here, saved with the weights below, and used
    # verbatim at inference. Never recompute or hardcode these anywhere else.
    means = np.mean(X, axis=0)
    stds = np.std(X, axis=0)

    X_norm = (X - means) / (stds + 1e-6)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(X_norm, y, test_size=0.2, random_state=42, stratify=y)

    X_train_t = torch.tensor(X_train, dtype=torch.float32)
    y_train_t = torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
    X_test_t = torch.tensor(X_test, dtype=torch.float32)
    y_test_t = torch.tensor(y_test, dtype=torch.float32).unsqueeze(1)

    model = GraphSAGEAnomalyModel(in_features=len(feature_cols))
    optimizer = torch.optim.Adam(model.parameters(), lr=0.005)
    criterion = nn.BCELoss()

    print("[TRAIN] Training GraphSAGE model over 50 epochs...")
    model.train()
    for epoch in range(50):
        optimizer.zero_grad()
        preds = model(X_train_t)
        loss = criterion(preds, y_train_t)
        loss.backward()
        optimizer.step()

        if (epoch + 1) % 10 == 0:
            print(f"  Epoch [{epoch+1}/50] - Loss: {loss.item():.4f}")

    # Evaluation on Test set
    model.eval()
    with torch.no_grad():
        test_preds = model(X_test_t).numpy().squeeze()
        test_pred_labels = (test_preds > 0.5).astype(np.float32)

        acc = accuracy_score(y_test, test_pred_labels)
        f1 = f1_score(y_test, test_pred_labels)
        auc = roc_auc_score(y_test, test_preds)

        print("\n[EVALUATION - STANDARD TEST SET]")
        print(f"  Accuracy: {acc:.4f}")
        print(f"  F1-Score: {f1:.4f}")
        print(f"  ROC-AUC : {auc:.4f}")

        # Evaluation on Zero-Day Held Out Category
        X_zero_day = zero_day_df[feature_cols].values.astype(np.float32)
        X_zero_day_norm = (X_zero_day - means) / (stds + 1e-6)
        X_zero_day_t = torch.tensor(X_zero_day_norm, dtype=torch.float32)

        zero_day_preds = model(X_zero_day_t).numpy().squeeze()
        avg_zero_day_anomaly = np.mean(zero_day_preds)
        zero_day_detected = np.mean(zero_day_preds > 0.5)

        print(f"\n[EVALUATION - HELD-OUT ZERO-DAY ('{HELD_OUT_CATEGORY}')]")
        print(f"  Average Anomaly Score: {avg_zero_day_anomaly:.4f}")
        print(f"  Zero-Day Detection Rate (Score > 0.5): {zero_day_detected * 100:.2f}%")

        # Conformal calibration set — benign scores only, from data the model was fit on.
        benign_df = train_val_df[train_val_df['label'] == 'BENIGN']
        X_benign = benign_df[feature_cols].values.astype(np.float32)
        X_benign_norm = (X_benign - means) / (stds + 1e-6)
        benign_scores = model(torch.tensor(X_benign_norm, dtype=torch.float32)).numpy().squeeze()

        if len(benign_scores) > CALIBRATION_SAMPLE_COUNT:
            rng = np.random.default_rng(42)
            benign_scores = rng.choice(benign_scores, CALIBRATION_SAMPLE_COUNT, replace=False)

        calibration = sorted(round(float(s), 6) for s in benign_scores)

        print(f"\n[CALIBRATION - CONFORMAL PREDICTOR]")
        print(f"  Benign samples scored : {len(calibration)}")
        print(f"  Score range           : {calibration[0]:.6f} — {calibration[-1]:.6f}")
        print(f"  95th percentile       : {np.percentile(calibration, 95):.6f}")
        print(f"  Min achievable p-value: {1 / (len(calibration) + 1):.5f}")

        # Benign population prior for BehavioralFingerprinter cold start. Without this,
        # an unseen IP has no baseline and the behavioural signal degenerates into
        # "is this host new?", which corroborates nothing.
        benign_baseline = {}
        for metric, column in BEHAVIOURAL_METRIC_COLUMNS.items():
            if column not in benign_df.columns:
                continue
            col = benign_df[column].values.astype(np.float32)
            benign_baseline[metric] = {
                "mean": float(np.mean(col)),
                "std": float(np.std(col)),
                "p99": float(np.percentile(col, 99)),
                "source_column": column,
            }

        print(f"\n[BASELINE - BEHAVIOURAL COLD START]")
        for metric, stats in benign_baseline.items():
            print(f"  {metric:<16} mu={stats['mean']:>10.2f}  sigma={stats['std']:>10.2f}")
        missing = set(BEHAVIOURAL_METRIC_COLUMNS) - set(benign_baseline)
        if missing:
            print(f"  NOTE: no column in the dataset for {sorted(missing)} — those metrics")
            print(f"        abstain at cold start rather than guessing.")

    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)

    torch.save(
        {
            "version": CHECKPOINT_VERSION,
            "state_dict": model.state_dict(),
            # Plain lists, not numpy arrays: torch.load(weights_only=True) refuses to
            # deserialize numpy globals, and a checkpoint that cannot be loaded safely
            # falls back to untrained weights.
            "means": [float(m) for m in means],
            "stds": [float(s) for s in stds],
            "feature_keys": list(feature_cols),
        },
        MODEL_OUTPUT_PATH,
    )
    print(f"\n[SAVED] Model weights + normalization stats -> '{MODEL_OUTPUT_PATH}'")

    with open(CALIBRATION_OUTPUT_PATH, "w") as f:
        json.dump({"alpha": 0.05, "scores": calibration}, f)
    print(f"[SAVED] Conformal calibration scores -> '{CALIBRATION_OUTPUT_PATH}'")

    with open(BASELINE_OUTPUT_PATH, "w") as f:
        json.dump({"source": DATASET_PATH, "metrics": benign_baseline}, f, indent=2)
    print(f"[SAVED] Benign behavioural baseline -> '{BASELINE_OUTPUT_PATH}'")


if __name__ == "__main__":
    train()
