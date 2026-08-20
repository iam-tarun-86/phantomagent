"""Train the GraphSAGE anomaly scorer on host-communication graphs.

Training operates on graphs, not rows: each sample is one time window containing
several hosts and the edges between them, and the model scores every node using both
its own features and its neighbourhood. Windows are batched block-diagonally so many
graphs pass through in one forward call while remaining structurally independent.

'Lateral' is held out entirely as the zero-day category. Its per-host features are
deliberately unremarkable, so detecting it requires reading the chain topology --
which is the point of using a GNN at all.

Three artefacts are produced, and all three matter at inference time:
  models/gnn_phantom.pt           weights + the normalization statistics used to fit them
  models/calibration_scores.json  benign score distribution for the conformal predictor
  models/benign_baseline.json     benign per-metric statistics for behavioural cold start

Persisting the statistics is not optional. An earlier version assigned them to
GNNPredictor.MEANS/STDS at training time -- an in-memory class-attribute write that was
never saved -- so inference silently fell back to hardcoded constants that did not match
the training set.
"""

import json
import os

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from backend.pipeline.gnn_model import (
    CHECKPOINT_VERSION,
    GNNPredictor,
    GraphSAGEAnomalyModel,
    build_adjacency,
)

GRAPH_DATASET_PATH = "backend/data/synthetic_graphs.jsonl"
FLAT_DATASET_PATH = "backend/data/synthetic_flows.csv"
MODEL_OUTPUT_PATH = "backend/models/gnn_phantom.pt"
CALIBRATION_OUTPUT_PATH = "backend/models/calibration_scores.json"
BASELINE_OUTPUT_PATH = "backend/models/benign_baseline.json"

HELD_OUT_SCENARIO = "Lateral"
EPOCHS = 60
BATCH_WINDOWS = 64
LEARNING_RATE = 0.005

# Conformal prediction needs enough benign samples for the p-value to have resolution:
# the smallest achievable p-value is 1/(n+1), so n must exceed 1/alpha - 1 (19 at
# alpha=0.05) before the signal can ever fire, and far more before it means anything.
CALIBRATION_SAMPLE_COUNT = 500

# BehavioralFingerprinter metric -> dataset column supplying its benign distribution.
# 'packet_count' has no equivalent in the flat table (it is a live 5s-window count), so
# that metric abstains at cold start instead of being fabricated.
BEHAVIOURAL_METRIC_COLUMNS = {
    "unique_ports": "unique_dst_ports",
    "conn_freq": "connection_frequency",
    "syn_count": "syn_count",
}


def load_windows(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


def batch_windows(windows, means, stds):
    """
    Collapse several graphs into one block-diagonal graph.

    Nodes from different windows never become neighbours, so batching changes speed but
    not semantics.
    """
    feats, labels, edges, offset = [], [], [], 0
    for w in windows:
        feats.extend(w["features"])
        labels.extend(w["labels"])
        edges.extend([(a + offset, b + offset) for a, b in w["edges"]])
        offset += len(w["labels"])

    x = (np.asarray(feats, dtype=np.float32) - means) / (stds + 1e-6)
    return (
        torch.tensor(x, dtype=torch.float32),
        torch.tensor(labels, dtype=torch.float32).unsqueeze(1),
        build_adjacency(offset, edges),
    )


def evaluate(model, windows, means, stds):
    """Return (scores, labels) for every node across these windows."""
    model.eval()
    all_scores, all_labels = [], []
    with torch.no_grad():
        for i in range(0, len(windows), BATCH_WINDOWS):
            x, y, adj = batch_windows(windows[i:i + BATCH_WINDOWS], means, stds)
            preds = model(x, adj).squeeze(-1).numpy()
            all_scores.extend(np.atleast_1d(preds).tolist())
            all_labels.extend(y.squeeze(-1).numpy().tolist())
    return np.array(all_scores), np.array(all_labels)


def train():
    # Deterministic weight init: without this every retrain produces a different score
    # distribution, so the calibration set and any tuned threshold silently drift.
    torch.manual_seed(42)
    np.random.seed(42)

    if not os.path.exists(GRAPH_DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {GRAPH_DATASET_PATH}. Run generate_dataset.py first."
        )

    windows = load_windows(GRAPH_DATASET_PATH)
    print(f"[TRAIN] Loaded {len(windows)} graph windows from {GRAPH_DATASET_PATH}")

    held_out = [w for w in windows if w["scenario"] == HELD_OUT_SCENARIO]
    usable = [w for w in windows if w["scenario"] != HELD_OUT_SCENARIO]
    print(f"[METHODOLOGY] Held-out zero-day scenario: '{HELD_OUT_SCENARIO}' "
          f"({len(held_out)} windows excluded from training)")

    split = int(len(usable) * 0.8)
    train_w, test_w = usable[:split], usable[split:]
    print(f"[TRAIN] {len(train_w)} train / {len(test_w)} test windows")

    # Normalization statistics — computed on training nodes only, saved with the weights
    # below, and used verbatim at inference. Never recompute or hardcode these elsewhere.
    train_feats = np.asarray(
        [f for w in train_w for f in w["features"]], dtype=np.float32
    )
    means = train_feats.mean(axis=0)
    stds = train_feats.std(axis=0)

    model = GraphSAGEAnomalyModel(in_features=len(GNNPredictor.FEATURE_KEYS))
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

    # Malicious nodes are ~11% of the population; weight them so the model cannot win
    # by predicting "benign" everywhere.
    n_pos = sum(sum(w["labels"]) for w in train_w)
    n_neg = sum(len(w["labels"]) for w in train_w) - n_pos
    pos_weight = torch.tensor([n_neg / max(n_pos, 1)], dtype=torch.float32)
    print(f"[TRAIN] class balance: {n_pos} malicious / {n_neg} benign "
          f"(pos_weight {pos_weight.item():.2f})")

    # BCEWithLogits would be preferable, but the model's sigmoid is part of its public
    # contract (scores are consumed directly), so weight the plain BCE instead.
    criterion = nn.BCELoss(reduction="none")

    print(f"[TRAIN] Training GraphSAGE over {EPOCHS} epochs...")
    for epoch in range(EPOCHS):
        model.train()
        np.random.shuffle(train_w)
        epoch_loss = 0.0
        n_batches = 0

        for i in range(0, len(train_w), BATCH_WINDOWS):
            x, y, adj = batch_windows(train_w[i:i + BATCH_WINDOWS], means, stds)

            optimizer.zero_grad()
            preds = model(x, adj).clamp(1e-7, 1 - 1e-7)
            weights = torch.where(y > 0.5, pos_weight, torch.ones_like(y))
            loss = (criterion(preds, y) * weights).mean()
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()
            n_batches += 1

        if (epoch + 1) % 10 == 0:
            print(f"  Epoch [{epoch+1}/{EPOCHS}] - Loss: {epoch_loss / n_batches:.4f}")

    # ===== Evaluation =====
    scores, labels = evaluate(model, test_w, means, stds)
    preds = (scores > 0.5).astype(np.float32)

    print("\n[EVALUATION - HELD-OUT TEST WINDOWS, node level]")
    print(f"  Nodes scored : {len(labels):,}  ({int(labels.sum())} malicious)")
    print(f"  Accuracy     : {accuracy_score(labels, preds):.4f}")
    print(f"  Precision    : {precision_score(labels, preds, zero_division=0):.4f}")
    print(f"  Recall       : {recall_score(labels, preds, zero_division=0):.4f}")
    print(f"  F1-Score     : {f1_score(labels, preds, zero_division=0):.4f}")
    print(f"  ROC-AUC      : {roc_auc_score(labels, scores):.4f}")
    print(f"  PR-AUC       : {average_precision_score(labels, scores):.4f}")
    fp = int(((preds == 1) & (labels == 0)).sum())
    print(f"  False positives: {fp} of {int((labels == 0).sum()):,} benign nodes "
          f"({fp / max((labels == 0).sum(), 1) * 100:.2f}%)")

    # Zero-day: never seen during training, and only detectable from topology.
    zd_scores, zd_labels = evaluate(model, held_out, means, stds)
    zd_mal = zd_scores[zd_labels == 1]
    print(f"\n[EVALUATION - HELD-OUT ZERO-DAY ('{HELD_OUT_SCENARIO}')]")
    print(f"  Malicious nodes      : {len(zd_mal)}")
    print(f"  Mean anomaly score   : {zd_mal.mean():.4f}")
    print(f"  Detection rate (>0.5): {(zd_mal > 0.5).mean() * 100:.2f}%")

    # ===== Calibration artefacts =====
    benign_scores = scores[labels == 0]
    if len(benign_scores) > CALIBRATION_SAMPLE_COUNT:
        pick = np.random.default_rng(42).choice(
            len(benign_scores), CALIBRATION_SAMPLE_COUNT, replace=False
        )
        benign_scores = benign_scores[pick]
    calibration = sorted(round(float(s), 6) for s in benign_scores)

    print("\n[CALIBRATION - CONFORMAL PREDICTOR]")
    print(f"  Benign samples scored : {len(calibration)}")
    print(f"  Score range           : {calibration[0]:.6f} - {calibration[-1]:.6f}")
    print(f"  95th percentile       : {np.percentile(calibration, 95):.6f}")
    print(f"  Min achievable p-value: {1 / (len(calibration) + 1):.5f}")

    # Benign population prior for BehavioralFingerprinter cold start. Without this, an
    # unseen IP has no baseline and the behavioural signal degenerates into "is this
    # host new?", which corroborates nothing.
    flat = pd.read_csv(FLAT_DATASET_PATH)
    benign_df = flat[flat["label"] == "BENIGN"]
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

    print("\n[BASELINE - BEHAVIOURAL COLD START]")
    for metric, stats in benign_baseline.items():
        print(f"  {metric:<16} mu={stats['mean']:>10.2f}  sigma={stats['std']:>10.2f}")
    missing = set(BEHAVIOURAL_METRIC_COLUMNS) - set(benign_baseline)
    if missing:
        print(f"  NOTE: no column for {sorted(missing)} — those metrics abstain at cold start.")

    # ===== Save =====
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
            "feature_keys": list(GNNPredictor.FEATURE_KEYS),
            "dataset": GRAPH_DATASET_PATH,
        },
        MODEL_OUTPUT_PATH,
    )
    print(f"\n[SAVED] Model weights + normalization stats -> '{MODEL_OUTPUT_PATH}'")

    with open(CALIBRATION_OUTPUT_PATH, "w") as f:
        json.dump({"alpha": 0.05, "scores": calibration}, f)
    print(f"[SAVED] Conformal calibration scores -> '{CALIBRATION_OUTPUT_PATH}'")

    with open(BASELINE_OUTPUT_PATH, "w") as f:
        json.dump({"source": FLAT_DATASET_PATH, "metrics": benign_baseline}, f, indent=2)
    print(f"[SAVED] Benign behavioural baseline -> '{BASELINE_OUTPUT_PATH}'")


if __name__ == "__main__":
    train()
